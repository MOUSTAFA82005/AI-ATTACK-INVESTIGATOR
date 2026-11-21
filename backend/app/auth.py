"""Accounts, two-step login by e-mail code, and sessions for the dashboard. Everything is checked by the server.

- Sign-up: a user name, an e-mail address and a password. A 6-digit code is sent to that address; typing it
  proves the address and the account can log in (or waits for approval when
  AAI_SIGNUP_APPROVAL=1: python -m backend.app.auth approve <email>).
- Login: user name or e-mail, and password, then a new 6-digit code sent to the same address.
- Changing the password needs the current password and a code sent by e-mail.

Codes: random, 6 digits, work once, end after CODE_SECONDS, and a ticket is dropped after
CODE_TRIES wrong codes. Only a keyed hash of each code is kept, in memory.
Passwords are stored only as salted scrypt hashes. After both steps the server keeps a random
session token in memory and sends it as an HttpOnly, SameSite=Strict cookie; restarting the
server logs everyone out; a session also ends after SESSION_IDLE_SECONDS without a request.
Failed attempts are limited per client address (MAX_FAILURES per FAILURE_WINDOW seconds) and
per account (ACCOUNT_MAX_FAILURES per ACCOUNT_WINDOW), and e-mails per address (MAIL_MAX per hour).

Server commands (python -m backend.app.auth --help): create, list, approve, disable, enable,
reset-password, set-email, rename, delete.
"""
import argparse
import getpass
import hashlib
import hmac
import os
import re
import secrets
import sys
import threading
import time
from collections import defaultdict, deque

from fastapi import HTTPException, Request

from backend.app.db import Store

COOKIE = "aai_session"
SESSION_SECONDS = 8 * 3600          # a login lasts one working day at most ...
SESSION_IDLE_SECONDS = 2 * 3600     # ... and ends sooner after this long without any request
CODE_SECONDS = 600                  # an e-mailed code works for 10 minutes ...
CODE_TRIES = 5                      # ... and for at most this many wrong guesses
RESEND_SECONDS = 30                 # wait between two codes for the same ticket
CODE_DIGITS = 6
MAX_FAILURES = 5                    # failed attempts allowed per address ...
FAILURE_WINDOW = 60                 # ... in this many seconds, then 429 until the window passes
ACCOUNT_MAX_FAILURES = 10           # wrong passwords or codes for ONE account, from any address ...
ACCOUNT_WINDOW = 15 * 60            # ... in this many seconds (stops slow guessing from many addresses)
MAIL_MAX = 5                        # e-mails to one address ...
MAIL_WINDOW = 3600                  # ... per hour (nobody can flood someone's inbox through the sign-up page)
MIN_PASSWORD_LENGTH = 12
MAX_PASSWORD_LENGTH = 256
USERNAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{2,31}$")
EMAIL = re.compile(r"^[^@\s]{1,64}@[^@\s.]+(\.[^@\s.]+)+$")
SCRYPT = {"n": 2 ** 14, "r": 8, "p": 1}   # standard interactive-login cost


# ------------------------------------------------------------------ passwords and addresses
def hash_password(password, salt, n=SCRYPT["n"], r=SCRYPT["r"], p=SCRYPT["p"]):
    return hashlib.scrypt(password.encode("utf-8"), salt=salt, n=n, r=r, p=p, dklen=32)


def make_record(password):
    """What is stored for a password: salt, cost parameters and hash."""
    salt = secrets.token_bytes(16)
    return {"salt": salt.hex(), **SCRYPT, "hash": hash_password(password, salt).hex()}


# Passwords people pick first; refused even when they pass the other rules (lower-case, compared
# after removing digits and symbols, so "Password123!" counts as "password").
COMMON_WORDS = {"password", "passw", "qwerty", "qwertyuiop", "asdfgh", "zxcvbn", "letmein", "welcome", "admin",
                "administrator", "iloveyou", "monkey", "dragon", "football", "baseball", "sunshine", "princess",
                "master", "shadow", "superman", "batman", "trustno", "abc", "abcdef", "abcdefgh", "test", "user",
                "login", "secret", "changeme", "default", "talon", "investigator", "attack", "egypt", "cairo"}


def password_rules(password, username="", email=""):
    """Each rule as (short text, passed?). The sign-up and account pages show the same list."""
    letters = re.sub(r"[^a-z]", "", password.lower())
    personal = [x.lower() for x in (username, (email or "").split("@")[0]) if x and len(x) >= 3]
    return [
        (f"At least {MIN_PASSWORD_LENGTH} characters", len(password) >= MIN_PASSWORD_LENGTH),
        ("An upper-case and a lower-case letter", bool(re.search(r"[A-Z]", password) and re.search(r"[a-z]", password))),
        ("A number", bool(re.search(r"[0-9]", password))),
        ("A symbol, such as ! @ # $ or a space", bool(re.search(r"[^A-Za-z0-9]", password))),
        ("Not your user name or e-mail", not any(x in password.lower() for x in personal)),
        ("Not a common password", letters not in COMMON_WORDS and len(set(password)) >= 5),
    ]


def password_problem(password, username="", email=""):
    """A sentence saying what is wrong with a new password, or None when it is fine."""
    if len(password) > MAX_PASSWORD_LENGTH:
        return f"Use at most {MAX_PASSWORD_LENGTH} characters."
    missing = [text for text, ok in password_rules(password, username, email) if not ok]
    if missing:
        return "The password needs: " + "; ".join(t[0].lower() + t[1:] for t in missing) + "."
    return None


def normal_email(email):
    return (email or "").strip().lower()


def normal_username(name):
    return (name or "").strip()


def username_problem(name):
    if not USERNAME.match(name):
        return "Use 3 to 32 letters, digits, dots, dashes or underscores for the user name."
    return None


def normal_login(login):
    """What was typed in the login box: an e-mail is lower-cased, a user name is kept as typed."""
    login = (login or "").strip()
    return login.lower() if "@" in login else login


def email_problem(email):
    if len(email) > 254 or not EMAIL.match(email):
        return "Enter a valid e-mail address."
    return None


def masked(email):
    """s***@gmail.com, for messages that confirm where a code went."""
    name, _, domain = email.partition("@")
    return f"{name[:1]}{'*' * max(2, len(name) - 1)}@{domain}"


def new_code():
    return str(secrets.randbelow(10 ** CODE_DIGITS)).zfill(CODE_DIGITS)


def clean_code(code):
    code = re.sub(r"\s", "", code or "")
    return code if re.fullmatch(rf"\d{{{CODE_DIGITS}}}", code) else None


# ------------------------------------------------------------------ the shared state
class Auth:
    """The account store, the code tickets, the live sessions and the failed-attempt counts."""

    def __init__(self, store):
        self.store = store
        self._sessions = {}                    # token -> [user id, expiry time, last request time]
        self._tickets = {}                     # ticket -> dict(user, purpose, code hash, expiry, tries, sent)
        self._failures = defaultdict(deque)    # key -> times of recent events (failures, e-mails sent)
        self._lock = threading.Lock()
        self._key = secrets.token_bytes(32)    # keys the code hashes; new on every start
        self._dummy = make_record(secrets.token_hex(8))   # same cost for unknown addresses

    @property
    def configured(self):
        return self.store.active_users() > 0

    # ---------------------------------------------------------------- password check
    def check_password(self, login, password):
        """The user row when the user name or e-mail and the password match (whatever the account status), else None."""
        login = normal_login(login)
        user = self.store.user_by_login(login) if login else None
        rec = user["password"] if user else self._dummy
        got = hash_password(password, bytes.fromhex(rec["salt"]), rec["n"], rec["r"], rec["p"])
        ok = hmac.compare_digest(got, bytes.fromhex(rec["hash"]))
        return user if (ok and user) else None

    # ---------------------------------------------------------------- failed-attempt limit
    # The same counter serves three limits; the key says which: a client address,
    # "account:<login>" or "mail:<address>".
    def _recent(self, key, now, window):
        q = self._failures[key]
        while q and now - q[0] >= window:
            q.popleft()
        if not q:
            del self._failures[key]            # keep the table small
            return deque()
        return q

    def retry_after(self, key, now=None, limit=MAX_FAILURES, window=FAILURE_WINDOW):
        """Seconds to wait before trying again (0 = may try now)."""
        now = time.monotonic() if now is None else now
        with self._lock:
            q = self._recent(key, now, window)
            if len(q) < limit:
                return 0
            return max(1, int(window - (now - q[-limit])) + 1)

    def record_failure(self, key, now=None, window=FAILURE_WINDOW):
        now = time.monotonic() if now is None else now
        with self._lock:
            self._recent(key, now, window)
            self._failures[key].append(now)

    def clear_failures(self, key):
        with self._lock:
            self._failures.pop(key, None)

    # ---------------------------------------------------------------- e-mailed code tickets
    def _hash(self, code):
        return hmac.new(self._key, code.encode(), hashlib.sha256).digest()

    def start_ticket(self, user_id, purpose, now=None, decoy_email=None):
        """A new single-use ticket for `purpose` ('verify', 'login' or 'change') and its code.
        The caller e-mails the code; only its hash is kept.

        A decoy ticket (user_id None, decoy_email set) answers a sign-up with an address that
        already has an account: it behaves like a real one, but no code is ever sent for it."""
        now = time.time() if now is None else now
        ticket, code = secrets.token_urlsafe(32), new_code()
        with self._lock:
            self._tickets = {t: v for t, v in self._tickets.items() if v["expires"] > now}
            self._tickets[ticket] = {"user": user_id, "purpose": purpose, "hash": self._hash(code),
                                     "expires": now + CODE_SECONDS, "tries": 0, "sent": now, "decoy": decoy_email}
        return ticket, code

    def _owner(self, t):
        if t["decoy"]:
            return {"id": None, "email": t["decoy"], "decoy": True}
        return self.store.user_by_id(t["user"])

    def resend(self, ticket, purpose, now=None):
        """A fresh code for a live ticket: (user row, code), or (user row, None) while
        RESEND_SECONDS have not passed, or (None, None) when the ticket is gone."""
        now = time.time() if now is None else now
        with self._lock:
            t = self._tickets.get(ticket or "")
            if t is None or t["expires"] <= now or t["purpose"] != purpose:
                return None, None
            if now - t["sent"] < RESEND_SECONDS:
                return self._owner(t), None
            code = new_code()
            t.update(hash=self._hash(code), expires=now + CODE_SECONDS, tries=0, sent=now)
        return self._owner(t), code

    def ticket_user(self, ticket, purpose, now=None):
        now = time.time() if now is None else now
        with self._lock:
            t = self._tickets.get(ticket or "")
        if t is None or t["expires"] <= now or t["purpose"] != purpose or t["decoy"]:
            return None
        return self.store.user_by_id(t["user"])

    def check_ticket_code(self, ticket, purpose, code, now=None):
        """'ok' (the ticket is used up), 'wrong', or 'expired' (missing, old, or too many tries)."""
        now = time.time() if now is None else now
        code = clean_code(code)
        with self._lock:
            t = self._tickets.get(ticket or "")
            if t is None or t["expires"] <= now or t["purpose"] != purpose:
                return "expired"
            if code and hmac.compare_digest(t["hash"], self._hash(code)):
                del self._tickets[ticket]
                return "ok"
            t["tries"] += 1
            if t["tries"] >= CODE_TRIES:
                del self._tickets[ticket]
                return "expired"
            return "wrong"

    def end_ticket(self, ticket):
        with self._lock:
            self._tickets.pop(ticket or "", None)

    def end_tickets_of(self, user_id, purpose):
        with self._lock:
            self._tickets = {k: v for k, v in self._tickets.items() if not (v["user"] == user_id and v["purpose"] == purpose)}

    # ---------------------------------------------------------------- sessions
    def start_session(self, user_id, now=None):
        now = time.time() if now is None else now
        token = secrets.token_urlsafe(32)
        with self._lock:
            self._sessions = {t: v for t, v in self._sessions.items()
                              if v[1] > now and now - v[2] < SESSION_IDLE_SECONDS}
            self._sessions[token] = [user_id, now + SESSION_SECONDS, now]
        return token

    def user_for(self, token, now=None):
        """The active user behind a session token, or None. Reads the account every time,
        so disabling an account takes effect on the next request."""
        if not token:
            return None
        now = time.time() if now is None else now
        with self._lock:
            entry = self._sessions.get(token)
            if entry is None:
                return None
            if entry[1] <= now or now - entry[2] >= SESSION_IDLE_SECONDS:
                del self._sessions[token]
                return None
            entry[2] = now
        user = self.store.user_by_id(entry[0])
        if user is None or user["status"] != "active":
            self.end_session(token)
            return None
        return {"id": user["id"], "username": user["username"], "email": user["email"]}

    def end_session(self, token):
        with self._lock:
            self._sessions.pop(token, None)

    def end_sessions_of(self, user_id):
        with self._lock:
            self._sessions = {t: v for t, v in self._sessions.items() if v[0] != user_id}


auth = None


def get_auth():
    """The shared Auth (opens var/app.db on first use, so importing this module writes nothing)."""
    global auth
    if auth is None:
        auth = Auth(Store())
    return auth


# Set AAI_BEHIND_PROXY=1 only when the app runs behind one HTTPS proxy that appends the real
# client address to X-Forwarded-For (the hosted demo). The last entry is the one the proxy wrote,
# so a visitor cannot dodge the failed-login limit by sending a fake header.
BEHIND_PROXY = os.environ.get("AAI_BEHIND_PROXY") == "1"


def client_address(request: Request):
    if BEHIND_PROXY:
        forwarded = request.headers.get("x-forwarded-for", "")
        if forwarded.strip():
            return forwarded.split(",")[-1].strip()
    return request.client.host if request.client else "unknown"


def is_https(request: Request):
    """True when the browser reached us over HTTPS (directly, or through the trusted proxy)."""
    return request.url.scheme == "https" or (BEHIND_PROXY and request.headers.get("x-forwarded-proto") == "https")


def bootstrap_from_env(store, env=None):
    """Hosted demo: create the first active account from secrets, because the host has no console.

    AAI_ADMIN_EMAIL and AAI_ADMIN_PASSWORD must both be set (AAI_ADMIN_USER is the user name,
    default "admin"); nothing happens when either is missing or the account already exists.
    AAI_APPROVE may list pending user names or addresses (comma-separated) to let them log in
    after a restart.
    """
    env = os.environ if env is None else env
    email, password = normal_email(env.get("AAI_ADMIN_EMAIL", "")), env.get("AAI_ADMIN_PASSWORD", "")
    name = normal_username(env.get("AAI_ADMIN_USER", "") or "admin")
    if email and password and store.user_by_email(email) is None:
        problem = (email_problem(email) or username_problem(name) or password_problem(password, name, email)
                   or (store.user_by_name(name) and "the user name is taken."))
        if problem:
            print(f"Admin account not created: {problem}", file=sys.stderr)
        else:
            uid = store.add_user(name, make_record(password), email=email, status="active")
            store.update_user(uid, totp_confirmed=1)
    for pending in filter(None, (normal_login(x) for x in env.get("AAI_APPROVE", "").split(","))):
        user = store.user_by_login(pending)
        if user and user["status"] == "pending" and user["totp_confirmed"]:
            store.update_user(user["id"], status="active")


def account_key(login):
    """The key that counts failed attempts on one account, the same for its user name and e-mail."""
    a = get_auth()
    login = normal_login(login)
    user = a.store.user_by_login(login) if login else None
    return f"account:{user['id'] if user else login.lower()}"


def require_user(request: Request):
    """FastAPI dependency for every endpoint that reads logs or results."""
    a = get_auth()
    if not a.configured:
        raise HTTPException(503, "No account yet. Create one on the sign-up page.")
    user = a.user_for(request.cookies.get(COOKIE))
    if user is None:
        raise HTTPException(401, "Please log in.")
    return user


# ------------------------------------------------------------------ command line (server machine only)
def _ask_password():
    while True:
        password = getpass.getpass(f"Password (at least {MIN_PASSWORD_LENGTH} characters): ")
        problem = password_problem(password)
        if problem:
            print(problem)
        elif getpass.getpass("Repeat the password: ") != password:
            print("The two passwords are different.")
        else:
            return password


def main(argv=None):
    ap = argparse.ArgumentParser(prog="python -m backend.app.auth", description="Manage dashboard accounts.")
    sub = ap.add_subparsers(dest="cmd")
    sub.add_parser("create", help="create an active account here on the server (no e-mail needed)")
    sub.add_parser("list", help="list accounts")
    for name, text in [("approve", "let a pending account log in"), ("disable", "stop an account from logging in"),
                       ("enable", "let a disabled account log in again"),
                       ("reset-password", "set a new password for an account"), ("delete", "delete an account and its results")]:
        sub.add_parser(name, help=text).add_argument("account", help="user name or e-mail")
    p = sub.add_parser("set-email", help="change the e-mail address of an account")
    p.add_argument("account", help="user name or e-mail")
    p.add_argument("email")
    p = sub.add_parser("rename", help="change the user name of an account")
    p.add_argument("account", help="user name or e-mail")
    p.add_argument("username")
    args = ap.parse_args(argv)
    store = Store()

    if args.cmd in (None, "create"):
        while True:
            name = normal_username(input("User name: "))
            problem = username_problem(name) or (store.user_by_name(name) and "This user name is taken.")
            if not problem:
                break
            print(problem)
        while True:
            email = normal_email(input("E-mail: "))
            problem = email_problem(email) or (store.user_by_email(email) and "An account with this e-mail exists.")
            if not problem:
                break
            print(problem)
        uid = store.add_user(name, make_record(_ask_password()), email=email, status="active")
        store.update_user(uid, totp_confirmed=1)
        print(f"Created '{name}' ({email}). The login code is e-mailed (or printed by the server in console mode).")
        return 0

    if args.cmd == "list":
        for u in store.users():
            mail = "e-mail confirmed" if u["totp_confirmed"] else "e-mail not confirmed"
            print(f"{u['username']:<24} {u['email'] or '-':<36} {u['status']:<9} {mail:<21} {u['investigations']} investigations")
        return 0

    user = store.user_by_login(normal_login(args.account))
    if user is None:
        print(f"No account '{args.account}'.")
        return 1
    if args.cmd == "set-email":
        email = normal_email(args.email)
        problem = email_problem(email) or (store.user_by_email(email) and "An account with this e-mail exists.")
        if problem:
            print(problem)
            return 1
        store.update_user(user["id"], email=email, totp_confirmed=1)
        print(f"'{user['username']}' now gets its codes at {email}.")
        return 0
    if args.cmd == "rename":
        name = normal_username(args.username)
        problem = username_problem(name) or (store.user_by_name(name) and "This user name is taken.")
        if problem:
            print(problem)
            return 1
        store.update_user(user["id"], username=name)
        print(f"'{user['username']}' is now '{name}'.")
        return 0
    if args.cmd == "approve":
        if not user["totp_confirmed"]:
            print("This account has not confirmed its e-mail yet.")
            return 1
        store.update_user(user["id"], status="active")
        print(f"'{user['username']}' can log in now.")
    elif args.cmd == "disable":
        store.update_user(user["id"], status="disabled")
        print(f"'{user['username']}' is disabled (logged out on the next request).")
    elif args.cmd == "enable":
        store.update_user(user["id"], status="active")
        print(f"'{user['username']}' is enabled.")
    elif args.cmd == "reset-password":
        store.update_user(user["id"], password=make_record(_ask_password()))
        print("Password changed.")
    elif args.cmd == "delete":
        if input(f"Type the user name again to delete '{user['username']}' and all its results: ") == user["username"]:
            store.delete_user(user["id"])
            print("Deleted.")
        else:
            print("Not deleted.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
