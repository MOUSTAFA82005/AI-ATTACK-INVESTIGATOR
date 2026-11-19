"""Accounts, two-factor login and sessions for the dashboard. Everything is checked by the server.

There is one kind of user (a tester); nobody manages accounts from the web page.
- Anyone can ask for an account on the sign-up page. They choose a password and set up
  an authenticator app (2FA) by scanning a QR code and typing one code.
- The account stays "pending" until it is approved on the server machine:
      python -m backend.app.auth approve <name>
- Login = password, then the 6-digit code from the authenticator app (RFC 6238 TOTP).

Other commands (python -m backend.app.auth --help): create, list, disable, enable,
reset-2fa, reset-password, delete.

Passwords are stored only as salted scrypt hashes. A code works once (replay is refused).
After both steps the server keeps a random session token in memory and sends it as an
HttpOnly, SameSite=Strict cookie; restarting the server logs everyone out.
Failed attempts are limited per client address (MAX_FAILURES per FAILURE_WINDOW seconds).
"""
import argparse
import base64
import getpass
import hashlib
import hmac
import io
import os
import re
import secrets
import struct
import sys
import threading
import time
from collections import defaultdict, deque
from urllib.parse import quote

from fastapi import HTTPException, Request

from backend.app.db import Store

COOKIE = "aai_session"
SESSION_SECONDS = 8 * 3600          # a login lasts one working day
TICKET_SECONDS = 300                # time to type the 2FA code after the password
MAX_FAILURES = 5                    # failed attempts allowed per address ...
FAILURE_WINDOW = 60                 # ... in this many seconds, then 429 until the window passes
MIN_PASSWORD_LENGTH = 10
MAX_PASSWORD_LENGTH = 256
USERNAME = re.compile(r"^[A-Za-z0-9_.-]{3,32}$")
SCRYPT = {"n": 2 ** 14, "r": 8, "p": 1}   # standard interactive-login cost
ISSUER = "AI Attack Investigator"
TOTP_PERIOD, TOTP_DIGITS, TOTP_WINDOW = 30, 6, 1   # accept the code of the previous/next 30 s too


# ------------------------------------------------------------------ passwords
def hash_password(password, salt, n=SCRYPT["n"], r=SCRYPT["r"], p=SCRYPT["p"]):
    return hashlib.scrypt(password.encode("utf-8"), salt=salt, n=n, r=r, p=p, dklen=32)


def make_record(password):
    """What is stored for a password: salt, cost parameters and hash."""
    salt = secrets.token_bytes(16)
    return {"salt": salt.hex(), **SCRYPT, "hash": hash_password(password, salt).hex()}


def password_problem(password):
    """A sentence saying what is wrong with a new password, or None when it is fine."""
    if len(password) < MIN_PASSWORD_LENGTH:
        return f"Use at least {MIN_PASSWORD_LENGTH} characters."
    if len(password) > MAX_PASSWORD_LENGTH:
        return f"Use at most {MAX_PASSWORD_LENGTH} characters."
    return None


def username_problem(username):
    if not USERNAME.match(username or ""):
        return "Use 3 to 32 letters, digits, dots, dashes or underscores."
    return None


# ------------------------------------------------------------------ 2FA (TOTP, RFC 6238)
def new_totp_secret():
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")


def totp_code(secret, step):
    key = base64.b32decode(secret + "=" * (-len(secret) % 8))
    digest = hmac.new(key, struct.pack(">Q", step), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    value = struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF
    return str(value % 10 ** TOTP_DIGITS).zfill(TOTP_DIGITS)


def totp_match(secret, code, now=None):
    """The 30-second step whose code equals `code` (within the window), or None."""
    code = re.sub(r"\s", "", code or "")
    if not re.fullmatch(rf"\d{{{TOTP_DIGITS}}}", code):
        return None
    step = int((time.time() if now is None else now) // TOTP_PERIOD)
    for s in range(step - TOTP_WINDOW, step + TOTP_WINDOW + 1):
        if hmac.compare_digest(totp_code(secret, s), code):
            return s
    return None


def totp_uri(username, secret):
    return (f"otpauth://totp/{quote(ISSUER)}:{quote(username)}?secret={secret}"
            f"&issuer={quote(ISSUER)}&digits={TOTP_DIGITS}&period={TOTP_PERIOD}")


def qr_svg(text):
    """The QR code of `text` as SVG, or None when the optional segno package is missing
    (the page then shows the key to type into the app by hand)."""
    try:
        import segno
    except ImportError:
        return None
    out = io.BytesIO()
    segno.make(text, error="m").save(out, kind="svg", scale=5, border=2, dark="#0f1a2e", light="#ffffff",
                                     xmldecl=False, svgns=True)
    return out.getvalue().decode("utf-8")


class Auth:
    """The account store, the login tickets, the live sessions and the failed-attempt counts."""

    def __init__(self, store):
        self.store = store
        self._sessions = {}                    # token -> (user id, expiry time)
        self._tickets = {}                     # ticket -> (user id, expiry time, purpose)
        self._failures = defaultdict(deque)    # client address -> times of recent failures
        self._lock = threading.Lock()
        self._dummy = make_record(secrets.token_hex(8))   # same cost for unknown user names

    @property
    def configured(self):
        return self.store.active_users() > 0

    # ---------------------------------------------------------------- checks
    def check_password(self, username, password):
        """The user row when the name and password match (whatever the account status), else None."""
        user = self.store.user_by_name(username) if username else None
        rec = user["password"] if user else self._dummy
        got = hash_password(password, bytes.fromhex(rec["salt"]), rec["n"], rec["r"], rec["p"])
        ok = hmac.compare_digest(got, bytes.fromhex(rec["hash"]))
        return user if (ok and user) else None

    def check_code(self, user, code, now=None):
        """True when `code` is right for this user and was not used before (then it is used up)."""
        step = totp_match(user["totp_secret"], code, now)
        return step is not None and self.store.use_totp_step(user["id"], step)

    # ---------------------------------------------------------------- failed-attempt limit
    def _recent_failures(self, client, now):
        q = self._failures[client]
        while q and now - q[0] >= FAILURE_WINDOW:
            q.popleft()
        return q

    def retry_after(self, client, now=None):
        """Seconds the client must wait before trying again (0 = may try now)."""
        now = time.monotonic() if now is None else now
        with self._lock:
            q = self._recent_failures(client, now)
            if len(q) < MAX_FAILURES:
                return 0
            return max(1, int(FAILURE_WINDOW - (now - q[0])) + 1)

    def record_failure(self, client, now=None):
        now = time.monotonic() if now is None else now
        with self._lock:
            self._recent_failures(client, now).append(now)

    def clear_failures(self, client):
        with self._lock:
            self._failures.pop(client, None)

    # ---------------------------------------------------------------- tickets (between two steps)
    def start_ticket(self, user_id, purpose, now=None):
        """A short-lived, single-use proof that the password step passed ('login' or 'setup')."""
        now = time.time() if now is None else now
        ticket = secrets.token_urlsafe(32)
        with self._lock:
            self._tickets = {t: v for t, v in self._tickets.items() if v[1] > now}
            self._tickets[ticket] = (user_id, now + TICKET_SECONDS, purpose)
        return ticket

    def ticket_user(self, ticket, purpose, now=None):
        now = time.time() if now is None else now
        with self._lock:
            entry = self._tickets.get(ticket or "")
        if entry is None or entry[1] <= now or entry[2] != purpose:
            return None
        return self.store.user_by_id(entry[0])

    def end_ticket(self, ticket):
        with self._lock:
            self._tickets.pop(ticket or "", None)

    # ---------------------------------------------------------------- sessions
    def start_session(self, user_id, now=None):
        now = time.time() if now is None else now
        token = secrets.token_urlsafe(32)
        with self._lock:
            self._sessions = {t: v for t, v in self._sessions.items() if v[1] > now}
            self._sessions[token] = (user_id, now + SESSION_SECONDS)
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
            if entry[1] <= now:
                del self._sessions[token]
                return None
        user = self.store.user_by_id(entry[0])
        if user is None or user["status"] != "active":
            self.end_session(token)
            return None
        return {"id": user["id"], "username": user["username"]}

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

    AAI_ADMIN_USER, AAI_ADMIN_PASSWORD and AAI_ADMIN_TOTP (the base32 key from your authenticator app)
    must all be set. Nothing happens when any is missing or the account already exists.
    AAI_APPROVE may list pending user names (comma-separated) to let them log in after a restart.
    """
    env = os.environ if env is None else env
    name, password, secret = env.get("AAI_ADMIN_USER", ""), env.get("AAI_ADMIN_PASSWORD", ""), env.get("AAI_ADMIN_TOTP", "")
    secret = secret.replace(" ", "").upper()
    if name and password and secret and store.user_by_name(name) is None:
        problem = username_problem(name) or password_problem(password)
        try:
            base64.b32decode(secret + "=" * (-len(secret) % 8))
        except ValueError:
            problem = problem or "AAI_ADMIN_TOTP is not a base32 key."
        if problem:
            print(f"Admin account not created: {problem}", file=sys.stderr)
        else:
            uid = store.add_user(name, make_record(password), secret, status="active")
            store.update_user(uid, totp_confirmed=1)
    for pending in filter(None, (x.strip() for x in env.get("AAI_APPROVE", "").split(","))):
        user = store.user_by_name(pending)
        if user and user["status"] == "pending" and user["totp_confirmed"]:
            store.update_user(user["id"], status="active")


def require_user(request: Request):
    """FastAPI dependency for every endpoint that reads logs or results."""
    a = get_auth()
    if not a.configured:
        raise HTTPException(503, "No active account yet. On the server run: python -m backend.app.auth create")
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


def _enrol_2fa(store, user_id, username):
    """Show a new key as a QR code in the terminal and confirm it with one code."""
    secret = new_totp_secret()
    uri = totp_uri(username, secret)
    try:
        import segno
        segno.make(uri, error="m").terminal(compact=True)
    except ImportError:
        print("(pip install segno to see a QR code here)")
    print(f"Scan the QR code with an authenticator app, or type this key: {secret}")
    while True:
        code = input("Code from the app: ")
        step = totp_match(secret, code)
        if step is not None:
            store.update_user(user_id, totp_secret=secret, totp_confirmed=1, totp_last_step=step)
            print("2FA is set up.")
            return
        print("That code is not right. Check the phone's time and try again.")


def main(argv=None):
    ap = argparse.ArgumentParser(prog="python -m backend.app.auth", description="Manage dashboard accounts.")
    sub = ap.add_subparsers(dest="cmd")
    sub.add_parser("create", help="create an active account (password + 2FA) here on the server")
    sub.add_parser("list", help="list accounts")
    for name, text in [("approve", "let a pending account log in"), ("disable", "stop an account from logging in"),
                       ("enable", "let a disabled account log in again"), ("reset-2fa", "set up a new authenticator for an account"),
                       ("reset-password", "set a new password for an account"), ("delete", "delete an account and its results")]:
        sub.add_parser(name, help=text).add_argument("username")
    args = ap.parse_args(argv)
    store = Store()

    if args.cmd in (None, "create"):
        while True:
            username = input("User name: ").strip()
            problem = username_problem(username) or (store.user_by_name(username) and "This user name is taken.")
            if not problem:
                break
            print(problem)
        uid = store.add_user(username, make_record(_ask_password()), new_totp_secret(), status="active")
        _enrol_2fa(store, uid, username)
        print(f"Created '{username}'. Restart the server if it is running.")
        return 0

    if args.cmd == "list":
        for u in store.users():
            twofa = "2FA on" if u["totp_confirmed"] else "2FA not set up"
            print(f"{u['username']:<24} {u['status']:<9} {twofa:<15} {u['investigations']} investigations")
        return 0

    user = store.user_by_name(args.username)
    if user is None:
        print(f"No account named '{args.username}'.")
        return 1
    if args.cmd == "approve":
        if not user["totp_confirmed"]:
            print("This account has not finished the 2FA setup. Ask them to sign up again, or run reset-2fa.")
            return 1
        store.update_user(user["id"], status="active")
        print(f"'{user['username']}' can log in now.")
    elif args.cmd == "disable":
        store.update_user(user["id"], status="disabled")
        print(f"'{user['username']}' is disabled (logged out on the next request).")
    elif args.cmd == "enable":
        store.update_user(user["id"], status="active")
        print(f"'{user['username']}' is enabled.")
    elif args.cmd == "reset-2fa":
        _enrol_2fa(store, user["id"], user["username"])
    elif args.cmd == "reset-password":
        store.update_user(user["id"], password=make_record(_ask_password()))
        print("Password changed.")
    elif args.cmd == "delete":
        if input(f"Type the name again to delete '{user['username']}' and all its results: ") == user["username"]:
            store.delete_user(user["id"])
            print("Deleted.")
        else:
            print("Not deleted.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
