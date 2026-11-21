"""Sign-up, two-step login, logout and account endpoints (rules in backend/app/auth.py).

Sign-up:  POST /signup {username, email, password} -> account waiting for its e-mail + ticket; code e-mailed
          POST /signup/verify {ticket, code}      -> e-mail confirmed; the account can log in
                                                     (or waits for approval when AAI_SIGNUP_APPROVAL=1)
Login:    POST /login {login, password}           -> ticket (login = user name or e-mail) (password was right); code e-mailed
          POST /login/code {ticket, code}         -> session cookie
Both:     POST /code/resend {ticket, purpose}     -> a new code for the same ticket (once per 30 s)
Account:  POST /api/account/code                  -> e-mails a code for the password change
          POST /api/account/password {...}        -> needs the current password and that code
"""
import os
import time

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field

from backend.app import mailer
from backend.app.auth import (ACCOUNT_MAX_FAILURES, ACCOUNT_WINDOW, COOKIE, MAIL_MAX, MAIL_WINDOW, RESEND_SECONDS,
                              SESSION_SECONDS, account_key, client_address, email_problem, get_auth, is_https,
                              make_record, masked, normal_email, normal_username, password_problem, require_user,
                              username_problem)

# Open sign-up by default: an account works as soon as its e-mail is confirmed. Set
# AAI_SIGNUP_APPROVAL=1 to make new accounts wait until someone runs:
#     python -m backend.app.auth approve <email>
SIGNUP_NEEDS_APPROVAL = os.environ.get("AAI_SIGNUP_APPROVAL") == "1"

router = APIRouter()
NOT_READY = "No account yet. Create one on the sign-up page."


UNCONFIRMED_SECONDS = 24 * 3600     # a sign-up that never confirmed its e-mail frees its name after a day


class SignUp(BaseModel):
    username: str = Field(max_length=64)
    email: str = Field(max_length=254)
    password: str = Field(max_length=512)


class Credentials(BaseModel):
    login: str = Field(max_length=254)      # user name or e-mail
    password: str = Field(max_length=512)


class Code(BaseModel):
    ticket: str = Field(max_length=128)
    code: str = Field(max_length=16)


class Resend(BaseModel):
    ticket: str = Field(max_length=128)
    purpose: str = Field(pattern="^(login|verify)$")


class PasswordChange(BaseModel):
    current_password: str = Field(max_length=512)
    new_password: str = Field(max_length=512)
    code: str = Field(max_length=16)


def _too_many(wait):
    return HTTPException(429, f"Too many attempts. Try again in {wait} seconds.", headers={"Retry-After": str(wait)})


def _limited(request, account=None):
    """Refuse with 429 when this address, or the account being tried, has too many recent
    failures; return the address. The account limit answers the same for an unknown name,
    so it does not tell anyone which accounts exist."""
    auth = get_auth()
    client = client_address(request)
    wait = auth.retry_after(client)
    if not wait and account:
        wait = auth.retry_after(account, limit=ACCOUNT_MAX_FAILURES, window=ACCOUNT_WINDOW)
    if wait:
        raise _too_many(wait)
    return client


def _fail(client, account=None):
    auth = get_auth()
    auth.record_failure(client)
    if account:
        auth.record_failure(account, window=ACCOUNT_WINDOW)


def _mail_allowed(email):
    """Refuse with 429 when this address already got MAIL_MAX e-mails in the last hour."""
    wait = get_auth().retry_after(f"mail:{email}", limit=MAIL_MAX, window=MAIL_WINDOW)
    if wait:
        raise HTTPException(429, f"Too many e-mails were sent to this address. Try again in {(wait + 59) // 60} minutes.",
                            headers={"Retry-After": str(wait)})


def _send(email, code, purpose):
    _mail_allowed(email)
    get_auth().record_failure(f"mail:{email}", window=MAIL_WINDOW)
    try:
        if code is None:
            mailer.send_notice(email, purpose)
        else:
            mailer.send_code(email, code, purpose)
    except mailer.MailError as e:
        raise HTTPException(503, str(e)) from None


def _code_result(result, client, expired_message, account=None):
    if result == "expired":
        _fail(client, account)
        raise HTTPException(401, expired_message)
    if result == "wrong":
        _fail(client, account)
        raise HTTPException(400, "That code is not right. Use the newest code we sent.")


# ------------------------------------------------------------------ sign-up
@router.post("/signup", status_code=201)
def signup(body: SignUp, request: Request):
    """Ask for an account. A code goes to the address; the account works once it is typed."""
    auth = get_auth()
    client = _limited(request)
    name, email = normal_username(body.username), normal_email(body.email)
    problem = username_problem(name) or email_problem(email) or password_problem(body.password, name, email)
    if problem:
        raise HTTPException(400, problem)
    auth.record_failure(client)          # every sign-up counts, so nobody can create accounts in bulk
    auth.store.delete_unconfirmed(time.time() - UNCONFIRMED_SECONDS)
    user = auth.store.user_by_email(email)
    confirmed = user is not None and bool(user["totp_confirmed"])
    holder = auth.store.user_by_name(name)
    # A name is free only when nobody has it, or when it is this address's own unconfirmed sign-up.
    if holder is not None and (user is None or confirmed or holder["id"] != user["id"]):
        raise HTTPException(409, "This user name is taken. Choose another one.")
    if confirmed:
        # The address already has an account. Answer exactly as for a new one (so nobody can test
        # which addresses have accounts here) and tell the owner by e-mail instead.
        make_record(body.password)               # same time cost as a real sign-up
        ticket, _ = auth.start_ticket(None, "verify", decoy_email=email)
        _send(email, None, "exists")
        return {"ticket": ticket, "sent_to": masked(email)}
    if user is None:
        uid = auth.store.add_user(name, make_record(body.password), email=email)
        if uid is None:                  # taken a moment ago by another sign-up
            raise HTTPException(409, "This user name or e-mail is taken. Choose another one.")
    else:                                # signed up before but never confirmed: start again
        uid = user["id"]
        auth.store.update_user(uid, username=name, password=make_record(body.password))
        auth.end_tickets_of(uid, "verify")
    ticket, code = auth.start_ticket(uid, "verify")
    _send(email, code, "verify")
    return {"ticket": ticket, "sent_to": masked(email)}


@router.post("/signup/verify")
def signup_verify(body: Code, request: Request):
    auth = get_auth()
    client = _limited(request)
    user = auth.ticket_user(body.ticket, "verify")
    _code_result(auth.check_ticket_code(body.ticket, "verify", body.code), client,
                 "This code has expired. Start the sign-up again.")
    if user is None:
        raise HTTPException(401, "This code has expired. Start the sign-up again.")
    if SIGNUP_NEEDS_APPROVAL:
        auth.store.update_user(user["id"], totp_confirmed=1)
        return {"status": "pending",
                "message": "Your e-mail is confirmed. You can log in after the project team approves the account."}
    auth.store.update_user(user["id"], totp_confirmed=1, status="active")
    return {"status": "active", "message": "Your e-mail is confirmed. You can log in now."}


# ------------------------------------------------------------------ login (two steps)
@router.post("/login")
def login(body: Credentials, request: Request):
    auth = get_auth()
    if not auth.configured:
        raise HTTPException(503, NOT_READY)
    account = account_key(body.login)
    client = _limited(request, account)
    user = auth.check_password(body.login, body.password)
    if user is None:
        _fail(client, account)
        raise HTTPException(401, "Wrong user name, e-mail or password.")
    if not user["email"]:
        raise HTTPException(403, "This account has no e-mail address yet. Ask the project team.")
    if not user["totp_confirmed"]:
        raise HTTPException(403, "This e-mail is not confirmed yet. Create the account again to get a new code.")
    if user["status"] == "pending":
        raise HTTPException(403, "Your account is waiting for approval by the project team.")
    if user["status"] != "active":
        raise HTTPException(403, "This account cannot log in now. Ask the project team.")
    auth.end_tickets_of(user["id"], "login")
    ticket, code = auth.start_ticket(user["id"], "login")
    _send(user["email"], code, "login")
    return {"ticket": ticket, "sent_to": masked(user["email"])}


@router.post("/login/code", status_code=204)
def login_code(body: Code, request: Request, response: Response):
    auth = get_auth()
    user = auth.ticket_user(body.ticket, "login")
    account = f"account:{user['id']}" if user else None
    client = _limited(request, account)
    _code_result(auth.check_ticket_code(body.ticket, "login", body.code), client,
                 "The login has expired. Enter your password again.", account)
    if user is None or user["status"] != "active":
        raise HTTPException(401, "The login has expired. Enter your password again.")
    auth.clear_failures(client)
    auth.store.update_user(user["id"], last_login=time.time())
    response.set_cookie(COOKIE, auth.start_session(user["id"]), max_age=SESSION_SECONDS, httponly=True,
                        samesite="strict", secure=is_https(request), path="/")


@router.post("/code/resend")
def resend_code(body: Resend, request: Request):
    auth = get_auth()
    _limited(request)
    user, code = auth.resend(body.ticket, body.purpose)
    if user is None:
        raise HTTPException(401, "This code has expired. Start again.")
    if code is None:
        raise HTTPException(429, f"Wait {RESEND_SECONDS} seconds before asking for a new code.",
                            headers={"Retry-After": str(RESEND_SECONDS)})
    if user.get("decoy"):                       # an address that already has an account: no code exists
        _mail_allowed(user["email"])
        return {"sent_to": masked(user["email"])}
    _send(user["email"], code, body.purpose)
    return {"sent_to": masked(user["email"])}


@router.post("/logout", status_code=204)
def logout(request: Request, response: Response):
    get_auth().end_session(request.cookies.get(COOKIE))
    response.delete_cookie(COOKIE, path="/")


@router.get("/me")
def me(user=Depends(require_user)):
    u = get_auth().store.user_by_id(user["id"])
    return {"username": u["username"], "email": u["email"], "created_at": u["created_at"], "last_login": u["last_login"]}


# ------------------------------------------------------------------ password change
# One live 'change' ticket per account, kept here by user id so the page only sends the code.
_change_tickets = {}


@router.post("/api/account/code")
def account_code(request: Request, user=Depends(require_user)):
    auth = get_auth()
    _limited(request)
    old = _change_tickets.get(user["id"])
    if old:
        u, code = auth.resend(old, "change")
        if u is not None:
            if code is None:
                raise HTTPException(429, f"Wait {RESEND_SECONDS} seconds before asking for a new code.",
                                    headers={"Retry-After": str(RESEND_SECONDS)})
            _send(user["email"], code, "change")
            return {"sent_to": masked(user["email"])}
    ticket, code = auth.start_ticket(user["id"], "change")
    _change_tickets[user["id"]] = ticket
    _send(user["email"], code, "change")
    return {"sent_to": masked(user["email"])}


@router.post("/api/account/password", status_code=204)
def change_password(body: PasswordChange, request: Request, response: Response, user=Depends(require_user)):
    """Needs the current password AND an e-mailed code. Logs out every session of this account."""
    auth = get_auth()
    account = f"account:{user['id']}"
    client = _limited(request, account)
    problem = password_problem(body.new_password, user["username"], user.get("email") or "")
    if problem:
        raise HTTPException(400, problem)
    if auth.check_password(user["email"] or user["username"], body.current_password) is None:
        _fail(client, account)
        raise HTTPException(400, "The current password is wrong.")
    ticket = _change_tickets.get(user["id"])
    result = auth.check_ticket_code(ticket, "change", body.code) if ticket else "expired"
    if result != "ok":
        _fail(client, account)
        if result == "expired":
            _change_tickets.pop(user["id"], None)
        # 400, not 401: a 401 would send the page to the login screen.
        raise HTTPException(400, "The code has expired. Send a new code." if result == "expired"
                            else "That code is not right. Use the newest code we sent.")
    _change_tickets.pop(user["id"], None)
    auth.store.update_user(user["id"], password=make_record(body.new_password))
    auth.end_sessions_of(user["id"])
    response.delete_cookie(COOKIE, path="/")
    if user.get("email"):
        try:
            _send(user["email"], None, "changed")    # tell the owner, in case it was not them
        except HTTPException:
            pass                                     # the change itself is done; the notice is a courtesy
