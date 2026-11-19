"""Sign-up, two-step login, logout and account endpoints (rules in backend/app/auth.py).

Sign-up:  POST /signup {username, password}      -> pending account + setup ticket + QR code
          POST /signup/2fa {ticket, code}        -> 2FA confirmed; wait for approval on the server
Login:    POST /login {username, password}       -> login ticket (password was right)
          POST /login/2fa {ticket, code}         -> session cookie
"""
import base64
import time

from fastapi import APIRouter, Depends, HTTPException, Request, Response
from pydantic import BaseModel, Field

from backend.app.auth import (COOKIE, SESSION_SECONDS, client_address, get_auth, is_https, make_record,
                              new_totp_secret, password_problem, qr_svg, require_user, totp_uri, username_problem)

router = APIRouter()
NOT_READY = "No active account yet. On the server run: python -m backend.app.auth create"


class Credentials(BaseModel):
    username: str = Field(max_length=64)
    password: str = Field(max_length=512)


class Code(BaseModel):
    ticket: str = Field(max_length=128)
    code: str = Field(max_length=16)


class PasswordChange(BaseModel):
    current_password: str = Field(max_length=512)
    new_password: str = Field(max_length=512)
    code: str = Field(max_length=16)


def _limited(request):
    """Refuse with 429 when this address has too many recent failures; return the address."""
    client = client_address(request)
    wait = get_auth().retry_after(client)
    if wait:
        raise HTTPException(429, f"Too many attempts. Try again in {wait} seconds.", headers={"Retry-After": str(wait)})
    return client


# ------------------------------------------------------------------ sign-up
@router.post("/signup", status_code=201)
def signup(body: Credentials, request: Request):
    """Ask for an account. Returns the 2FA key to scan; the account stays pending."""
    auth = get_auth()
    client = _limited(request)
    problem = username_problem(body.username) or password_problem(body.password)
    if problem:
        raise HTTPException(400, problem)
    auth.record_failure(client)          # every sign-up counts, so nobody can create accounts in bulk
    secret = new_totp_secret()
    uid = auth.store.add_user(body.username, make_record(body.password), secret)
    if uid is None:
        raise HTTPException(409, "This user name is taken. Pick another one.")
    svg = qr_svg(totp_uri(body.username, secret))
    return {
        "ticket": auth.start_ticket(uid, "setup"),
        "secret": secret,           # shown once, so the key can be typed by hand
        "qr": "data:image/svg+xml;base64," + base64.b64encode(svg.encode()).decode() if svg else None,
    }


@router.post("/signup/2fa")
def signup_2fa(body: Code, request: Request):
    auth = get_auth()
    client = _limited(request)
    user = auth.ticket_user(body.ticket, "setup")
    if user is None or user["totp_confirmed"]:
        raise HTTPException(400, "This sign-up has expired. Start again with a new user name.")
    if not auth.check_code(user, body.code):
        auth.record_failure(client)
        raise HTTPException(400, "That code is not right. Use the newest code in the app and check the phone's time.")
    auth.store.update_user(user["id"], totp_confirmed=1)
    auth.end_ticket(body.ticket)
    return {"status": "pending",
            "message": "2FA is set up. You can log in after your account is approved on the server."}


# ------------------------------------------------------------------ login (two steps)
@router.post("/login")
def login(body: Credentials, request: Request):
    auth = get_auth()
    if not auth.configured:
        raise HTTPException(503, NOT_READY)
    client = _limited(request)
    user = auth.check_password(body.username, body.password)
    if user is None:
        auth.record_failure(client)
        raise HTTPException(401, "Wrong user name or password.")
    if user["status"] == "pending":
        raise HTTPException(403, "Your account is waiting for approval on the server.")
    if user["status"] != "active" or not user["totp_confirmed"]:
        raise HTTPException(403, "This account cannot log in now. Ask the project team.")
    return {"ticket": auth.start_ticket(user["id"], "login")}


@router.post("/login/2fa", status_code=204)
def login_2fa(body: Code, request: Request, response: Response):
    auth = get_auth()
    client = _limited(request)
    user = auth.ticket_user(body.ticket, "login")
    if user is None or user["status"] != "active":
        raise HTTPException(401, "The login has expired. Enter your password again.")
    if not auth.check_code(user, body.code):
        auth.record_failure(client)
        raise HTTPException(400, "That code is not right. Use the newest code in the app.")
    auth.end_ticket(body.ticket)
    auth.clear_failures(client)
    auth.store.update_user(user["id"], last_login=time.time())
    response.set_cookie(COOKIE, auth.start_session(user["id"]), max_age=SESSION_SECONDS, httponly=True,
                        samesite="strict", secure=is_https(request), path="/")


@router.post("/logout", status_code=204)
def logout(request: Request, response: Response):
    get_auth().end_session(request.cookies.get(COOKIE))
    response.delete_cookie(COOKIE, path="/")


@router.get("/me")
def me(user=Depends(require_user)):
    u = get_auth().store.user_by_id(user["id"])
    return {"username": u["username"], "created_at": u["created_at"], "last_login": u["last_login"]}


@router.post("/api/account/password", status_code=204)
def change_password(body: PasswordChange, request: Request, response: Response, user=Depends(require_user)):
    """Needs the current password AND a 2FA code. Logs out every session of this account."""
    auth = get_auth()
    client = _limited(request)
    row = auth.check_password(user["username"], body.current_password)
    if row is None or not auth.check_code(row, body.code):
        auth.record_failure(client)
        raise HTTPException(400, "The current password or the code is wrong.")
    problem = password_problem(body.new_password)
    if problem:
        raise HTTPException(400, problem)
    auth.store.update_user(user["id"], password=make_record(body.new_password))
    auth.end_sessions_of(user["id"])
    response.delete_cookie(COOKIE, path="/")

