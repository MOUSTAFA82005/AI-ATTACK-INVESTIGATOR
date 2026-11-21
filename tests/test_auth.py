"""Security tests for accounts, two-step login by e-mail code, sessions, saved results and headers
(backend/app/auth.py, accounts.py, mailer.py, history.py, main.py). No model files and no mail
server are needed: sent codes are captured in a list.
Run: python -m pytest tests/test_auth.py
"""
import json
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from backend.app import accounts, mailer, main  # noqa: E402
from backend.app import auth as auth_module  # noqa: E402
from backend.app.auth import (CODE_TRIES, COOKIE, FAILURE_WINDOW, MAX_FAILURES, Auth, make_record,  # noqa: E402
                              masked)
from backend.app.db import Store  # noqa: E402

USER = "tester"
EMAIL = "tester@example.com"
PASSWORD = "correct horse battery"
LOG = '10.0.0.5 - - [16/Oct/2026:18:00:00 +0000] "GET /index.html HTTP/1.1" 200 512 "-" "Mozilla/5.0"\n'


@pytest.fixture
def sent(monkeypatch):
    """Every code the server 'e-mails', as (to, code, purpose)."""
    box = []
    monkeypatch.setattr(mailer, "send_code", lambda to, code, purpose, env=None: box.append((to, code, purpose)))
    return box


@pytest.fixture
def auth(monkeypatch, sent):
    a = Auth(Store(":memory:"))
    uid = a.store.add_user(USER, make_record(PASSWORD), email=EMAIL, status="active")
    a.store.update_user(uid, totp_confirmed=1)
    monkeypatch.setattr(auth_module, "auth", a)
    monkeypatch.setattr(accounts, "SIGNUP_NEEDS_APPROVAL", False)
    monkeypatch.setattr(main, "detector", None)     # past the login check an upload answers 503, not a result
    return a


@pytest.fixture
def client(auth):
    return TestClient(main.app)


def last_code(sent, purpose=None):
    return [c for _, c, p in sent if purpose in (None, p)][-1]


def wrong(code):
    return "000000" if code != "000000" else "111111"


def login(client, sent, who=EMAIL, password=PASSWORD):
    r = client.post("/login", json={"login": who, "password": password})
    if r.status_code != 200:
        return r
    return client.post("/login/code", json={"ticket": r.json()["ticket"], "code": last_code(sent, "login")})


def upload(client, endpoint):
    return client.post(endpoint, files={"file": ("a.log", LOG.encode(), "text/plain")})


# ---------- everything with data is closed without a full login ----------

@pytest.mark.parametrize("method,path", [("post", "/analyze"), ("post", "/investigate"), ("get", "/me"),
                                         ("get", "/api/stats"), ("get", "/api/investigations"),
                                         ("get", "/api/investigations/1"), ("delete", "/api/investigations/1")])
def test_data_needs_login(client, method, path):
    r = upload(client, path) if method == "post" else getattr(client, method)(path)
    assert r.status_code == 401


def test_password_alone_is_not_a_login(client, sent):
    r = client.post("/login", json={"login": EMAIL, "password": PASSWORD})
    assert r.status_code == 200 and "ticket" in r.json()
    assert r.json()["sent_to"] == masked(EMAIL) and EMAIL not in r.text
    assert sent[-1][0] == EMAIL and sent[-1][2] == "login" and len(sent[-1][1]) == 6
    assert sent[-1][1] not in r.text                   # the code goes only by e-mail
    assert COOKIE not in r.cookies
    assert client.get("/me").status_code == 401


def test_full_login_opens_the_api(client, sent):
    r = login(client, sent)
    assert r.status_code == 204
    cookie = r.headers["set-cookie"].lower()
    assert "httponly" in cookie and "samesite=strict" in cookie
    me = client.get("/me").json()
    assert me["email"] == EMAIL and me["username"] == USER
    assert upload(client, "/investigate").status_code == 503      # past the login check (no model here)


def test_email_is_matched_without_case_or_spaces(client, sent):
    assert login(client, sent, "  Tester@Example.COM ").status_code == 204


def test_pages_are_open_but_hold_no_data(client):
    for path in ["/", "/login", "/signup", "/app", "/health"]:
        assert client.get(path).status_code == 200


def test_no_active_account_means_closed_not_open(monkeypatch, sent):
    monkeypatch.setattr(auth_module, "auth", Auth(Store(":memory:")))
    c = TestClient(main.app)
    assert upload(c, "/investigate").status_code == 503
    assert c.post("/login", json={"login": "x@example.com", "password": "y" * 10}).status_code == 503


@pytest.mark.parametrize("email,password", [(EMAIL, "wrong password"), (USER, "wrong password"), ("nobody@example.com", PASSWORD), ("nobody", PASSWORD), ("", "")])
def test_wrong_password_is_refused_and_sends_nothing(client, sent, email, password):
    assert client.post("/login", json={"login": email, "password": password}).status_code == 401
    assert sent == []


def test_wrong_code_is_refused(client, sent):
    t = client.post("/login", json={"login": EMAIL, "password": PASSWORD}).json()["ticket"]
    assert client.post("/login/code", json={"ticket": t, "code": wrong(last_code(sent))}).status_code == 400
    assert client.get("/me").status_code == 401


def test_too_many_wrong_codes_end_the_ticket(auth):
    ticket, code = auth.start_ticket(1, "login")
    for _ in range(CODE_TRIES - 1):
        assert auth.check_ticket_code(ticket, "login", wrong(code)) == "wrong"
    assert auth.check_ticket_code(ticket, "login", wrong(code)) == "expired"
    assert auth.check_ticket_code(ticket, "login", code) == "expired"     # even the right code is too late


def test_code_expires_and_purpose_must_match(auth):
    ticket, code = auth.start_ticket(1, "login", now=1000.0)
    assert auth.check_ticket_code(ticket, "verify", code, now=1001.0) == "expired"
    assert auth.check_ticket_code(ticket, "login", code, now=1000.0 + auth_module.CODE_SECONDS + 1) == "expired"


def test_a_code_works_only_once(client, sent):
    t = client.post("/login", json={"login": EMAIL, "password": PASSWORD}).json()["ticket"]
    code = last_code(sent)
    assert client.post("/login/code", json={"ticket": t, "code": code}).status_code == 204
    client.post("/logout")
    assert client.post("/login/code", json={"ticket": t, "code": code}).status_code == 401


def test_new_login_ends_the_older_ticket(client, sent):
    t1 = client.post("/login", json={"login": EMAIL, "password": PASSWORD}).json()["ticket"]
    c1 = last_code(sent)
    client.post("/login", json={"login": EMAIL, "password": PASSWORD})
    assert client.post("/login/code", json={"ticket": t1, "code": c1}).status_code == 401


def test_made_up_ticket_and_cookie_are_refused(client):
    assert client.post("/login/code", json={"ticket": "made-up", "code": "123456"}).status_code == 401
    client.cookies.set(COOKIE, "not-a-real-token")
    assert client.get("/me").status_code == 401


def test_resend_waits_then_replaces_the_code(client, sent, auth):
    t = client.post("/login", json={"login": EMAIL, "password": PASSWORD}).json()["ticket"]
    first = last_code(sent)
    r = client.post("/code/resend", json={"ticket": t, "purpose": "login"})
    assert r.status_code == 429 and len(sent) == 1
    auth._tickets[t]["sent"] -= auth_module.RESEND_SECONDS + 1          # pretend the wait has passed
    assert client.post("/code/resend", json={"ticket": t, "purpose": "login"}).status_code == 200
    assert len(sent) == 2
    if last_code(sent) != first:
        assert client.post("/login/code", json={"ticket": t, "code": first}).status_code == 400
    assert client.post("/login/code", json={"ticket": t, "code": last_code(sent)}).status_code == 204


def test_resend_needs_a_live_ticket(client):
    assert client.post("/code/resend", json={"ticket": "made-up", "purpose": "login"}).status_code == 401
    assert client.post("/code/resend", json={"ticket": "x", "purpose": "change"}).status_code == 422


def test_mail_failure_is_a_clear_503(client, monkeypatch):
    def fail(*a, **k):
        raise mailer.MailError("The e-mail could not be sent. Try again in a minute.")
    monkeypatch.setattr(mailer, "send_code", fail)
    r = client.post("/login", json={"login": EMAIL, "password": PASSWORD})
    assert r.status_code == 503 and "could not be sent" in r.json()["detail"]


def test_logout_ends_the_session(client, sent):
    login(client, sent)
    token = client.cookies.get(COOKIE)
    assert client.post("/logout").status_code == 204
    client.cookies.set(COOKIE, token)
    assert client.get("/me").status_code == 401


def test_disabled_account_is_logged_out_at_once(client, auth, sent):
    auth.store.add_user("someone", make_record(PASSWORD), email="someone@example.com", status="active")   # the server stays set up
    login(client, sent)
    auth.store.update_user(auth.store.user_by_name(USER)["id"], status="disabled")
    assert client.get("/me").status_code == 401
    assert client.post("/login", json={"login": EMAIL, "password": PASSWORD}).status_code == 403


def test_session_expires(auth):
    token = auth.start_session(1, now=1000.0)
    assert auth.user_for(token, now=1000.0 + auth_module.SESSION_SECONDS + 1) is None


# ---------- sign-up ----------

def test_signup_works_after_the_email_is_confirmed(client, sent):
    r = client.post("/signup", json={"username": "newbie", "email": "Newbie@Example.com", "password": "Long-Pass-2026!"})
    assert r.status_code == 201
    body = r.json()
    assert body["ticket"] and body["sent_to"] == masked("newbie@example.com")
    assert sent[-1][0] == "newbie@example.com" and sent[-1][2] == "verify"
    # E-mail not confirmed yet: no login.
    assert client.post("/login", json={"login": "newbie@example.com", "password": "Long-Pass-2026!"}).status_code == 403
    assert client.post("/signup/verify", json={"ticket": body["ticket"], "code": wrong(last_code(sent))}).status_code == 400
    done = client.post("/signup/verify", json={"ticket": body["ticket"], "code": last_code(sent, "verify")})
    assert done.status_code == 200 and done.json()["status"] == "active"
    assert login(client, sent, "newbie", "Long-Pass-2026!").status_code == 204


def test_signup_again_before_confirming_starts_over(client, sent, auth):
    first = client.post("/signup", json={"username": "newbie", "email": "newbie@example.com", "password": "Long-Pass-2026!"}).json()
    old_code = last_code(sent)
    client.post("/signup", json={"username": "newbie2", "email": "newbie@example.com", "password": "Second-Strong-88"})
    assert len(auth.store.users()) == 2                        # no duplicate account
    assert client.post("/signup/verify", json={"ticket": first["ticket"], "code": old_code}).status_code == 401
    assert auth.check_password("newbie2", "Second-Strong-88") is not None      # the new name replaced the old one
    assert auth.store.user_by_name("newbie") is None


def test_signup_name_is_taken_by_another_account(client, sent):
    body = {"username": "Tester", "email": "new@example.com", "password": "Long-Pass-2026!"}
    r = client.post("/signup", json=body)
    assert r.status_code == 409 and "user name" in r.json()["detail"] and sent == []


def test_unconfirmed_signups_free_their_name_after_a_day(client, sent, auth):
    client.post("/signup", json={"username": "squat", "email": "a@example.com", "password": "Long-Pass-2026!"})
    uid = auth.store.user_by_name("squat")["id"]
    auth.store._exec("UPDATE users SET created_at = created_at - ? WHERE id = ?", (accounts.UNCONFIRMED_SECONDS + 1, uid))
    r = client.post("/signup", json={"username": "squat", "email": "b@example.com", "password": "Long-Pass-2026!"})
    assert r.status_code == 201 and auth.store.user_by_name("squat")["email"] == "b@example.com"


def test_old_database_gets_an_email_column(tmp_path):
    import sqlite3
    path = tmp_path / "old.db"
    db = sqlite3.connect(path)
    db.execute("CREATE TABLE users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT NOT NULL UNIQUE COLLATE NOCASE, "
               "password TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending', totp_secret TEXT NOT NULL, "
               "totp_confirmed INTEGER NOT NULL DEFAULT 0, totp_last_step INTEGER NOT NULL DEFAULT 0, "
               "created_at REAL NOT NULL, last_login REAL)")
    db.execute("INSERT INTO users (username, password, totp_secret, created_at) VALUES ('Old@Mail.com', '{}', '', 1), "
               "('admin', '{}', '', 1)")
    db.commit()
    db.close()
    store = Store(path)
    assert store.user_by_name("admin")["email"] is None
    assert store.user_by_email("old@mail.com")["username"] == "Old@Mail.com"


def test_account_without_email_cannot_get_a_code(client, auth, sent):
    auth.store.add_user("legacy", make_record(PASSWORD), status="active")
    r = client.post("/login", json={"login": "legacy", "password": PASSWORD})
    assert r.status_code == 403 and sent == []


def test_signup_can_require_approval(client, auth, monkeypatch, sent):
    monkeypatch.setattr(accounts, "SIGNUP_NEEDS_APPROVAL", True)
    body = client.post("/signup", json={"username": "newbie", "email": "newbie@example.com", "password": "Long-Pass-2026!"}).json()
    done = client.post("/signup/verify", json={"ticket": body["ticket"], "code": last_code(sent)})
    assert done.json()["status"] == "pending"
    assert client.post("/login", json={"login": "newbie@example.com", "password": "Long-Pass-2026!"}).status_code == 403
    auth.store.update_user(auth.store.user_by_name("newbie")["id"], status="active")   # = "approve"
    assert client.post("/login", json={"login": "newbie@example.com", "password": "Long-Pass-2026!"}).status_code == 200


@pytest.mark.parametrize("name,email,password,status", [
    ("okname", "not-an-email", "Long-Pass-2026!", 400), ("okname", "a@b", "Long-Pass-2026!", 400),
    ("okname", "ok@example.com", "short", 400), ("ab", "ok@example.com", "Long-Pass-2026!", 400),
    ("bad name!", "ok@example.com", "Long-Pass-2026!", 400), ("a@b.com", "ok@example.com", "Long-Pass-2026!", 400),
    ("TESTER", "ok@example.com", "Long-Pass-2026!", 409)])
def test_signup_checks_name_email_and_password(client, sent, name, email, password, status):
    body = {"username": name, "email": email, "password": password}
    assert client.post("/signup", json=body).status_code == status
    assert sent == []


def test_signup_is_limited_per_address(client):
    codes = [client.post("/signup", json={"username": f"user{i}", "email": f"user{i}@example.com", "password": "Long-Pass-2026!"}).status_code
             for i in range(MAX_FAILURES + 1)]
    assert codes[:MAX_FAILURES] == [201] * MAX_FAILURES and codes[-1] == 429


def test_password_is_stored_only_as_a_salted_hash(auth):
    row = auth.store.user_by_name(USER)
    assert PASSWORD not in json.dumps(row["password"])
    assert make_record(PASSWORD)["hash"] != make_record(PASSWORD)["hash"]


# ---------- failed-attempt limit ----------

def test_too_many_failures_lock_out_even_the_right_password(client):
    for _ in range(MAX_FAILURES):
        assert client.post("/login", json={"login": EMAIL, "password": "guess"}).status_code == 401
    r = client.post("/login", json={"login": EMAIL, "password": PASSWORD})
    assert r.status_code == 429 and int(r.headers["retry-after"]) > 0


def test_failure_limit_clears_after_the_window(auth):
    for i in range(MAX_FAILURES):
        auth.record_failure("10.0.0.9", now=100.0 + i)
    assert auth.retry_after("10.0.0.9", now=105.0) > 0
    assert auth.retry_after("10.0.0.10", now=105.0) == 0
    assert auth.retry_after("10.0.0.9", now=100.0 + FAILURE_WINDOW + MAX_FAILURES) == 0


# ---------- password change ----------

def test_password_change_needs_password_and_code_and_logs_out(client, sent):
    login(client, sent)
    new = {"current_password": PASSWORD, "new_password": "Another-Strong-77"}
    assert client.post("/api/account/password", json={**new, "code": "123456"}).status_code == 400   # no code sent yet
    assert client.post("/api/account/code").status_code == 200
    code = last_code(sent, "change")
    assert sent[-1][0] == EMAIL
    assert client.post("/api/account/password", json={**new, "current_password": "nope", "code": code}).status_code == 400
    assert client.post("/api/account/password", json={**new, "code": wrong(code)}).status_code == 400
    assert client.post("/api/account/password", json={**new, "code": code}).status_code == 204
    assert client.get("/me").status_code == 401
    assert client.post("/login", json={"login": EMAIL, "password": "Another-Strong-77"}).status_code == 200


# ---------- saved investigations are private ----------

def test_users_never_see_each_others_results(auth):
    other = auth.store.add_user("other", make_record(PASSWORD), email="other@example.com", status="active")
    mine = auth.store.user_by_name(USER)["id"]
    inv = auth.store.save_investigation(other, "x.log", {"parsed": 1}, {"filename": "x.log", "sessions": []})
    assert auth.store.investigation(mine, inv) is None
    assert auth.store.investigations(mine) == []
    assert auth.store.delete_investigation(mine, inv) == 0
    assert auth.store.investigation(other, inv)["filename"] == "x.log"


# ---------- browser-side protections ----------

def test_security_headers(client):
    h = client.get("/").headers
    assert "script-src 'self'" in h["content-security-policy"] and "frame-ancestors 'none'" in h["content-security-policy"]
    assert h["x-content-type-options"] == "nosniff" and h["x-frame-options"] == "DENY"


def test_results_are_never_cached(client, sent):
    login(client, sent)
    assert client.get("/api/stats").headers["cache-control"] == "no-store"


def test_cross_site_posts_are_refused(client, sent):
    login(client, sent)
    r = client.post("/logout", headers={"origin": "http://evil.example"})
    assert r.status_code == 403
    assert client.get("/me").status_code == 200       # still logged in: the request was dropped


# ---------- hosted demo settings ----------

def test_bootstrap_from_env_creates_active_admin_once():
    from backend.app.auth import bootstrap_from_env
    store = Store(":memory:")
    env = {"AAI_ADMIN_EMAIL": "Admin@Example.com", "AAI_ADMIN_PASSWORD": "Demo-Strong-Pass-42!"}
    bootstrap_from_env(store, env)
    bootstrap_from_env(store, env)
    users = store.users()
    assert [(u["username"], u["email"]) for u in users] == [("admin", "admin@example.com")]
    assert users[0]["status"] == "active" and users[0]["totp_confirmed"]


def test_bootstrap_skips_weak_or_partial_settings():
    from backend.app.auth import bootstrap_from_env
    store = Store(":memory:")
    bootstrap_from_env(store, {"AAI_ADMIN_EMAIL": "admin@example.com", "AAI_ADMIN_PASSWORD": "short"})
    bootstrap_from_env(store, {"AAI_ADMIN_EMAIL": "not-an-email", "AAI_ADMIN_PASSWORD": "Demo-Strong-Pass-42!"})
    bootstrap_from_env(store, {"AAI_ADMIN_EMAIL": "admin@example.com"})
    assert store.users() == []


def test_client_address_uses_last_forwarded_entry_behind_proxy(monkeypatch):
    from types import SimpleNamespace
    req = SimpleNamespace(headers={"x-forwarded-for": "6.6.6.6, 203.0.113.9"}, client=SimpleNamespace(host="10.0.0.1"))
    monkeypatch.setattr(auth_module, "BEHIND_PROXY", False)
    assert auth_module.client_address(req) == "10.0.0.1"
    monkeypatch.setattr(auth_module, "BEHIND_PROXY", True)
    assert auth_module.client_address(req) == "203.0.113.9"


# ---------- mailer ----------

def test_console_mode_only_on_a_local_machine(capsys):
    mailer.send_code("a@example.com", "123456", "login", env={})
    assert "123456" in capsys.readouterr().err
    with pytest.raises(mailer.MailError):
        mailer.send_code("a@example.com", "123456", "login", env={"AAI_BEHIND_PROXY": "1"})


def test_mail_message_names_the_code_and_purpose():
    msg = mailer.build_message("a@example.com", "123456", "verify", "sender@example.com")
    assert "123456" in msg["Subject"] and msg["To"] == "a@example.com"
    text = msg.get_body(preferencelist=("plain",)).get_content()
    assert "123456" in text and "10 minutes" in text


def test_mail_has_branded_html_with_inline_logo():
    msg = mailer.build_message("a@example.com", "123456", "login", "sender@example.com")
    page = msg.get_body(preferencelist=("html",)).get_content()
    assert "TALON" in page and "10 minutes" in page
    assert all(f">{d}</div>" in page for d in "123456")
    logo = [p for p in msg.walk() if p.get_content_type() == "image/png"]
    assert len(logo) == 1 and f"cid:{logo[0]['Content-ID'].strip('<>')}" in page
    assert "http://" not in page and "https://" not in page   # nothing loaded from the internet


@pytest.mark.parametrize("pw,ok", [
    ("Long-Pass-2026!", True), ("short-A1!", False), ("alllowercase-12!", False), ("ALLUPPERCASE-12!", False),
    ("No-Digits-Here!", False), ("NoSymbols12345", False), ("Password123456!", False), ("Tester-Strong-12!", False),
    ("Aaaaaaaaaa1!", False)])
def test_password_rules(pw, ok):
    from backend.app.auth import password_problem
    assert (password_problem(pw, "tester", "tester@example.com") is None) is ok


def test_signup_refuses_a_weak_password_with_the_reason(client, sent):
    r = client.post("/signup", json={"username": "newbie", "email": "n@example.com", "password": "alllowercase-12!"})
    assert r.status_code == 400 and "upper-case" in r.json()["detail"] and sent == []


def test_settings_file_fills_missing_values_only(tmp_path):
    f = tmp_path / "mail.env"
    f.write_text('﻿# comment\nAAI_SMTP_HOST=smtp.gmail.com\nAAI_SMTP_PORT = "587"\n'
                 "AAI_SMTP_USER=from-file@example.com\nOTHER=x\nbroken line\n", encoding="utf-8")
    env = {"AAI_SMTP_USER": "from-terminal@example.com"}
    loaded = mailer.load_settings(f, env)
    assert env == {"AAI_SMTP_USER": "from-terminal@example.com", "AAI_SMTP_HOST": "smtp.gmail.com", "AAI_SMTP_PORT": "587"}
    assert sorted(loaded) == ["AAI_SMTP_HOST", "AAI_SMTP_PORT"]
    assert mailer.load_settings(tmp_path / "missing.env", {}) == []


def test_mail_tries_the_other_port_and_names_the_step(monkeypatch, capsys):
    tried = []

    def fake(host, port, user, password, msg):
        tried.append(port)
        if port == 587:
            raise mailer._StepError("connect", OSError("closed"))

    monkeypatch.setattr(mailer, "_deliver", fake)
    env = {"AAI_SMTP_HOST": "smtp.gmail.com", "AAI_SMTP_PORT": "587", "AAI_SMTP_USER": "a@x.com", "AAI_SMTP_PASSWORD": "abcd efgh"}
    mailer.send_code("b@example.com", "123456", "login", env=env)
    assert tried == [587, 465]
    err = capsys.readouterr().err
    assert "step 'connect'" in err and "AAI_SMTP_PORT=465" in err


def test_mail_wrong_password_is_not_retried(monkeypatch):
    tried = []

    def fake(host, port, user, password, msg):
        tried.append(port)
        raise mailer._StepError("login", OSError("bad credentials"))

    monkeypatch.setattr(mailer, "_deliver", fake)
    env = {"AAI_SMTP_HOST": "smtp.gmail.com", "AAI_SMTP_USER": "a@x.com", "AAI_SMTP_PASSWORD": "x"}
    with pytest.raises(mailer.MailError):
        mailer.send_code("b@example.com", "123456", "login", env=env)
    assert tried == [587]


def test_mail_empty_password_is_reported():
    with pytest.raises(mailer.MailError):
        mailer.send_code("b@example.com", "1", "login", env={"AAI_SMTP_HOST": "h", "AAI_SMTP_USER": "a@x.com"})


def test_save_password_replaces_the_line(tmp_path, monkeypatch):
    import getpass
    f = tmp_path / "mail.env"
    f.write_text("AAI_SMTP_HOST=smtp.gmail.com\r\nAAI_SMTP_PASSWORD=\r\n", encoding="utf-8")
    monkeypatch.setattr(getpass, "getpass", lambda prompt="": "abcd efgh ijkl mnop")
    mailer.save_password(f)
    env = {}
    mailer.load_settings(f, env)
    assert env == {"AAI_SMTP_HOST": "smtp.gmail.com", "AAI_SMTP_PASSWORD": "abcdefghijklmnop"}


# ---------- hardening (security review 2026-11-21) ----------

def test_signup_with_a_taken_email_looks_like_a_new_signup(client, sent, auth):
    """Nobody can learn which addresses have accounts: same answer, and the owner gets a notice without a code."""
    r = client.post("/signup", json={"username": "okname", "email": "TESTER@example.com", "password": "Long-Pass-2026!"})
    fresh = client.post("/signup", json={"username": "other", "email": "fresh@example.com", "password": "Long-Pass-2026!"})
    assert r.status_code == fresh.status_code == 201 and set(r.json()) == set(fresh.json())
    assert sent[0] == (EMAIL, None, "exists") and sent[1][2] == "verify"
    assert auth.store.user_by_name("okname") is None
    # The decoy ticket behaves like a real one and never confirms anything.
    assert client.post("/signup/verify", json={"ticket": r.json()["ticket"], "code": "123456"}).status_code == 400
    assert client.post("/code/resend", json={"ticket": r.json()["ticket"], "purpose": "verify"}).status_code == 429


def test_signup_with_own_name_and_taken_email_says_name_taken(client, sent):
    """The name check does not reveal which address owns a name."""
    a = client.post("/signup", json={"username": USER, "email": EMAIL, "password": "Long-Pass-2026!"})
    b = client.post("/signup", json={"username": USER, "email": "x@example.com", "password": "Long-Pass-2026!"})
    assert a.status_code == b.status_code == 409 and sent == []


def test_account_is_limited_across_addresses(client, auth, monkeypatch):
    """Slow guessing from many addresses stops after ACCOUNT_MAX_FAILURES on one account."""
    ips = iter(f"10.1.0.{i}" for i in range(100))
    monkeypatch.setattr(accounts, "client_address", lambda request: next(ips))
    codes = [client.post("/login", json={"login": EMAIL, "password": f"wrong-{i}"}).status_code
             for i in range(auth_module.ACCOUNT_MAX_FAILURES)]
    assert codes == [401] * auth_module.ACCOUNT_MAX_FAILURES
    # Even the right password now waits, whichever name is typed; an unknown name is limited the same way.
    assert client.post("/login", json={"login": USER, "password": PASSWORD}).status_code == 429
    for i in range(auth_module.ACCOUNT_MAX_FAILURES):
        client.post("/login", json={"login": "nobody@example.com", "password": f"wrong-{i}"})
    assert client.post("/login", json={"login": "nobody@example.com", "password": "x"}).status_code == 429


def test_one_address_gets_at_most_mail_max_emails(client, sent, auth):
    auth.store.add_user("x", make_record(PASSWORD), email="x@example.com", status="active")
    for i in range(auth_module.MAIL_MAX):
        auth.clear_failures("testclient")
        assert client.post("/login", json={"login": EMAIL, "password": PASSWORD}).status_code == 200
    auth.clear_failures("testclient")
    r = client.post("/login", json={"login": EMAIL, "password": PASSWORD})
    assert r.status_code == 429 and "e-mails" in r.json()["detail"] and len(sent) == auth_module.MAIL_MAX


def test_password_change_sends_a_notice(client, auth, sent):
    login(client, sent)
    client.post("/api/account/code")
    r = client.post("/api/account/password", json={"current_password": PASSWORD, "new_password": "Brand-New-Pass-77",
                                                  "code": last_code(sent, "change")})
    assert r.status_code == 204 and sent[-1] == (EMAIL, None, "changed")


def test_session_ends_after_idle_time(auth):
    token = auth.start_session(1, now=1000.0)
    auth.store.add_user  # noqa: B018 (the user row does not matter for the expiry check)
    assert auth.user_for(token, now=1000.0 + auth_module.SESSION_IDLE_SECONDS + 1) is None


def test_cross_site_post_is_refused_even_without_origin(client):
    r = client.post("/login", json={"login": EMAIL, "password": PASSWORD}, headers={"Sec-Fetch-Site": "cross-site"})
    assert r.status_code == 403
    r = client.post("/login", json={"login": EMAIL, "password": PASSWORD}, headers={"Origin": "null"})
    assert r.status_code == 403


def test_api_description_pages_are_off(client):
    for path in ("/docs", "/redoc", "/openapi.json"):
        assert client.get(path).status_code == 404


def test_hsts_only_over_https(client):
    assert "strict-transport-security" not in client.get("/health").headers
    assert "max-age" in TestClient(main.app, base_url="https://testserver").get("/health").headers["strict-transport-security"]


def test_uploaded_filename_is_cleaned():
    assert main._filename("C:\\Users\\me\\access.log") == "access.log"
    assert main._filename("../../etc/passwd") == "passwd"
    assert main._filename("a\x00b\nc.log") == "abc.log"
    assert len(main._filename("x" * 5000)) == main.MAX_FILENAME
    assert main._filename("") == main._filename(None) == "log"


def test_one_analysis_per_account_and_a_global_cap():
    from fastapi import HTTPException
    jobs = main._Jobs()
    jobs.start(1)
    with pytest.raises(HTTPException) as e:
        jobs.start(1)
    assert e.value.status_code == 429
    jobs.start(2)
    with pytest.raises(HTTPException) as e:
        jobs.start(3)
    assert e.value.status_code == 503
    jobs.end(1)
    jobs.start(3)


def test_saved_investigations_are_capped(client, auth, sent, monkeypatch):
    login(client, sent)
    monkeypatch.setattr(main, "MAX_SAVED", 0)
    assert upload(client, "/investigate").status_code == 409


def test_notice_email_has_no_code():
    msg = mailer.build_message("a@example.com", None, "exists", "talon@example.com")
    assert "None" not in msg["Subject"] and "already have" in msg.get_body(preferencelist=("html",)).get_content()
    assert not __import__("re").search(r">\d</div>", msg.get_body(preferencelist=("html",)).get_content())
