"""Security tests for accounts, two-factor login, sessions, saved results and headers
(backend/app/auth.py, accounts.py, history.py, main.py). No model files are needed.
Run: python -m pytest tests/test_auth.py
"""
import json
import sys
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from backend.app import auth as auth_module  # noqa: E402
from backend.app import main  # noqa: E402
from backend.app.auth import (COOKIE, FAILURE_WINDOW, MAX_FAILURES, Auth, make_record, totp_code,  # noqa: E402
                              totp_match)
from backend.app.db import Store  # noqa: E402

PASSWORD = "correct horse battery"
SECRET = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
LOG = '10.0.0.5 - - [16/Oct/2026:18:00:00 +0000] "GET /index.html HTTP/1.1" 200 512 "-" "Mozilla/5.0"\n'


def code(offset=0, secret=SECRET):
    return totp_code(secret, int(time.time() // 30) + offset)


@pytest.fixture
def auth(monkeypatch):
    a = Auth(Store(":memory:"))
    uid = a.store.add_user("tester", make_record(PASSWORD), SECRET, status="active")
    a.store.update_user(uid, totp_confirmed=1)
    monkeypatch.setattr(auth_module, "auth", a)
    monkeypatch.setattr(main, "detector", None)     # past the login check an upload answers 503, not a result
    return a


@pytest.fixture
def client(auth):
    return TestClient(main.app)


def login(client, username="tester", password=PASSWORD, offset=0):
    r = client.post("/login", json={"username": username, "password": password})
    if r.status_code != 200:
        return r
    return client.post("/login/2fa", json={"ticket": r.json()["ticket"], "code": code(offset)})


def upload(client, endpoint):
    return client.post(endpoint, files={"file": ("a.log", LOG.encode(), "text/plain")})


# ---------- TOTP itself ----------

def test_totp_matches_the_rfc_6238_test_vector():
    # RFC 6238 appendix B, SHA-1, T = 59 s -> 94287082 (8 digits); the last 6 digits are what 6-digit apps show.
    secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"      # base32 of "12345678901234567890"
    assert totp_code(secret, 59 // 30) == "287082"
    assert totp_match(secret, "287 082", now=59) == 1
    assert totp_match(secret, "287082", now=59 + 30 * 5) is None     # too old
    assert totp_match(secret, "abcdef", now=59) is None


# ---------- everything with data is closed without a full login ----------

@pytest.mark.parametrize("method,path", [("post", "/analyze"), ("post", "/investigate"), ("get", "/me"),
                                         ("get", "/api/stats"), ("get", "/api/investigations"),
                                         ("get", "/api/investigations/1"), ("delete", "/api/investigations/1")])
def test_data_needs_login(client, method, path):
    r = upload(client, path) if method == "post" else getattr(client, method)(path)
    assert r.status_code == 401


def test_password_alone_is_not_a_login(client):
    r = client.post("/login", json={"username": "tester", "password": PASSWORD})
    assert r.status_code == 200 and "ticket" in r.json()
    assert COOKIE not in r.cookies
    assert client.get("/me").status_code == 401


def test_full_login_opens_the_api(client):
    r = login(client)
    assert r.status_code == 204
    cookie = r.headers["set-cookie"].lower()
    assert "httponly" in cookie and "samesite=strict" in cookie
    assert client.get("/me").json()["username"] == "tester"
    assert upload(client, "/investigate").status_code == 503      # past the login check (no model here)


def test_pages_are_open_but_hold_no_data(client):
    for path in ["/", "/login", "/signup", "/app", "/health"]:
        assert client.get(path).status_code == 200


def test_no_active_account_means_closed_not_open(monkeypatch):
    monkeypatch.setattr(auth_module, "auth", Auth(Store(":memory:")))
    c = TestClient(main.app)
    assert upload(c, "/investigate").status_code == 503
    assert c.post("/login", json={"username": "x", "password": "y" * 10}).status_code == 503


@pytest.mark.parametrize("username,password", [("tester", "wrong password"), ("nobody", PASSWORD), ("", "")])
def test_wrong_password_is_refused(client, username, password):
    assert client.post("/login", json={"username": username, "password": password}).status_code == 401


def test_wrong_code_is_refused(client):
    t = client.post("/login", json={"username": "tester", "password": PASSWORD}).json()["ticket"]
    wrong = "000000" if code() != "000000" else "111111"
    assert client.post("/login/2fa", json={"ticket": t, "code": wrong}).status_code == 400
    assert client.get("/me").status_code == 401


def test_a_code_works_only_once(client):
    assert login(client).status_code == 204
    client.post("/logout")
    assert login(client).status_code == 400            # the same 30-second code again: replay refused


def test_made_up_ticket_and_cookie_are_refused(client):
    assert client.post("/login/2fa", json={"ticket": "made-up", "code": code()}).status_code == 401
    client.cookies.set(COOKIE, "not-a-real-token")
    assert client.get("/me").status_code == 401


def test_logout_ends_the_session(client):
    login(client)
    token = client.cookies.get(COOKIE)
    assert client.post("/logout").status_code == 204
    client.cookies.set(COOKIE, token)
    assert client.get("/me").status_code == 401


def test_disabled_account_is_logged_out_at_once(client, auth):
    auth.store.add_user("someone", make_record(PASSWORD), SECRET, status="active")   # the server stays set up
    login(client)
    auth.store.update_user(auth.store.user_by_name("tester")["id"], status="disabled")
    assert client.get("/me").status_code == 401


def test_session_expires(auth):
    token = auth.start_session(1, now=1000.0)
    assert auth.user_for(token, now=1000.0 + auth_module.SESSION_SECONDS + 1) is None


# ---------- sign-up ----------

def test_signup_needs_2fa_and_approval(client, auth):
    r = client.post("/signup", json={"username": "newbie", "password": "a long password"})
    assert r.status_code == 201
    body = r.json()
    assert body["secret"] and body["ticket"]
    assert client.post("/login", json={"username": "newbie", "password": "a long password"}).status_code == 403
    assert client.post("/signup/2fa", json={"ticket": body["ticket"], "code": code(secret=body["secret"])}).status_code == 200
    # Still pending: 2FA alone does not give access.
    assert client.post("/login", json={"username": "newbie", "password": "a long password"}).status_code == 403
    auth.store.update_user(auth.store.user_by_name("newbie")["id"], status="active")      # = "approve" on the server
    assert client.post("/login", json={"username": "newbie", "password": "a long password"}).status_code == 200


@pytest.mark.parametrize("username,password,status", [("ab", "a long password", 400), ("bad name!", "a long password", 400),
                                                      ("okname", "short", 400), ("TESTER", "a long password", 409)])
def test_signup_checks_name_and_password(client, username, password, status):
    assert client.post("/signup", json={"username": username, "password": password}).status_code == status


def test_signup_is_limited_per_address(client):
    codes = [client.post("/signup", json={"username": f"user{i}", "password": "a long password"}).status_code
             for i in range(MAX_FAILURES + 1)]
    assert codes[:MAX_FAILURES] == [201] * MAX_FAILURES and codes[-1] == 429


def test_password_is_stored_only_as_a_salted_hash(auth):
    row = auth.store.user_by_name("tester")
    assert PASSWORD not in json.dumps(row["password"])
    assert make_record(PASSWORD)["hash"] != make_record(PASSWORD)["hash"]


# ---------- failed-attempt limit ----------

def test_too_many_failures_lock_out_even_the_right_password(client):
    for _ in range(MAX_FAILURES):
        assert client.post("/login", json={"username": "tester", "password": "guess"}).status_code == 401
    r = client.post("/login", json={"username": "tester", "password": PASSWORD})
    assert r.status_code == 429 and int(r.headers["retry-after"]) > 0


def test_failure_limit_clears_after_the_window(auth):
    for i in range(MAX_FAILURES):
        auth.record_failure("10.0.0.9", now=100.0 + i)
    assert auth.retry_after("10.0.0.9", now=105.0) > 0
    assert auth.retry_after("10.0.0.10", now=105.0) == 0
    assert auth.retry_after("10.0.0.9", now=100.0 + FAILURE_WINDOW + MAX_FAILURES) == 0


# ---------- password change ----------

def test_password_change_needs_password_and_code_and_logs_out(client):
    login(client)
    bad = client.post("/api/account/password", json={"current_password": "nope", "new_password": "another long one", "code": code(1)})
    assert bad.status_code == 400
    ok = client.post("/api/account/password", json={"current_password": PASSWORD, "new_password": "another long one", "code": code(1)})
    assert ok.status_code == 204
    assert client.get("/me").status_code == 401
    assert client.post("/login", json={"username": "tester", "password": "another long one"}).status_code == 200


# ---------- saved investigations are private ----------

def test_users_never_see_each_others_results(auth):
    other = auth.store.add_user("other", make_record(PASSWORD), SECRET, status="active")
    mine = auth.store.user_by_name("tester")["id"]
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


def test_results_are_never_cached(client):
    login(client)
    assert client.get("/api/stats").headers["cache-control"] == "no-store"


def test_cross_site_posts_are_refused(client):
    login(client)
    r = client.post("/logout", headers={"origin": "http://evil.example"})
    assert r.status_code == 403
    assert client.get("/me").status_code == 200       # still logged in: the request was dropped


def test_bootstrap_from_env_creates_active_admin_once():
    from backend.app.auth import bootstrap_from_env
    from backend.app.db import Store
    store = Store(":memory:")
    env = {"AAI_ADMIN_USER": "admin", "AAI_ADMIN_PASSWORD": "a-long-demo-password", "AAI_ADMIN_TOTP": "JBSW Y3DP EHPK 3PXP"}
    bootstrap_from_env(store, env)
    bootstrap_from_env(store, env)
    users = store.users()
    assert [u["username"] for u in users] == ["admin"]
    assert users[0]["status"] == "active" and users[0]["totp_confirmed"]


def test_bootstrap_skips_weak_or_partial_settings():
    from backend.app.auth import bootstrap_from_env
    from backend.app.db import Store
    store = Store(":memory:")
    bootstrap_from_env(store, {"AAI_ADMIN_USER": "admin", "AAI_ADMIN_PASSWORD": "short", "AAI_ADMIN_TOTP": "JBSWY3DPEHPK3PXP"})
    bootstrap_from_env(store, {"AAI_ADMIN_USER": "admin", "AAI_ADMIN_PASSWORD": "a-long-demo-password"})
    assert store.users() == []


def test_client_address_uses_last_forwarded_entry_behind_proxy(monkeypatch):
    from types import SimpleNamespace
    from backend.app import auth as A
    req = SimpleNamespace(headers={"x-forwarded-for": "6.6.6.6, 203.0.113.9"}, client=SimpleNamespace(host="10.0.0.1"))
    monkeypatch.setattr(A, "BEHIND_PROXY", False)
    assert A.client_address(req) == "10.0.0.1"
    monkeypatch.setattr(A, "BEHIND_PROXY", True)
    assert A.client_address(req) == "203.0.113.9"
