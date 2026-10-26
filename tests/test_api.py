"""API tests for /health and /analyze. They use a fake model, so models/detector.joblib is not needed.
Run: python -m pytest tests/
"""
import sys
from pathlib import Path

import numpy as np
import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from backend.app import main  # noqa: E402


# ---------- fakes ----------

class FakeDetector:
    """High attack probability when the path contains 'attack', low otherwise."""

    def predict_proba(self, X):
        p = np.array([0.95 if "attack" in path else 0.05 for path in X])
        return np.column_stack([1 - p, p])


@pytest.fixture
def client(monkeypatch):
    seen = {"bodies": []}

    def fake_to_frame(methods, paths, bodies):
        seen["bodies"].extend(bodies)      # remember what the model "saw"
        return paths                        # the fake detector only needs the paths

    monkeypatch.setattr(main, "detector", FakeDetector())
    monkeypatch.setattr(main, "to_frame", fake_to_frame)
    c = TestClient(main.app)
    c.seen = seen
    return c


def post_log(client, text, name="test.log"):
    return client.post("/analyze", files={"file": (name, text.encode("utf-8"), "text/plain")})


# ---------- sample logs (made-up data only) ----------

COMBINED = (
    '10.0.0.5 - - [16/Oct/2026:18:00:00 +0000] "GET /index.html HTTP/1.1" 200 512 "-" "Mozilla/5.0"\n'
    '10.0.0.6 - - [16/Oct/2026:18:00:01 +0000] "GET /attack?id=1 HTTP/1.1" 200 512 "-" "Mozilla/5.0"\n'
    '10.0.0.7 - - [16/Oct/2026:18:00:02 +0000] "GET /about HTTP/1.1" 200 300 "-" "Mozilla/5.0"\n'
)

JSON_LOG = (
    '{"remote_addr":"10.0.0.5","time_local":"16/Oct/2026:18:00:00 +0000","request_method":"GET",'
    '"request_uri":"/index.html","status":200,"body_bytes_sent":512,"http_user_agent":"Mozilla/5.0"}\n'
    '{"remote_addr":"10.0.0.6","time_local":"16/Oct/2026:18:00:01 +0000","request_method":"GET",'
    '"request_uri":"/attack?id=1","status":200,"body_bytes_sent":512,"http_user_agent":"Mozilla/5.0"}\n'
)

IIS_LOG = (
    "#Fields: date time c-ip cs-method cs-uri-stem cs-uri-query sc-status sc-bytes cs(User-Agent)\n"
    "2026-10-16 18:00:00 10.0.0.5 GET /index.html - 200 512 Mozilla/5.0\n"
    "2026-10-16 18:00:01 10.0.0.6 GET /attack id=1 200 512 Mozilla/5.0\n"
)

# The body is the extra last field; the quotes inside it are escaped like Nginx does.
LOGIN_BODY = '{\\"email\\":\\"a@b.test\\",\\"password\\":\\"123\\"}'
LOGIN_LOG = (
    '10.0.0.9 - - [16/Oct/2026:18:00:03 +0000] "POST /rest/user/login HTTP/1.1" 401 10 "-" "Mozilla/5.0" "'
    + LOGIN_BODY + '"\n'
)


# ---------- /health ----------

def test_health(client):
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json() == {"status": "ok", "model_loaded": True}


# ---------- /analyze: normal cases ----------

def test_analyze_combined(client):
    r = post_log(client, COMBINED)
    assert r.status_code == 200
    data = r.json()
    assert data["format"] == "combined"
    assert data["parsed"] == 3
    assert data["skipped"] == 0
    assert data["attacks"] == 1
    assert data["normal"] == 2
    labels = [x["label"] for x in data["results"]]
    assert labels == ["normal", "attack", "normal"]


def test_analyze_json_log(client):
    data = post_log(client, JSON_LOG).json()
    assert data["format"] == "json"
    assert (data["attacks"], data["normal"]) == (1, 1)


def test_analyze_iis_log(client):
    data = post_log(client, IIS_LOG).json()
    assert data["format"] == "w3c"
    assert (data["attacks"], data["normal"]) == (1, 1)


# ---------- /analyze: error cases (Task 3) ----------

def test_empty_file_returns_400(client):
    r = post_log(client, "")
    assert r.status_code == 400
    assert "empty" in r.json()["detail"].lower()


def test_whitespace_only_returns_400(client):
    assert post_log(client, "  \n \n").status_code == 400


def test_unknown_format_returns_400(client):
    r = post_log(client, "hello, this is not an access log\n")
    assert r.status_code == 400
    assert "Unknown log format" in r.json()["detail"]
    assert "combined" in r.json()["detail"]           # lists the supported formats


def test_too_large_returns_413(client, monkeypatch):
    monkeypatch.setattr(main, "MAX_UPLOAD_BYTES", 10)   # tiny limit, no need for a 50 MB file
    r = post_log(client, COMBINED)
    assert r.status_code == 413
    assert "larger than" in r.json()["detail"]


def test_missing_model_returns_503(client, monkeypatch):
    monkeypatch.setattr(main, "detector", None)
    r = post_log(client, COMBINED)
    assert r.status_code == 503
    assert client.get("/health").json()["model_loaded"] is False


# ---------- /analyze: secrets (Task 2) ----------

def test_password_is_masked_but_model_saw_original(client):
    r = post_log(client, LOGIN_LOG)
    assert r.status_code == 200
    body = r.json()["results"][0]["body"]
    assert '"password":"***"' in body
    assert "123" not in body
    assert "a@b.test" in body                          # other fields stay readable
    # The model received the original text, so detection is not affected by masking.
    assert any("123" in b for b in client.seen["bodies"])


def test_query_secret_is_masked_in_path(client):
    log = '10.0.0.9 - - [16/Oct/2026:18:00:03 +0000] "GET /login?pwd=abc&lang=en HTTP/1.1" 200 10 "-" "Mozilla/5.0"\n'
    path = post_log(client, log).json()["results"][0]["path"]
    assert path == "/login?pwd=***&lang=en"