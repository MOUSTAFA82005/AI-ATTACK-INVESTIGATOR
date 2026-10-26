"""Tests for backend/app/privacy.py. Run: python tests/test_privacy.py"""
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from backend.app.privacy import mask_path, mask_secrets  # noqa: E402


def test_json_simple():
    out = json.loads(mask_secrets('{"email":"a@b.test","password":"x"}'))
    assert out == {"email": "a@b.test", "password": "***"}


def test_json_nested():
    body = '{"user":{"name":"a","auth":{"Token":"t1"}},"cards":[{"cvv":"123","n":1}]}'
    out = json.loads(mask_secrets(body))
    assert out["user"]["auth"]["Token"] == "***"
    assert out["cards"][0]["cvv"] == "***"
    assert out["cards"][0]["n"] == 1
    assert out["user"]["name"] == "a"


def test_form():
    assert mask_secrets("user=a&password=x") == "user=a&password=***"


def test_query_string():
    assert mask_path("/login?pwd=x&lang=en") == "/login?pwd=***&lang=en"


def test_no_secrets_unchanged():
    assert mask_secrets('{"email": "a@b.test"}') == '{"email": "a@b.test"}'
    assert mask_secrets("user=a&city=cairo") == "user=a&city=cairo"
    assert mask_path("/search?q=apple") == "/search?q=apple"
    assert mask_path("/index.html") == "/index.html"


def test_not_json_not_form_unchanged():
    assert mask_secrets("just some text") == "just some text"
    assert mask_secrets("{broken json") == "{broken json"
    assert mask_secrets("") == ""


def test_case_insensitive():
    assert mask_secrets("PASSWORD=x") == "PASSWORD=***"
    assert json.loads(mask_secrets('{"PassWord":"x"}'))["PassWord"] == "***"


def test_exact_match_only():
    # Decision: exact names only, so "passport" is NOT hidden.
    assert mask_secrets("passport=AB123") == "passport=AB123"


def test_secret_name_variants_are_masked():
    for name in ["newPassword", "passwordRepeat", "confirm_password", "access_token", "cardNumber"]:
        assert mask_secrets(f"{name}=x") == f"{name}=***"
        assert json.loads(mask_secrets(json.dumps({name: "x"})))[name] == "***"
        assert mask_path(f"/register?{name}=x") == f"/register?{name}=***"


def test_short_names_stay_exact():
    for name in ["passport", "compass", "cardigan"]:
        assert mask_secrets(f"{name}=x") == f"{name}=x"
        assert json.loads(mask_secrets(json.dumps({name: "x"})))[name] == "x"

if __name__ == "__main__":
    tests = [f for n, f in sorted(globals().items()) if n.startswith("test_")]
    for t in tests:
        t()
        print("ok", t.__name__)
    print(f"{len(tests)} tests passed")