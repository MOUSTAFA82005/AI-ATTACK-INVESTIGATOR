"""Trusted addresses (backend/app/trusted.py): an account's own IPs or networks are never blocked or
rate-limited, but detection (risk, reasons, stage) is unchanged. Made-up addresses only."""
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from backend.app import main  # noqa: E402
from backend.app.db import Store  # noqa: E402
from backend.app.trusted import apply_trusted, networks, normal_address  # noqa: E402
from tests.test_api import BRUTE_LOG, FakeTree, client, post_investigate, session_of  # noqa: E402,F401


# ---------- normal_address ----------

@pytest.mark.parametrize("text,want", [
    ("10.0.0.7", "10.0.0.7"),
    (" 10.0.0.7 ", "10.0.0.7"),
    ("10.0.0.7/32", "10.0.0.7"),
    ("10.0.0.0/24", "10.0.0.0/24"),
    ("10.0.0.9/24", "10.0.0.0/24"),
    ("2001:db8::1", "2001:db8::1"),
    ("2001:db8::/48", "2001:db8::/48"),
])
def test_normal_address(text, want):
    assert normal_address(text) == want


@pytest.mark.parametrize("bad", ["", "   ", "example.com", "10.0.0", "10.0.0.0/33", "0.0.0.0/0", "10.0.0.0/7", "::/0"])
def test_normal_address_rejects(bad):
    with pytest.raises(ValueError):
        normal_address(bad)


# ---------- apply_trusted ----------

def _result():
    return {"sessions": [
        {"ip": "10.0.0.20", "action": "block", "action_reason": "x", "risk_level": "high", "risk_score": 70},
        {"ip": "10.0.0.21", "action": "rate_limit", "action_reason": "x", "risk_level": "medium", "risk_score": 40},
        {"ip": "10.0.1.5", "action": "block", "action_reason": "x", "risk_level": "high", "risk_score": 70},
        {"ip": "not-an-ip", "action": "block", "action_reason": "x", "risk_level": "high", "risk_score": 70},
    ]}


def test_apply_trusted_changes_only_the_action():
    r = _result()
    marked = apply_trusted(r, networks([{"address": "10.0.0.0/24"}]))
    a, b, c, d = r["sessions"]
    assert marked == 2 and r["trusted_visitors"] == 2
    assert a["trusted"] and a["action"] == "allow" and a["model_action"] == "block"
    assert b["trusted"] and b["action"] == "allow" and b["model_action"] == "rate_limit"
    assert "Trusted address" in a["action_reason"]
    # detection is untouched
    assert (a["risk_level"], a["risk_score"]) == ("high", 70)
    # other addresses keep the model's action
    assert "trusted" not in c and c["action"] == "block"
    assert "trusted" not in d and d["action"] == "block"


def test_apply_trusted_with_no_list_changes_nothing():
    r = _result()
    assert apply_trusted(r, []) == 0
    assert [s["action"] for s in r["sessions"]] == ["block", "rate_limit", "block", "block"]
    assert "trusted_visitors" not in r


def test_apply_trusted_keeps_allow_and_ignores_other_ip_versions():
    r = {"sessions": [{"ip": "10.0.0.20", "action": "allow"}, {"ip": "2001:db8::5", "action": "block"}]}
    apply_trusted(r, networks([{"address": "10.0.0.20"}, {"address": "bad"}]))
    assert r["sessions"][0]["trusted"] and "model_action" not in r["sessions"][0]
    assert r["sessions"][1]["action"] == "block"


# ---------- store ----------

def test_store_trusted_is_per_user():
    s = Store(":memory:")
    from backend.app.auth import make_record
    u1 = s.add_user("one", make_record("pw-one-123456"), email="one@example.com", status="active")
    u2 = s.add_user("two", make_record("pw-two-123456"), email="two@example.com", status="active")
    i = s.add_trusted(u1, "10.0.0.0/24", "office")
    assert s.add_trusted(u1, "10.0.0.0/24") is None            # no duplicates
    assert [t["address"] for t in s.trusted(u1)] == ["10.0.0.0/24"]
    assert s.trusted(u2) == []
    assert s.delete_trusted(u2, i) == 0                         # cannot delete another user's row
    assert s.delete_trusted(u1, i) == 1 and s.count_trusted(u1) == 0


# ---------- API + /investigate ----------

def test_trusted_api_round_trip(client):
    assert client.get("/api/trusted").json() == []
    r = client.post("/api/trusted", json={"address": "10.0.0.9/24", "note": "office NAT"})
    assert r.status_code == 201 and r.json()["address"] == "10.0.0.0/24"
    assert client.post("/api/trusted", json={"address": "10.0.0.0/24"}).status_code == 409
    assert client.post("/api/trusted", json={"address": "nope"}).status_code == 400
    items = client.get("/api/trusted").json()
    assert [(t["address"], t["note"]) for t in items] == [("10.0.0.0/24", "office NAT")]
    assert client.delete(f"/api/trusted/{items[0]['id']}").status_code == 204
    assert client.delete(f"/api/trusted/{items[0]['id']}").status_code == 404
    assert client.get("/api/trusted").json() == []


def test_investigate_never_blocks_a_trusted_visitor(client, monkeypatch):
    monkeypatch.setattr(main, "block_tree", FakeTree())
    before = session_of(post_investigate(client, BRUTE_LOG).json(), "10.0.0.20")
    assert before["action"] == "block" and not before.get("trusted")

    client.post("/api/trusted", json={"address": "10.0.0.20"})
    data = post_investigate(client, BRUTE_LOG).json()
    after = session_of(data, "10.0.0.20")
    assert after["trusted"] and after["action"] == "allow" and after["model_action"] == "block"
    # same detection as before
    for k in ("risk_level", "risk_score", "stage", "behaviours", "reasons"):
        assert after[k] == before[k], k
    assert data["trusted_visitors"] == 1
    # the saved copy says the same
    saved = client.get(f"/api/investigations/{data['id']}").json()
    assert session_of(saved, "10.0.0.20")["action"] == "allow"


def test_sealed_path_ignores_the_trusted_list(client):
    """main._investigate (what the sealed tests ran) never looks at the list."""
    client.post("/api/trusted", json={"address": "10.0.0.20"})
    raw = BRUTE_LOG.encode("utf-8")
    result = main._investigate(raw, main.MODES["sensitive"], "t.log", "sensitive")
    assert not any(s.get("trusted") for s in result["sessions"])
