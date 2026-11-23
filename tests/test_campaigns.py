"""Distributed campaigns (backend/app/campaigns.py): many addresses, same browser name, only probe requests.
Report only: visitor verdicts never change. Documentation addresses only (RFC 5737)."""
import copy
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from backend.app import main  # noqa: E402
from backend.app.campaigns import find_campaigns  # noqa: E402
from tests.test_api import client, post_investigate  # noqa: E402,F401

OLD = "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.11 (KHTML, like Gecko) Chrome/23.0.1271.97 Safari/537.11"
NEW = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/142.0.0.0 Safari/537.36"


def line(ip, path, status, ua, sec):
    return f'{ip} - - [16/Oct/2026:18:{sec // 60:02d}:{sec % 60:02d} +0000] "GET {path} HTTP/1.1" {status} 200 "-" "{ua}"\n'


def botnet(n, start=0):
    names = ["/a.php", "/dd.php", "/x.php", "/1.php", "/aa.php", "/admin8.php", "/11.php", "/ak.php"]
    return "".join(line(f"198.51.100.{start + i}", names[i % len(names)], 404, OLD, i) for i in range(n))


def normal(n, start=100):
    return "".join(line(f"203.0.113.{start + i}", p, 200, NEW, 60 + i * 3 + k)
                   for i in range(n) for k, p in enumerate(["/", "/about", "/static/app.css"]))


def run(text):
    raw = text.encode("utf-8")
    r = main._investigate(raw, main.MODES["sensitive"], "t.log", "sensitive")
    before = copy.deepcopy([{k: s.get(k) for k in ("risk_level", "risk_score", "action", "reasons", "stage")}
                            for s in r["sessions"]])
    found = find_campaigns(r, raw)
    after = [{k: s.get(k) for k in ("risk_level", "risk_score", "action", "reasons", "stage")} for s in r["sessions"]]
    assert before == after          # report only: verdicts never change
    return r, found


def test_botnet_is_one_campaign(client):
    r, found = run(botnet(8) + normal(5))
    assert len(found) == 1
    c = found[0]
    assert c["user_agent"] == OLD and len(c["addresses"]) == 8 and c["visitors"] == 8 and c["requests"] == 8
    assert set(c["examples"]) <= {"/a.php", "/dd.php", "/x.php", "/1.php", "/aa.php", "/admin8.php", "/11.php", "/ak.php"}
    assert c["statuses"] == {"404": 8}
    marked = {s["ip"] for s in r["sessions"] if s.get("campaign") == 1}
    assert marked == set(c["addresses"])
    assert not any(s.get("campaign") for s in r["sessions"] if s["ip"].startswith("203.0.113."))


def test_too_few_addresses_is_not_a_campaign(client):
    _, found = run(botnet(4) + normal(3))
    assert found == []


def test_normal_visitors_are_never_a_campaign(client):
    _, found = run(normal(20))
    assert found == []


def test_shared_agent_with_real_browsing_is_not_a_campaign(client):
    # 6 probing addresses, but 4 other visitors with the same agent browse normally: share below 0.8
    browsing = "".join(line(f"192.0.2.{i}", p, 200, OLD, 200 + i * 3 + k)
                       for i in range(4) for k, p in enumerate(["/", "/about", "/blog"]))
    _, found = run(botnet(6) + browsing)
    assert found == []


def test_pages_that_were_served_are_not_probes(client):
    served = "".join(line(f"198.51.100.{i}", "/index.php", 200, OLD, i) for i in range(8))
    _, found = run(served)
    assert found == []


def test_investigate_returns_and_saves_campaigns(client):
    data = post_investigate(client, botnet(6) + normal(3)).json()
    assert len(data["campaigns"]) == 1 and len(data["campaigns"][0]["addresses"]) == 6
    saved = client.get(f"/api/investigations/{data['id']}").json()
    assert saved["campaigns"] == data["campaigns"]


def test_sealed_path_has_no_campaigns(client):
    r = main._investigate(botnet(8).encode("utf-8"), main.MODES["sensitive"], "t.log", "sensitive")
    assert "campaigns" not in r and not any(s.get("campaign") for s in r["sessions"])
