import pandas as pd

from ml.defense import FixFinder, add_defense, evidence_text, waf_rules
from ml.knowledge_base import FAMILIES, KNOWLEDGE_BASE


def _rows(paths, bodies=None, status=200, seconds=0):
    n = len(paths)
    t = pd.Timestamp("2026-10-29T10:00:00Z")
    return pd.DataFrame({"method": ["POST" if b else "GET" for b in (bodies or [""] * n)],
                         "path": paths, "body": bodies or [""] * n, "status": [status] * n,
                         "timestamp": [(t + pd.Timedelta(seconds=seconds * i)).isoformat() for i in range(n)]})


def test_knowledge_base_entries_are_complete():
    ids = [e["id"] for e in KNOWLEDGE_BASE]
    assert len(ids) == len(set(ids)) and 15 <= len(ids) <= 20
    for e in KNOWLEDGE_BASE:
        assert e["family"] in FAMILIES and e["fix"] and e["owasp"] and e["cwe"].startswith("CWE-")
    assert {e["family"] for e in KNOWLEDGE_BASE} == set(FAMILIES)


def test_knn_tells_spraying_from_one_account_guessing():
    finder = FixFinder()
    login = "/rest/user/login"
    one = _rows([login] * 8, [f'{{"email":"a@x.lab","password":"p{i}"}}' for i in range(8)], status=401)
    many = _rows([login] * 8, [f'{{"email":"u{i}@x.lab","password":"Summer1"}}' for i in range(8)], status=401)
    slow = _rows([login] * 4, [f'{{"email":"a@x.lab","password":"p{i}"}}' for i in range(4)], status=401, seconds=30)
    pick = lambda rows: finder.nearest(evidence_text("bruteforce", rows), 1, family="bruteforce")[0][0]["id"]
    assert pick(one) == "bruteforce-account"
    assert pick(many) == "bruteforce-spray"
    assert pick(slow) == "bruteforce-slow"


def test_family_limits_the_candidates():
    finder = FixFinder()
    near = finder.nearest("anything at all", 3, family="enum")
    assert [e["family"] for e, _ in near] == ["enum"]


def test_waf_rules_name_the_ip_page_and_field():
    rows = _rows(["/search?q=x"])
    rules = waf_rules("10.9.9.9", "block", {"sqli": rows})
    text = "\n".join(rules)
    assert "@ipMatch 10.9.9.9" in text and "@streq /search" in text and "ARGS:q" in text
    assert waf_rules("10.9.9.9", "rate_limit", {"bruteforce": _rows(["/login"])})[0].startswith("# nginx")


def test_sessions_without_attack_steps_are_allowed():
    req = _rows(["/", "/about"]).assign(ip="10.0.0.1", session="10.0.0.1#0", pred=0, session_attack=0,
                                         behaviour="", type_pred="")
    sessions = pd.DataFrame({"session": ["10.0.0.1#0"], "ip": ["10.0.0.1"], "risk_score": [0],
                             "risk_level": ["low"], "attack_requests": [0], "failed_logins": [0],
                             "max_ids_one_resource": [0], "probes": [0], "not_found": [0],
                             "server_errors": [0], "stage": [""]})
    out = add_defense(req, sessions)
    assert out.loc[0, "action"] == "allow" and out.loc[0, "fixes"] == [] and out.loc[0, "waf_rules"] == []
