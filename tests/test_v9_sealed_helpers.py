"""Helpers of eval/v9_sealed_test.py, on made-up lines only (no sealed data)."""
from eval.v9_sealed_test import _audit_records, _label_line, _modsec_class, _rotation_order, _site_key


def test_label_needs_all_filter_strings():
    rules = [("sqli", ["UNION", "GET"]), ("scan", ["nikto"])]
    assert _label_line('1.2.3.4 - - [x] "GET /?a=UNION" 200 1', rules) == "sqli"
    assert _label_line('1.2.3.4 - - [x] "POST /?a=UNION" 200 1', rules) == ""
    assert _label_line("ua nikto", rules) == "scan"


def test_rotation_oldest_first_live_last():
    names = ["d/a.access_log", "d/a.access_log.2025_04_22", "d/a.access_log.2025_04_20.01", "d/a.access_log.2025_04_20"]
    assert sorted(names, key=_rotation_order) == ["d/a.access_log.2025_04_20", "d/a.access_log.2025_04_20.01",
                                                  "d/a.access_log.2025_04_22", "d/a.access_log"]
    logs = ["x/web-access.log", "x/web-access.log.1", "x/web-access.log.3.gz", "x/web-access.log.2.gz"]
    assert sorted(logs, key=_rotation_order) == ["x/web-access.log.3.gz", "x/web-access.log.2.gz",
                                                 "x/web-access.log.1", "x/web-access.log"]


def test_site_key_groups_rotations():
    assert _site_key("h/s1/logs/s1.access_log.2025_04_20") == _site_key("h/s1/logs/s1.access_log")
    assert _site_key("x/apache2/web-access.log.2.gz") == _site_key("x/apache2/web-access.log")


def test_modsec_classes():
    assert [_modsec_class(x) for x in ["Normal", "SQLi", "XSS", "File Inclusion", "RCE", "Brute Force"]] == \
        ["normal", "sqli", "xss", "fileinclusion", "rce", "bruteforce"]
    assert _modsec_class("weird").startswith("other:")


def test_audit_record_sections():
    lines = ["--a1-A--", "[01/Aug/2025:10:00:00.1 +0000] id 1.1.1.1 1 2.2.2.2 443", "--a1-B--", "GET / HTTP/1.1",
             "--a1-F--", "HTTP/1.1 403 Forbidden", "--a1-H--", "Message: x", "--a1-Z--",
             "--a2-A--", "[01/Aug/2025:10:00:01 +0000] id 1.1.1.1 1 2.2.2.2 443", "--a2-B--", "POST /x HTTP/1.1", "--a2-Z--"]
    recs = list(_audit_records(lines))
    assert len(recs) == 2 and recs[0]["B"] == ["GET / HTTP/1.1"] and recs[1]["B"] == ["POST /x HTTP/1.1"]
