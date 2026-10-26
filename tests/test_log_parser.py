"""
Checks that the log parser reads every supported format the same way.

    python -m pytest tests/test_log_parser.py      (or: python tests/test_log_parser.py)

All sample lines are made up: documentation IPs, normal requests only.
"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from backend.app.log_parser import decode, parse_log, parse_log_detailed  # noqa: E402

SAMPLES = {
    "combined": (
        '203.0.113.7 - - [19/Oct/2026:20:02:21 +0000] "GET /rest/products/search?q=apple HTTP/1.1" '
        '200 1234 "http://shop.test/" "Mozilla/5.0 (X11; Linux x86_64)"\n'
        '203.0.113.7 - - [19/Oct/2026:20:02:22 +0000] "GET /api/Products/8 HTTP/1.1" '
        '200 512 "-" "Mozilla/5.0 (X11; Linux x86_64)"\n'
    ),
    "combined + body (our lab)": (
        '203.0.113.7 - - [19/Oct/2026:20:02:21 +0000] "POST /api/Feedbacks/ HTTP/1.1" 201 300 '
        '"" "Mozilla/5.0" "{\\"comment\\":\\"great shop\\",\\"rating\\":5}"\n'
    ),
    "nginx main (X-Forwarded-For at the end)": (
        '203.0.113.7 - - [19/Oct/2026:20:02:21 +0000] "GET /index.html HTTP/1.1" 200 612 '
        '"-" "curl/8.0" "198.51.100.1, 10.0.0.2"\n'
    ),
    "vhost": (
        'shop.test:443 203.0.113.7 - - [19/Oct/2026:20:02:21 +0000] "GET /about?lang=en HTTP/1.1" '
        '200 900 "-" "Mozilla/5.0"\n'
    ),
    "common": (
        '203.0.113.7 - frank [19/Oct/2026:20:02:21 +0000] "GET /docs/index.html?page=2 HTTP/1.0" 200 2326\n'
    ),
    "w3c (IIS)": (
        "#Software: Microsoft Internet Information Services 10.0\n"
        "#Version: 1.0\n"
        "#Date: 2026-10-19 20:02:21\n"
        "#Fields: date time s-ip cs-method cs-uri-stem cs-uri-query s-port cs-username c-ip "
        "cs(User-Agent) cs(Referer) sc-status sc-substatus sc-win32-status time-taken\n"
        "2026-10-19 20:02:21 192.0.2.10 GET /shop/search q=apple 443 - 203.0.113.7 "
        "Mozilla/5.0+(Windows+NT+10.0) - 200 0 0 15\n"
        "2026-10-19 20:02:22 192.0.2.10 POST /shop/login - 443 - 203.0.113.7 "
        "Mozilla/5.0+(Windows+NT+10.0) - 302 0 0 31\n"
    ),
    "alb (AWS)": (
        'https 2026-10-19T20:02:21.123456Z app/my-lb/50dc6c495c0c9188 203.0.113.7:2817 '
        '10.0.0.1:80 0.000 0.001 0.000 200 200 34 366 '
        '"GET https://shop.test:443/rest/products/search?q=apple HTTP/1.1" "Mozilla/5.0" '
        'ECDHE-RSA-AES128-GCM-SHA256 TLSv1.2 arn:aws:elasticloadbalancing:x "Root=1-58337262" '
        '"shop.test" "arn:aws:acm:x" 0 2026-10-19T20:02:21.000000Z "forward" "-" "-" '
        '"10.0.0.1:80" "200" "-" "-"\n'
    ),
    "json (nginx)": (
        '{"time_local":"19/Oct/2026:20:02:21 +0000","remote_addr":"203.0.113.7",'
        '"request":"GET /rest/products/search?q=apple HTTP/1.1","status":"200",'
        '"body_bytes_sent":"1234","http_user_agent":"Mozilla/5.0","request_body":"-"}\n'
    ),
    "json (gcp)": (
        '{"timestamp":"2026-10-19T20:02:21Z","httpRequest":{"requestMethod":"GET",'
        '"requestUrl":"https://shop.test/rest/products/search?q=apple","status":200,'
        '"remoteIp":"203.0.113.7","userAgent":"Mozilla/5.0"}}\n'
    ),
    "json (caddy)": (
        '{"ts":1792440141.5,"request":{"remote_ip":"203.0.113.7","method":"GET",'
        '"uri":"/rest/products/search?q=apple","headers":{"User-Agent":["Mozilla/5.0"]}},'
        '"status":200,"size":1234}\n'
    ),
}

EXPECTED_FORMAT = {
    "combined": "combined", "combined + body (our lab)": "combined",
    "nginx main (X-Forwarded-For at the end)": "combined", "vhost": "vhost",
    "common": "common", "w3c (IIS)": "w3c", "alb (AWS)": "alb",
    "json (nginx)": "json", "json (gcp)": "json", "json (caddy)": "json",
}


def test_every_format():
    for name, text in SAMPLES.items():
        rows, skipped, fmt = parse_log_detailed(text)
        assert fmt == EXPECTED_FORMAT[name], (name, fmt)
        assert skipped == 0 and rows, (name, skipped)
        r = rows[0]
        assert r["ip"] == "203.0.113.7", (name, r)
        assert r["method"] in ("GET", "POST") and r["path"].startswith("/"), (name, r)
        assert r["timestamp"].startswith("2026-10-19T20:02:2"), (name, r["timestamp"])
        assert r["status"] in (200, 201), (name, r)


def test_query_kept_and_full_url_stripped():
    for name in ("combined", "w3c (IIS)", "alb (AWS)", "json (nginx)", "json (gcp)", "json (caddy)"):
        rows, _ = parse_log(SAMPLES[name])
        assert rows[0]["path"] in ("/rest/products/search?q=apple", "/shop/search?q=apple"), (name, rows[0])


def test_body():
    rows, _ = parse_log(SAMPLES["combined + body (our lab)"])
    assert rows[0]["body"] == '{"comment":"great shop","rating":5}'
    rows, _ = parse_log(SAMPLES["nginx main (X-Forwarded-For at the end)"])
    assert rows[0]["body"] == ""          # X-Forwarded-For is not a body
    rows, _ = parse_log(SAMPLES["combined"])
    assert rows[0]["body"] == ""


def test_iis_user_agent_spaces():
    rows, _ = parse_log(SAMPLES["w3c (IIS)"])
    assert rows[0]["user_agent"] == "Mozilla/5.0 (Windows NT 10.0)"
    assert rows[1]["path"] == "/shop/login"


def test_unknown_format():
    rows, skipped, fmt = parse_log_detailed("hello world\nthis is not a log\n")
    assert fmt is None and rows == [] and skipped == 2


def test_bad_lines_are_skipped():
    text = SAMPLES["combined"] + "garbage line\n"
    rows, skipped, fmt = parse_log_detailed(text)
    assert fmt == "combined" and len(rows) == 2 and skipped == 1


def test_utf16_file():
    raw = SAMPLES["combined"].encode("utf-16")      # what PowerShell's ">" writes
    rows, _ = parse_log(decode(raw))
    assert len(rows) == 2


if __name__ == "__main__":
    for name, fn in list(globals().items()):
        if name.startswith("test_"):
            fn()
            print("ok ", name)
