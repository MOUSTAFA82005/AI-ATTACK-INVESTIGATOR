"""
Minimal access-log parser for the backend.

Reads the Nginx/Apache "combined" format, plus the optional extra field our lab
adds at the end with the request body. Lines that don't match are skipped.

Temporary: replace with the lab parser when it is ready.
"""
import json
import re

LINE = re.compile(
    r'(?P<ip>\S+) \S+ (?P<user>\S*) \[(?P<time>[^\]]+)\] '
    r'"(?P<request>(?:[^"\\]|\\.)*)" (?P<status>\d{3}) (?P<size>\S+) '
    r'"(?P<referer>(?:[^"\\]|\\.)*)" "(?P<agent>(?:[^"\\]|\\.)*)"'
    r'(?: "(?P<body>(?:[^"\\]|\\.)*)")?\s*$'
)


def _unescape(s):
    """Undo Nginx escaping (escape=json gives \\" and \\uXXXX; default gives \\xXX)."""
    if not s or s == "-":
        return ""
    if "\\x" in s:
        s = re.sub(r"\\x([0-9A-Fa-f]{2})", lambda m: chr(int(m.group(1), 16)), s)
    try:
        return json.loads(f'"{s}"')
    except ValueError:
        return s


def parse_line(line):
    m = LINE.match(line.strip())
    if not m:
        return None
    parts = _unescape(m["request"]).split(" ")
    method = parts[0] if parts else ""
    path = parts[1] if len(parts) > 1 else ""
    return {
        "ip": m["ip"],
        "time": m["time"],
        "method": method,
        "path": path,
        "status": int(m["status"]),
        "size": 0 if m["size"] == "-" else int(m["size"]),
        "user_agent": _unescape(m["agent"]),
        "body": _unescape(m["body"]),
    }


def parse_log(text):
    """Return (parsed rows, number of skipped lines)."""
    rows, skipped = [], 0
    for line in text.splitlines():
        if not line.strip():
            continue
        row = parse_line(line)
        if row is None:
            skipped += 1
        else:
            rows.append(row)
    return rows, skipped
