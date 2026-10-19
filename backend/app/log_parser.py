"""
Access-log parser that detects the log format by itself.

Supported formats:
- combined:  Nginx/Apache "combined", with optional extra quoted fields at the
             end (our lab adds the request body; Nginx's default "main" format
             adds X-Forwarded-For instead).
- vhost:     Apache "vhost_combined" (host:port before the client IP).
- common:    Nginx/Apache "common" (no referer / user agent).
- w3c:       IIS and other W3C extended logs (the "#Fields:" header names the columns).
- alb:       AWS Application / Classic Load Balancer access logs.
- json:      one JSON object per line (Nginx/Caddy/Traefik JSON logs, GCP httpRequest, ...).

Every parsed row has the same keys: ip, time (as written in the log),
timestamp (ISO 8601, or "" if the time could not be read), method, path
(path + query string), status, size, user_agent, body ("" when the log has none).
"""
import ipaddress
import json
import re
from datetime import datetime, timezone
from urllib.parse import urlsplit

_Q = r'"(?P<{}>(?:[^"\\]|\\.)*)"'          # a quoted field that may contain \"

_COMBINED = re.compile(
    r'(?P<ip>\S+) \S+ (?P<user>\S+) \[(?P<time>[^\]]+)\] '
    + _Q.format("request") + r' (?P<status>\d{3}) (?P<size>\S+) '
    + _Q.format("referer") + " " + _Q.format("agent")
    + r'(?P<extra>(?: "(?:[^"\\]|\\.)*")*)\s*$'
)
_VHOST = re.compile(r"(?P<vhost>\S+:\d+) (?P<rest>.*)$")
_COMMON = re.compile(
    r'(?P<ip>\S+) \S+ (?P<user>\S+) \[(?P<time>[^\]]+)\] '
    + _Q.format("request") + r' (?P<status>\d{3}) (?P<size>\S+)\s*$'
)
_ALB = re.compile(
    r'(?:(?:http|https|h2|grpcs|ws|wss) )?(?P<time>\d{4}-\d\d-\d\dT\S+) \S+ '
    r'(?P<ip>[^\s:]+|\[[^\]]+\]):\d+ \S+ \S+ \S+ \S+ (?P<status>\d{3}|-) \S+ \S+ (?P<size>\d+) '
    + _Q.format("request") + " " + _Q.format("agent")
)
_EXTRA_FIELD = re.compile(r'"((?:[^"\\]|\\.)*)"')


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


def _is_ip_list(s):
    """True for X-Forwarded-For style values such as "1.2.3.4, 10.0.0.1"."""
    try:
        return all(ipaddress.ip_address(p.strip()) for p in s.split(","))
    except ValueError:
        return False


def _to_path(target):
    """Keep only path + query, also when the log wrote a full URL."""
    if target.startswith(("http://", "https://")):
        u = urlsplit(target)
        return (u.path or "/") + (f"?{u.query}" if u.query else "")
    return target


def _split_request(request):
    parts = request.split(" ")
    method = parts[0] if parts else ""
    target = parts[1] if len(parts) > 1 else ""
    return method, _to_path(target)


def _iso(time_str, fmt=None):
    try:
        if fmt:
            t = datetime.strptime(time_str, fmt)
        else:
            t = datetime.fromisoformat(time_str.replace("Z", "+00:00"))
        if t.tzinfo is None:
            t = t.replace(tzinfo=timezone.utc)
        return t.isoformat()
    except (ValueError, TypeError):
        return ""


def _int(s):
    try:
        return int(s)
    except (ValueError, TypeError):
        return 0


def _row(ip, time, timestamp, method, path, status, size, agent, body):
    return {"ip": ip, "time": time, "timestamp": timestamp, "method": method,
            "path": path, "status": _int(status), "size": _int(size),
            "user_agent": agent, "body": body}


# ---------- one parser per format: line -> row or None ----------

def _parse_combined(line):
    m = _COMBINED.match(line)
    if not m:
        return None
    method, path = _split_request(_unescape(m["request"]))
    body = ""
    extras = [_unescape(x) for x in _EXTRA_FIELD.findall(m["extra"])]
    # Our lab writes the body as the first extra field. Nginx's default format
    # writes X-Forwarded-For there instead, which is never a request body.
    if extras and not _is_ip_list(extras[0]):
        body = extras[0]
    return _row(m["ip"], m["time"], _iso(m["time"], "%d/%b/%Y:%H:%M:%S %z"), method, path,
                m["status"], m["size"], _unescape(m["agent"]), body)


def _parse_vhost(line):
    m = _VHOST.match(line)
    return _parse_combined(m["rest"]) if m else None


def _parse_common(line):
    m = _COMMON.match(line)
    if not m:
        return None
    method, path = _split_request(_unescape(m["request"]))
    return _row(m["ip"], m["time"], _iso(m["time"], "%d/%b/%Y:%H:%M:%S %z"), method, path,
                m["status"], m["size"], "", "")


def _parse_alb(line):
    m = _ALB.match(line)
    if not m:
        return None
    method, path = _split_request(m["request"])
    return _row(m["ip"].strip("[]"), m["time"], _iso(m["time"]), method, path,
                m["status"], m["size"], m["agent"], "")


# JSON logs name the same thing in many ways; first key found wins.
_JSON_KEYS = {
    "ip": ["remote_addr", "client_ip", "clientip", "client.ip", "ClientHost", "remote_ip", "ip",
           "src_ip", "httpRequest.remoteIp", "request.remote_ip", "c-ip"],
    "time": ["time_local", "time_iso8601", "@timestamp", "timestamp", "time", "ts", "StartUTC",
             "datetime", "date"],
    "method": ["request_method", "method", "http_method", "httpRequest.requestMethod",
               "request.method", "RequestMethod", "cs-method"],
    "uri": ["request_uri", "uri", "url", "path", "httpRequest.requestUrl", "request.uri",
            "RequestPath", "cs-uri-stem"],
    "query": ["query_string", "args", "query", "cs-uri-query"],
    "request": ["request"],
    "status": ["status", "status_code", "response_code", "httpRequest.status", "DownstreamStatus",
               "sc-status"],
    "size": ["body_bytes_sent", "bytes_sent", "size", "httpRequest.responseSize", "size_bytes",
             "DownstreamContentSize", "sc-bytes"],
    "agent": ["http_user_agent", "user_agent", "userAgent", "httpRequest.userAgent",
              "request.headers.User-Agent", "request_User-Agent", "cs(User-Agent)"],
    "body": ["request_body", "body", "request.body"],
}


def _flatten(d, prefix=""):
    out = {}
    for k, v in d.items():
        key = f"{prefix}{k}"
        if isinstance(v, dict):
            out.update(_flatten(v, key + "."))
        elif isinstance(v, list) and v and all(isinstance(x, str) for x in v):
            out[key] = v[0]           # e.g. Caddy: headers are lists
        else:
            out[key] = v
    return out


def _parse_json(line):
    if not line.startswith("{"):
        return None
    try:
        d = json.loads(line)
    except ValueError:
        return None
    if not isinstance(d, dict):
        return None
    f = _flatten(d)

    def get(name):
        for k in _JSON_KEYS[name]:
            v = f.get(k)
            if v not in (None, "", "-"):
                return str(v)
        return ""

    method, uri = get("method"), get("uri")
    if (not method or not uri) and get("request"):
        method, uri = _split_request(get("request"))
    if not method and not uri:
        return None
    path = _to_path(uri)
    query = get("query").lstrip("?")
    if query and "?" not in path:
        path += "?" + query
    t = get("time")
    ts = _iso(t, "%d/%b/%Y:%H:%M:%S %z") or _iso(t)
    if not ts and re.fullmatch(r"\d{9,10}(\.\d+)?", t):        # Unix seconds
        ts = datetime.fromtimestamp(float(t), timezone.utc).isoformat()
    return _row(get("ip"), t, ts, method, path, get("status"), get("size"), get("agent"),
                get("body"))


class _W3C:
    """IIS / W3C extended format. The '#Fields:' header line names the columns."""

    def __init__(self):
        self.fields = None

    def header(self, line):
        if line.startswith("#Fields:"):
            self.fields = line[len("#Fields:"):].split()
        return line.startswith("#")

    def parse(self, line):
        if not self.fields:
            return None
        values = line.split("\t") if "\t" in line else line.split(" ")
        if len(values) != len(self.fields):
            return None
        f = dict(zip(self.fields, values))
        method, stem = f.get("cs-method", ""), f.get("cs-uri-stem", "")
        if not method or not stem:
            return None
        query = f.get("cs-uri-query", "-")
        path = stem + (f"?{query}" if query not in ("-", "") else "")
        agent = f.get("cs(User-Agent)", "-")
        agent = "" if agent == "-" else agent.replace("+", " ")
        t = f"{f.get('date', '')} {f.get('time', '')}".strip()
        return _row(f.get("c-ip", ""), t, _iso(t, "%Y-%m-%d %H:%M:%S"), method, path,
                    f.get("sc-status"), f.get("sc-bytes"), agent, "")


_LINE_PARSERS = {
    "combined": _parse_combined,
    "vhost": _parse_vhost,
    "common": _parse_common,
    "alb": _parse_alb,
    "json": _parse_json,
}
FORMATS = list(_LINE_PARSERS) + ["w3c"]


def decode(raw):
    """Bytes -> text. Handles UTF-8 (with or without BOM) and UTF-16 (e.g. from PowerShell)."""
    if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        return raw.decode("utf-16", errors="replace")
    return raw.decode("utf-8-sig", errors="replace")


def detect_format(lines, sample=200):
    """Pick the format that parses the most of the first `sample` lines."""
    if any(l.startswith("#Fields:") for l in lines[:50]):
        return "w3c"
    sample_lines = [l for l in lines if l.strip() and not l.startswith("#")][:sample]
    best, best_hits = None, 0
    for name, fn in _LINE_PARSERS.items():
        hits = sum(fn(l.strip()) is not None for l in sample_lines)
        if hits > best_hits:
            best, best_hits = name, hits
    return best


def parse_log_detailed(text):
    """Return (rows, skipped lines, format name or None if no format matched)."""
    lines = text.splitlines()
    fmt = detect_format(lines)
    rows, skipped = [], 0
    if fmt is None:
        return rows, sum(bool(l.strip()) for l in lines), None
    w3c = _W3C() if fmt == "w3c" else None
    for line in lines:
        line = line.strip()
        if not line:
            continue
        if w3c is not None:
            if w3c.header(line):
                continue
            row = w3c.parse(line)
        else:
            row = _LINE_PARSERS[fmt](line)
        if row is None:
            skipped += 1
        else:
            rows.append(row)
    return rows, skipped, fmt


def parse_log(text):
    """Return (parsed rows, number of skipped lines)."""
    rows, skipped, _ = parse_log_detailed(text)
    return rows, skipped
