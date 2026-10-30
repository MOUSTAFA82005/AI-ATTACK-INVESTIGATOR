"""
features.py - hand-built features for the AI Attack Investigator.

Two levels:
  1) request_features(): features of ONE request (used by the detection model)
  2) session_features(): features of ONE attacker (IP) over a time window
     (used for attack stage, brute force, and risk scoring)

These are the features YOU design from your knowledge of attacks. They are
combined with TF-IDF character n-grams (the automatic part) before training.
"""
import math
import re
from collections import Counter
from urllib.parse import urlsplit, parse_qsl, unquote

# ---------- keyword families (lowercase) ----------
SQL_WORDS = ["select", "union", "insert", "update", "delete", "drop", "sleep(",
             "benchmark(", "information_schema", "or 1=1", "' or ", "\" or ",
             "waitfor delay", "order by", "group by", "having", "load_file",
             "xp_cmdshell", "concat(", "char(", "0x"]
XSS_WORDS = ["<script", "</script", "javascript:", "onerror=", "onload=",
             "onclick=", "onmouseover=", "alert(", "prompt(", "confirm(",
             "document.cookie", "document.location", "<img", "<svg", "<iframe",
             "<body", "eval(", "fromcharcode"]
TRAVERSAL_WORDS = ["../", "..\\", "%2e%2e", "..%2f", "..%5c", "/etc/passwd",
                   "/etc/shadow", "boot.ini", "win.ini", "/proc/self",
                   "c:\\windows"]
CMD_WORDS = ["; ls", ";ls", "| cat", "|cat", "`", "$(", "/bin/sh", "/bin/bash",
             "cmd.exe", "wget ", "curl ", "nc -e", "&& ", "|| ", "whoami", "ping -c"]
SCANNER_AGENTS = ["sqlmap", "nikto", "nmap", "hydra", "dirbuster", "gobuster",
                  "wfuzz", "burp", "zap", "masscan", "acunetix"]
LOGIN_HINTS = ["login", "signin", "auth", "password", "admin"]
STATIC_EXT = (".css", ".js", ".png", ".jpg", ".jpeg", ".gif", ".ico", ".svg",
              ".woff", ".woff2", ".ttf", ".map")

SPECIAL_CHARS = {
    "quote1": "'", "quote2": '"', "lt": "<", "gt": ">", "semicolon": ";",
    "paren_open": "(", "paren_close": ")", "pipe": "|", "amp": "&",
    "backtick": "`", "brace_open": "{", "brace_close": "}", "backslash": "\\",
    "dollar": "$", "percent": "%", "equals": "=", "hash": "#", "star": "*",
}


def _count_any(text, words):
    return sum(text.count(w) for w in words)


def _entropy(s):
    if not s:
        return 0.0
    c = Counter(s)
    n = len(s)
    return -sum((v / n) * math.log2(v / n) for v in c.values())


def request_features(method, url, body="", user_agent=""):
    """Return a dict of numeric features for one HTTP request."""
    method = (method or "GET").upper()
    raw = url + " " + (body or "")
    decoded = unquote(unquote(raw)).lower()          # decode twice: catches %2527 tricks
    parts = urlsplit(url)
    path, query = parts.path, parts.query
    params = parse_qsl(query + ("&" + body if body else ""), keep_blank_values=True)
    values = [v for _, v in params]

    f = {}
    # --- length / structure ---
    f["url_len"] = len(url)
    f["path_len"] = len(path)
    f["query_len"] = len(query)
    f["body_len"] = len(body or "")
    f["num_params"] = len(params)
    f["max_param_len"] = max((len(v) for v in values), default=0)
    f["path_depth"] = path.count("/")
    f["num_dots_in_path"] = path.count(".")

    # --- method ---
    for m in ("GET", "POST", "PUT", "DELETE"):
        f["method_" + m.lower()] = int(method == m)
    f["method_other"] = int(method not in ("GET", "POST", "PUT", "DELETE"))

    # --- special characters (counted on the decoded text) ---
    for name, ch in SPECIAL_CHARS.items():
        f["chr_" + name] = decoded.count(ch)
    f["sql_comment"] = decoded.count("--") + decoded.count("/*") + decoded.count("*/")
    n = max(len(decoded), 1)
    f["special_ratio"] = sum(not (c.isalnum() or c in "/._-") for c in decoded) / n
    f["digit_ratio"] = sum(c.isdigit() for c in decoded) / n
    f["upper_ratio"] = sum(c.isupper() for c in unquote(raw)) / n
    f["entropy"] = _entropy(decoded)

    # --- encoding tricks ---
    f["pct_encoded"] = raw.count("%")
    f["double_encoded"] = int("%25" in raw)
    f["null_byte"] = int("%00" in raw or "\x00" in raw)
    f["non_ascii"] = sum(ord(c) > 127 for c in raw)

    # --- suspicious keywords per attack family ---
    f["kw_sql"] = _count_any(decoded, SQL_WORDS)
    f["kw_xss"] = _count_any(decoded, XSS_WORDS)
    f["kw_traversal"] = _count_any(decoded, TRAVERSAL_WORDS)
    f["kw_cmd"] = _count_any(decoded, CMD_WORDS)
    f["tautology"] = int(bool(re.search(r"(\d+)\s*=\s*\1|'[^']*'\s*=\s*'[^']*'", decoded)))
    f["kw_total"] = f["kw_sql"] + f["kw_xss"] + f["kw_traversal"] + f["kw_cmd"]

    # --- target and client hints ---
    f["is_login_path"] = int(any(h in path.lower() for h in LOGIN_HINTS))
    f["is_static"] = int(path.lower().endswith(STATIC_EXT))
    f["scanner_agent"] = int(any(a in (user_agent or "").lower() for a in SCANNER_AGENTS))
    return f


def session_features(df, window="1min"):
    """
    One row per (ip, time window) from a parsed log DataFrame with columns:
      ip, time (datetime), url, status (int), size (int), kw_total (from
      request_features) and is_login_path.
    Used for brute force, attack stage, and the risk score.
    """
    import pandas as pd
    d = df.copy()
    d["window"] = d["time"].dt.floor(window)
    g = d.groupby(["ip", "window"])
    out = pd.DataFrame({
        "req_count": g.size(),
        "distinct_urls": g["url"].nunique(),
        "error_rate_4xx": g["status"].apply(lambda s: (s.between(400, 499)).mean()),
        "error_rate_5xx": g["status"].apply(lambda s: (s >= 500).mean()),
        "login_attempts": g["is_login_path"].sum(),
        "login_401_403": g.apply(lambda x: ((x["is_login_path"] == 1) & x["status"].isin([401, 403])).sum()),
        "login_success_after_fail": g.apply(
            lambda x: int((x["is_login_path"] == 1).any() and (x["status"] == 200).any()
                          and x["status"].isin([401, 403]).any())),
        "avg_size": g["size"].mean(),
        "max_size": g["size"].max(),
        "suspicious_requests": g["kw_total"].apply(lambda s: (s > 0).sum()),
    }).reset_index()
    return out


if __name__ == "__main__":
    tests = [
        ("GET", "/rest/products/search?q=apple"),
        ("GET", "/rest/products/search?q=')) OR 1=1--"),
        ("GET", "/#/search?q=<script>alert(1)</script>"),
        ("GET", "/ftp/../../etc/passwd"),
    ]
    for m, u in tests:
        f = request_features(m, u)
        keep = {k: f[k] for k in ("url_len", "num_params", "chr_quote1", "chr_lt",
                                  "sql_comment", "kw_sql", "kw_xss", "kw_traversal", "tautology")}
        print(u, "->", keep)



# =====================================================================
# Site-independent features (value_features)
# ---------------------------------------------------------------------
# request_features() looks at the whole request, so it also learns the
# SHAPE of one site (path names, methods, JSON brackets). A model trained
# on CSIC with it calls almost every normal Juice Shop request an attack.
#
# value_features() looks only at what the user typed: the values of URL
# parameters, the values inside a form or JSON body, and the path itself
# for traversal. Path names, parameter names, JSON brackets and the HTTP
# method are ignored, because they change from site to site.
# =====================================================================
import json as _json
from urllib.parse import unquote_plus as _unquote_plus

_SQL_RE = [
    r"\bunion\b[\s\S]{0,40}\bselect\b", r"\bselect\b[\s\S]{0,80}\bfrom\b",
    r"\binsert\b\s+\binto\b", r"\bdrop\b\s+\btable\b", r"\bupdate\b\s+\w+\s+\bset\b",
    r"\bdelete\b\s+\bfrom\b", r"['\"]\s*\b(or|and)\b", r"\b(or|and)\b\s+[\w'\"]+\s*=\s*[\w'\"]+",
    r"\bsleep\s*\(", r"\bbenchmark\s*\(", r"\bwaitfor\b\s+\bdelay\b",
    r"information_schema", r"\bload_file\b", r"xp_cmdshell", r"\bconcat\s*\(",
    r"\bchar\s*\(", r"\border\s+by\s+\d", r";\s*(select|drop|insert|update|delete|shutdown)\b",
    r"(--|#)\s*$", r"/\*.*?\*/",
]
_XSS_RE = [
    r"<\s*script", r"<\s*/\s*script", r"javascript\s*:", r"\bon\w+\s*=",
    r"<\s*(img|svg|iframe|body|object|embed|a|div|input|style|link|meta)\b",
    r"\b(alert|prompt|confirm|eval)\s*\(", r"document\.(cookie|location|write)",
    r"fromcharcode", r"<\s*!--#",                      # last one: SSI
]
_TRAV_RE = [r"\.\./", r"\.\.\\", r"/etc/(passwd|shadow|hosts)", r"boot\.ini",
            r"win\.ini", r"/proc/self", r"c:\\windows"]
_CMD_RE = [r"[;|&`\n]\s*(ls|cat|id|whoami|uname|wget|curl|nc|ping|rm|echo|ifconfig|ipconfig|"
           r"netstat|nslookup|hostname|systeminfo|sleep\s+\d+)\b",
           r"\$\(", r"`[^`]+`", r"/bin/(sh|bash)", r"cmd\.exe", r"\|\|", r"&&"]
_CRLF_RE = [r"[\r\n]", r"%0d|%0a"]
# paths that scanners look for (backup copies, config, admin tools)
_PROBE_EXT = (".bak", ".old", ".inc", ".orig", ".swp", ".save", ".tmp", ".java",
              ".config", ".conf", ".ini", ".log", ".sql", ".tar", ".gz", ".zip", "~")
_PROBE_PATHS = ["/.git", "/.env", "/.svn", "/.htaccess", "/.htpasswd", "/_vti_",
                "/wp-admin", "/wp-login", "/phpmyadmin", "/cgi-bin", "/server-status",
                "/web.config", "/admin.php", "/etc/"]
# a web shell: /shell.php, /shell.jsp, ... or /shell at the site root, not a blog page about shells
_SHELL_RE = re.compile(r"/shell\.(php\d?|aspx?|jspx?|cgi|pl|py|sh)\b|^/shell/?(\?|$)")
_ALL_RE = {"sql": _SQL_RE, "xss": _XSS_RE, "trav": _TRAV_RE, "cmd": _CMD_RE}
_COMPILED = {k: [re.compile(p, re.I) for p in v] for k, v in _ALL_RE.items()}

_B64 = re.compile(r"[A-Za-z0-9+/_-]{4,}={1,2}")


def _dec(s):
    """Decode up to 3 times (catches double encoding like %2527)."""
    s = str(s or "")
    for _ in range(3):
        d = _unquote_plus(s, encoding="latin-1")
        if d == s:
            break
        s = d
    return s


def _json_leaves(obj, out):
    if isinstance(obj, dict):
        for v in obj.values():
            _json_leaves(v, out)
    elif isinstance(obj, list):
        for v in obj:
            _json_leaves(v, out)
    elif isinstance(obj, str):
        out.append(obj)
    # numbers / bools / null are not user text: skip


def user_values(url, body=""):
    """Everything the user typed: URL parameter values and body values."""
    url = str(url or "")
    body = str(body or "")
    query = url.split("?", 1)[1] if "?" in url else ""
    vals = [v for _, v in parse_qsl(query, keep_blank_values=True)] if query else []
    if "=" in query and not vals:
        vals = [query]
    b = body.strip()
    if b:
        try:
            leaves = []
            _json_leaves(_json.loads(b), leaves)
            vals += leaves
        except ValueError:
            if "=" in b:
                vals += [v for _, v in parse_qsl(b, keep_blank_values=True)]
            else:
                vals.append(b)
    vals = [_dec(v) for v in vals if v != ""]
    # base64 tokens end in "=" / "==": drop that padding so it doesn't look like "a=b"
    return [v.rstrip("=") if _B64.fullmatch(v) else v for v in vals]


# A quote next to SQL syntax ("' or 1=1", "')--", "admin'#"), not one in prose ("O'Brien").
_CTX_QUOTE = [re.compile(p) for p in (
    r"['\"]\s*(\)|;|--|#|/\*|=|\+|\|\||\b(or|and|xor|union|select|order|group|having|like)\b)",
    r"(=|\(|,)\s*['\"]",
)]
_PROSE_PUNCT = ".,@_-:/'!?;()%&$#=+\"*"
_TAUTOLOGY = re.compile(r"(?:\b(?:or|and|xor|where|having)\b|['\")]|\|\||&&)\s*"
                        r"\(*\s*(?:(\d+)\s*=\s*\1\b|'([^']*)'\s*=\s*'\2)")


def value_features(method, url, body="", user_agent=""):
    """Site-independent numeric features for one request (see note above)."""
    url = str(url or "")
    path = _dec(url.split("?", 1)[0])
    vals = user_values(url, body)
    text = "\n".join(vals)
    low = text.lower()
    raw = url + " " + str(body or "")

    f = {}
    f["v_count"] = len(vals)
    f["v_max_len"] = max((len(v) for v in vals), default=0)
    f["v_log_total_len"] = math.log1p(len(text))
    # Special characters count only where they act like code: a single
    # apostrophe or ";" is normal in human text ("Can't wait; thanks!").
    f["v_ctx_quote"] = sum(len(p.findall(low)) for p in _CTX_QUOTE)
    f["v_ctx_tag"] = len(re.findall(r"<\s*[a-z!/?]", low))
    f["v_ctx_attr_break"] = len(re.findall(r"['\"]\s*>", low))
    f["v_ctx_call"] = len(re.findall(r"[a-z_]\(", low))
    f["v_ctx_shell"] = len(re.findall(r"`|\$\(|\$\{|\|", text))
    f["v_chr_backslash"] = text.count("\\")
    f["v_chr_brace"] = text.count("{") + text.count("}")
    f["v_sql_comment"] = text.count("--") + text.count("/*")
    f["v_max_special_ratio"] = max(
        (sum(not (c.isalnum() or c.isspace() or c in _PROSE_PUNCT) for c in v) / max(len(v), 1)
         for v in vals), default=0.0)
    for fam, pats in _COMPILED.items():
        f["v_kw_" + fam] = sum(len(p.findall(low)) for p in pats)
    # "1=1" counts only right after SQL syntax ("' OR 1=1", "where 1=1"), not in prose ("1=1 deal")
    f["v_tautology"] = int(bool(_TAUTOLOGY.search(low)))
    f["v_crlf"] = int(any(re.search(p, v, re.I) for p in _CRLF_RE for v in vals + [raw]))
    # path: only traversal / injected markup, never the path words themselves
    f["p_kw_trav"] = sum(len(p.findall(path.lower())) for p in _COMPILED["trav"])
    f["p_bad_chars"] = sum(path.count(c) for c in "<>'\"`;|$")
    f["p_kw_xss"] = sum(len(p.findall(path.lower())) for p in _COMPILED["xss"])
    lp = path.lower().rstrip("/")
    f["p_probe_ext"] = int(any(lp.endswith(e) or (e + "/") in lp + "/" for e in _PROBE_EXT if e != ".log"))
    f["p_probe_path"] = int(any(x in lp for x in _PROBE_PATHS) or bool(_SHELL_RE.search(lp)))
    # encoding tricks anywhere in the raw request
    f["double_encoded"] = int(bool(re.search(r"%25[0-9a-f]{2}", raw, re.I)))
    f["null_byte"] = int("%00" in raw or "\x00" in raw)
    f["v_kw_total"] = (f["v_kw_sql"] + f["v_kw_xss"] + f["v_kw_trav"] + f["v_kw_cmd"]
                       + f["p_kw_trav"] + f["p_kw_xss"] + f["p_probe_ext"] + f["p_probe_path"])
    f["scanner_agent"] = int(any(a in (user_agent or "").lower() for a in SCANNER_AGENTS))
    return f
