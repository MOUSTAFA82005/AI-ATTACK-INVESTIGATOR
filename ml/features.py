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

