"""
Session layer: looks at what one client (IP) does over time.

Some attacks look normal one request at a time:
- brute force:    many failed logins (fast, slow, or one password on many accounts)
- ID enumeration: the same resource asked for with many different IDs
- scanning:       many probes for files/pages that should not be public

The per-request model cannot see these, so here we group requests per IP into
sessions and apply simple, explainable rules, then give every session a risk
score with the reasons behind it.

Thresholds were chosen on run3 and run4 (development data). Normal users there
include people who mistype their password once or twice, open a few product
IDs, and hit a missing page, so the thresholds sit above those.

Sites differ in how a login and an ID look, so both are read in a general way
(checked on the DVWA dev run too):
- a login attempt is a POST to a login-like path, or any request that sends a
  password field (some sites log in with GET and always answer 200)
- an ID is a number in the path (/api/Users/42) or in a query parameter (?id=42)
"""
import json
import re
from urllib.parse import parse_qsl

import pandas as pd

from ml.features import value_features

SESSION_GAP = pd.Timedelta(minutes=30)   # a new session starts after 30 min of silence

LOGIN_PATH = re.compile(r"login|signin|sign-in|logon|auth|session|token", re.I)
MIN_FAILED_LOGINS = 3        # normal users in run3: at most 2 failures
MIN_LOGIN_ATTEMPTS = 4       # on one login form, for sites that answer a failed login with 200/302;
                             # normal users in run3/run4 (both sites): at most 3, so 4 is the
                             # lowest value that flags nobody normal. 5 missed the slow brute
                             # force on DVWA, which sends only 3 to 5 attempts.
MIN_IDS_PER_RESOURCE = 15    # normal users in run3: at most 4; leaves room for heavy shoppers
MIN_PROBES = 3               # requests for files like /.env, /.git, *.bak
MIN_NOT_FOUND = 10           # 404 answers (sites that return 404 for missing pages)
MIN_SERVER_ERRORS = 3        # 5xx answers

_ID_SEGMENT = re.compile(r"/(\d+)(?=/|$)")
_NUMBER = re.compile(r"\d+")
PASSWORD_FIELD = re.compile(r"pass|pwd", re.I)


def _id_of(path):
    """
    (resource, id) for a request that names an object by number, else (None, None).
    '/api/BasketItems/42'          -> ('/api/BasketItems/{id}', '42')
    '/vulnerabilities/sqli/?id=7'  -> ('/vulnerabilities/sqli/?id={id}', '7')
    """
    p, _, query = str(path or "").partition("?")
    ids = _ID_SEGMENT.findall(p)
    if ids:
        return _ID_SEGMENT.sub("/{id}", p), "/".join(ids)
    for name, value in parse_qsl(query, keep_blank_values=True):
        if _NUMBER.fullmatch(value):
            return f"{p}?{name}={{id}}", value
    return None, None


def _resource(path):
    return _id_of(path)[0]


def field_names(path, body=""):
    """Names of the fields a request sends, in the query string and in the body (form or JSON)."""
    query = str(path or "").partition("?")[2]
    names = [k for k, _ in parse_qsl(query, keep_blank_values=True)]
    b = str(body or "").strip()
    if b.startswith("{"):
        try:
            obj = json.loads(b)
            names += list(obj) if isinstance(obj, dict) else []
        except ValueError:
            pass
    elif "=" in b:
        names += [k for k, _ in parse_qsl(b, keep_blank_values=True)]
    return names


def is_login_attempt(method, path, body=""):
    path0 = str(path or "").split("?", 1)[0]
    if str(method).upper() == "POST" and LOGIN_PATH.search(path0):
        return True
    return any(PASSWORD_FIELD.search(n) for n in field_names(path, body))


def _is_probe(method, path):
    f = value_features(method, path, "")
    return bool(f["p_probe_path"] or f["p_probe_ext"])


def add_session_ids(df):
    """Add a `session` column: per IP, a new session after SESSION_GAP of silence."""
    d = df.copy()
    d["_t"] = pd.to_datetime(d["timestamp"], utc=True, errors="coerce")
    d = d.sort_values(["ip", "_t"], kind="stable")
    new = d.groupby("ip")["_t"].diff().gt(SESSION_GAP).astype(int)
    d["session"] = d["ip"] + "#" + new.groupby(d["ip"]).cumsum().astype(str)
    return d


def _one_session(s):
    is_login = s["_login"]
    per_form = s[is_login].groupby("_path0").size()
    failed = is_login & s["status"].isin([401, 403])
    login_ok = is_login & s["status"].between(200, 399)
    ok_after_fail = bool((login_ok & failed.cummax()).any())     # a success after the first failure
    has_id = s["_res"].notna()
    ids = s[has_id].groupby("_res")["_id"].nunique()
    probes = sum(_is_probe(m, p) for m, p in zip(s["method"], s["path"]))
    n_attacks = int(s["pred"].sum())

    stats = {
        "ip": s["ip"].iloc[0],
        "start": s["_t"].min(),
        "end": s["_t"].max(),
        "requests": len(s),
        "attack_requests": n_attacks,
        "failed_logins": int(failed.sum()),
        "login_attempts": int(per_form.max()) if len(per_form) else 0,
        "login_form": per_form.idxmax() if len(per_form) else "",
        "login_after_failures": ok_after_fail,
        "max_ids_one_resource": int(ids.max()) if len(ids) else 0,
        "enumerated_resource": ids.idxmax() if len(ids) else "",
        "probes": int(probes),
        "not_found": int((s["status"] == 404).sum()),
        "server_errors": int((s["status"] >= 500).sum()),
    }

    behaviours, reasons, score = [], [], 0
    if n_attacks:
        score += min(60, 15 * n_attacks)
        reasons.append(f"{n_attacks} requests carry an attack payload")
    if stats["failed_logins"] >= MIN_FAILED_LOGINS or stats["login_attempts"] >= MIN_LOGIN_ATTEMPTS:
        behaviours.append("bruteforce")
        score += 40
        reasons.append(f"{stats['failed_logins']} failed logins, {stats['login_attempts']} login attempts on {stats['login_form']}")
        if ok_after_fail:
            score += 30
            reasons.append("a login succeeded after the failures (possible compromised account)")
    if stats["max_ids_one_resource"] >= MIN_IDS_PER_RESOURCE:
        behaviours.append("enumeration")
        score += 40
        reasons.append(f"{stats['max_ids_one_resource']} different IDs of {stats['enumerated_resource']}")
    if stats["probes"] >= MIN_PROBES or stats["not_found"] >= MIN_NOT_FOUND:
        behaviours.append("scan")
        score += 30
        reasons.append(f"{stats['probes']} probes for hidden files, {stats['not_found']} not-found answers")
    if stats["server_errors"] >= MIN_SERVER_ERRORS and score:
        score += 10
        reasons.append(f"{stats['server_errors']} server errors")

    score = min(100, score)
    stats.update({
        "behaviours": behaviours,
        "risk_score": score,
        "risk_level": "high" if score >= 70 else "medium" if score >= 30 else "low" if score else "none",
        "reasons": reasons,
    })
    return stats


def analyze_sessions(df):
    """
    df: one row per request with columns ip, timestamp, method, path, status,
    and pred (1 if the per-request model called it an attack).
    Returns (sessions DataFrame sorted by risk, request-level DataFrame with a
    `session` column and `session_attack` = 1 for requests that belong to a
    detected behaviour).
    """
    d = add_session_ids(df)
    bodies = d["body"] if "body" in d else pd.Series("", index=d.index)
    d["_path0"] = d["path"].str.split("?").str[0]
    d["_login"] = [is_login_attempt(m, p, b) for m, p, b in zip(d["method"], d["path"], bodies)]
    id_info = d["path"].map(_id_of)
    d["_res"], d["_id"] = id_info.str[0], id_info.str[1]
    sessions = pd.DataFrame([_one_session(s) | {"session": k} for k, s in d.groupby("session", sort=False)])

    # Mark the requests that make up each detected behaviour.
    flags = sessions.set_index("session")["behaviours"]
    beh = d["session"].map(flags)
    # A brute force is the many attempts on one form, not the attacker's own login to the site.
    on_form = d["_login"] & (d["_path0"] == d["session"].map(sessions.set_index("session")["login_form"]))
    in_enum = d["_res"] == d["session"].map(sessions.set_index("session")["enumerated_resource"])
    # In a scan, the probes are plain GETs of a path (no query, no form): a
    # search or a login from the same IP is ordinary use and is not marked.
    scan_like = ((d["method"] == "GET") & ~d["path"].str.contains(r"\?", regex=True)) | (d["status"] == 404)
    marks = {
        "bruteforce": beh.map(lambda b: "bruteforce" in b) & on_form,
        "enumeration": beh.map(lambda b: "enumeration" in b) & in_enum,
        "scan": beh.map(lambda b: "scan" in b) & scan_like,
    }
    # `behaviour`: which detected behaviour each request is part of ("" if none).
    d["behaviour"] = ""
    for name in reversed(list(marks)):               # bruteforce wins over enumeration over scan
        d.loc[marks[name], "behaviour"] = name
    d["session_attack"] = (d["behaviour"] != "").astype(int)
    d = d.drop(columns=["_t", "_path0", "_login", "_res", "_id"])
    return sessions.sort_values("risk_score", ascending=False, kind="stable").reset_index(drop=True), d
