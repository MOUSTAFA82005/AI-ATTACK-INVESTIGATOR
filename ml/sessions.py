"""
Session layer: looks at what one client (IP) does over time.

Some attacks look normal one request at a time:
- brute force:    many failed logins (fast, slow, or one password on many accounts)
- ID enumeration: the same resource asked for with many different IDs
- scanning:       many probes for files/pages that should not be public

The per-request model cannot see these, so here we group requests per IP into
sessions and apply simple, explainable rules, then give every session a risk
score with the reasons behind it.

Thresholds were chosen on run3 (development data). Normal users in run3
include people who mistype their password once or twice, open a few product
IDs, and hit a missing page, so the thresholds sit above those.
"""
import re

import pandas as pd

from ml.features import value_features

SESSION_GAP = pd.Timedelta(minutes=30)   # a new session starts after 30 min of silence

LOGIN_PATH = re.compile(r"login|signin|sign-in|logon|auth|session|token", re.I)
MIN_FAILED_LOGINS = 3        # normal users in run3: at most 2 failures
MIN_LOGIN_POSTS = 6          # for sites that answer a failed login with 200/302
MIN_IDS_PER_RESOURCE = 15    # normal users in run3: at most 4; leaves room for heavy shoppers
MIN_PROBES = 3               # requests for files like /.env, /.git, *.bak
MIN_NOT_FOUND = 10           # 404 answers (sites that return 404 for missing pages)
MIN_SERVER_ERRORS = 3        # 5xx answers

_ID_SEGMENT = re.compile(r"/(\d+)(?=/|$)")


def _resource(path):
    """'/api/BasketItems/42?x=1' -> '/api/BasketItems/{id}' (None if no numeric ID)."""
    p = path.split("?", 1)[0]
    return _ID_SEGMENT.sub("/{id}", p) if _ID_SEGMENT.search(p) else None


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
    path0 = s["path"].str.split("?").str[0]
    is_login = (s["method"] == "POST") & path0.str.contains(LOGIN_PATH)
    failed = is_login & s["status"].isin([401, 403])
    login_ok = is_login & s["status"].between(200, 399)
    ok_after_fail = bool((login_ok & failed.cummax()).any())     # a success after the first failure
    res = s["path"].map(_resource)
    ids = s[res.notna()].groupby(res[res.notna()])["path"].nunique()
    probes = sum(_is_probe(m, p) for m, p in zip(s["method"], s["path"]))
    n_attacks = int(s["pred"].sum())

    stats = {
        "ip": s["ip"].iloc[0],
        "start": s["_t"].min(),
        "end": s["_t"].max(),
        "requests": len(s),
        "attack_requests": n_attacks,
        "failed_logins": int(failed.sum()),
        "login_posts": int(is_login.sum()),
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
    if stats["failed_logins"] >= MIN_FAILED_LOGINS or stats["login_posts"] >= MIN_LOGIN_POSTS:
        behaviours.append("bruteforce")
        score += 40
        reasons.append(f"{stats['failed_logins']} failed logins ({stats['login_posts']} login attempts)")
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
    sessions = pd.DataFrame([_one_session(s) | {"session": k} for k, s in d.groupby("session", sort=False)])

    # Mark the requests that make up each detected behaviour.
    flags = sessions.set_index("session")["behaviours"]
    path0 = d["path"].str.split("?").str[0]
    beh = d["session"].map(flags)
    is_login = (d["method"] == "POST") & path0.str.contains(LOGIN_PATH)
    in_enum = d["path"].map(_resource) == d["session"].map(sessions.set_index("session")["enumerated_resource"])
    # In a scan, the probes are plain GETs of a path (no query, no form): a
    # search or a login from the same IP is ordinary use and is not marked.
    scan_like = ((d["method"] == "GET") & ~d["path"].str.contains(r"\?", regex=True)) | (d["status"] == 404)
    d["session_attack"] = (
        (beh.map(lambda b: "bruteforce" in b) & is_login)
        | (beh.map(lambda b: "enumeration" in b) & in_enum)
        | (beh.map(lambda b: "scan" in b) & scan_like)
    ).astype(int)
    d = d.drop(columns="_t")
    return sessions.sort_values("risk_score", ascending=False, kind="stable").reset_index(drop=True), d
