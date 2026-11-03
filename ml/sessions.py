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
- a missing page is a 404, or a 200 that is the site's catch-all page (same
  answer size for many different paths), for sites that never answer 404

v5 (checked on a real shop log, zanbil): pictures, scripts and styles, and paging or
cache-busting numbers, are not object IDs; a scan needs its not-found answers to be at
least 10% of the session (crawlers meet dead links too); pages are compared by shape;
a session whose user agent is a search-engine crawler counts its page reading as low
risk (never hidden: the user agent can be faked, and its attack payloads still count).
"""
import json
import re
from urllib.parse import parse_qsl

import pandas as pd

from ml.features import value_features
from ml import graphql

SESSION_GAP = pd.Timedelta(minutes=30)   # a new session starts after 30 min of silence

LOGIN_PATH = re.compile(r"login|signin|sign-in|logon|auth|session|token", re.I)
MIN_FAILED_LOGINS = 3        # normal users in run3: at most 2 failures
MIN_LOGIN_ATTEMPTS = 4       # on one login form, for sites that answer a failed login with 200/302;
                             # normal users in run3/run4 (both sites): at most 3, so 4 is the
                             # lowest value that flags nobody normal. 5 missed the slow brute
                             # force on DVWA, which sends only 3 to 5 attempts.
CLEAR_LOGIN_ATTEMPTS = 6     # below this (4-5 attempts, no clear failures) a session looks like a
                             # user who mistyped a few times, so it stays medium risk: a warning
                             # for the investigator, not a verdict
MIN_IDS_PER_RESOURCE = 15    # normal users in run3: at most 4; leaves room for heavy shoppers
MIN_PROBES = 3               # requests for files like /.env, /.git, *.bak
MIN_NOT_FOUND = 10           # 404 answers (sites that return 404 for missing pages)
MIN_NOT_FOUND_SHARE = 0.10   # ... and at least this share of the session's requests: a crawler that
                             # reads thousands of real pages also meets some dead links (zanbil dev:
                             # search-engine bots at 1-7%); lab scanners are at 16% or more
MIN_SERVER_ERRORS = 3        # 5xx answers
MIN_COMMON_VISITS = 5        # a page opened this often by unflagged visitors is an ordinary page
CATCH_ALL_PATHS = 15         # a 200 answer of one size for this many different paths is the site's
                             # catch-all page ("not found" sent as 200, as single-page apps do);
                             # real pages of one size: at most 9 in the semicomplete log

_ID_SEGMENT = re.compile(r"/(\d+)(?=/|$)")
# Files the browser fetches by itself (pictures, scripts, styles, fonts). A shop page shows dozens
# of product pictures, so their numbers are not object IDs a visitor asks for.
_STATIC = re.compile(r"\.(jpe?g|png|gif|webp|svg|ico|bmp|css|js|map|woff2?|ttf|eot|mp4|webm|mp3)$"
                     r"|/(images?|img|thumbs?|thumbnails?|static|assets|media|fonts?|css|js)(/|$)", re.I)
# Query parameters whose number is not an object: paging, sorting and cache-busting.
_NOT_ID_PARAMS = {"_", "page", "p", "pg", "offset", "start", "limit", "size", "per_page", "perpage", "sort",
                  "order", "t", "ts", "v", "ver", "rnd", "rand", "cb"}
_NUMBER = re.compile(r"\d+")
PASSWORD_FIELD = re.compile(r"pass|pwd", re.I)
# Search-engine crawlers say who they are in the user agent. They read thousands of pages and
# meet dead links, which looks like enumeration and scanning. The user agent can be faked, so a
# crawler is never hidden: its reading counts as low risk, and any attack payload still counts.
CRAWLER_AGENT = re.compile(r"googlebot|bingbot|msnbot|yandex(?:bot|images)|baiduspider|duckduckbot|applebot"
                           r"|slurp|petalbot|seznambot|sogou", re.I)


def _id_of(path):
    """
    (resource, id) for a request that names an object by number, else (None, None).
    '/api/BasketItems/42'          -> ('/api/BasketItems/{id}', '42')
    '/vulnerabilities/sqli/?id=7'  -> ('/vulnerabilities/sqli/?id={id}', '7')
    """
    p, _, query = str(path or "").partition("?")
    if _STATIC.search(p):
        return None, None
    ids = _ID_SEGMENT.findall(p)
    if ids:
        return _ID_SEGMENT.sub("/{id}", p), "/".join(ids)
    for name, value in parse_qsl(query, keep_blank_values=True):
        if _NUMBER.fullmatch(value) and name.lower() not in _NOT_ID_PARAMS:
            return f"{p}?{name}={{id}}", value
    return None, None


def _shape(path):
    """Path without query, numbers -> {n}: /rest/basket/7 and /rest/basket/8 are one page."""
    return re.sub(r"\d+", "{n}", str(path or "").split("?", 1)[0])


def soft_not_found(d):
    """True for requests answered with the site's catch-all page: status 200 with a size
    that came back for >= CATCH_ALL_PATHS different pages, on a page that ordinary visitors
    (IPs with no model alarm) do not open often. Needs size; all False without it."""
    if "size" not in d:
        return pd.Series(False, index=d.index)
    size = pd.to_numeric(d["size"], errors="coerce").fillna(0)
    shape = d["path"].map(_shape)
    ok = (d["status"] == 200) & (size > 0)
    catch = set(shape[ok].groupby(size[ok]).nunique().loc[lambda n: n >= CATCH_ALL_PATHS].index)
    quiet_ip = ~d["pred"].astype(bool).groupby(d["ip"]).transform("any")
    seen = d[ok & quiet_ip].groupby(shape[ok & quiet_ip])["ip"].nunique()
    common = set(seen[seen >= MIN_COMMON_VISITS].index)
    return ok & size.isin(catch) & ~shape.isin(common)


def _resource(path):
    return _id_of(path)[0]


def field_names(path, body=""):
    """Names of the fields a request sends, in the query string and in the body (form or JSON)."""
    query = str(path or "").partition("?")[2]
    names = [k for k, _ in parse_qsl(query, keep_blank_values=True)]
    b = str(body or "").strip()
    gql = graphql.field_names(b)
    if gql is not None:                 # GraphQL: the query's argument names are its fields
        return names + gql
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


def _one_session(s, learned=None):
    is_login = s["_login"]
    per_form = s[is_login].groupby("_path0").size()
    failed = is_login & s["status"].isin([401, 403])
    login_ok = is_login & s["status"].between(200, 399)
    ok_after_fail = bool((login_ok & failed.cummax()).any())     # a success after the first failure
    has_id = s["_res"].notna()
    ids = s[has_id].groupby("_res")["_id"].nunique()
    probes = sum(_is_probe(m, p) for m, p in zip(s["method"], s["path"]))
    n_attacks = int(s["pred"].sum())
    agents = s["user_agent"] if "user_agent" in s else pd.Series("", index=s.index)
    crawler = bool(agents.fillna("").astype(str).str.contains(CRAWLER_AGENT).mean() > 0.5)

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
        "enumerated_resources": sorted(ids[ids >= MIN_IDS_PER_RESOURCE].index),
        "probes": int(probes),
        "not_found": int((s["status"] == 404).sum()),
        "soft_not_found": int(s["_soft404"].sum()),
        "server_errors": int((s["status"] >= 500).sum()),
        "crawler": crawler,
    }

    behaviours, reasons, score = [], [], 0
    if n_attacks:
        score += min(60, 15 * n_attacks)
        reasons.append(f"{n_attacks} requests carry an attack payload")
    rule_bf = stats["failed_logins"] >= MIN_FAILED_LOGINS or stats["login_attempts"] >= MIN_LOGIN_ATTEMPTS
    if learned is not None:          # the context model decided (ml/context_model.py)
        rule_bf = "bruteforce" in learned
    if rule_bf:
        behaviours.append("bruteforce")
        clear = (stats["failed_logins"] >= MIN_FAILED_LOGINS or stats["login_attempts"] >= CLEAR_LOGIN_ATTEMPTS
                 or learned is not None)
        score += 70 if clear else 40
        reasons.append(f"{stats['failed_logins']} failed logins, {stats['login_attempts']} login attempts on {stats['login_form']}"
                       + ("" if clear else " (possible slow brute force, or a user who mistyped)"))
        if ok_after_fail:
            score += 30
            reasons.append("a login succeeded after the failures (possible compromised account)")
    missing = stats["not_found"] + stats["soft_not_found"]
    enumerates = stats["max_ids_one_resource"] >= MIN_IDS_PER_RESOURCE
    scans = stats["probes"] >= MIN_PROBES or (missing >= MIN_NOT_FOUND and missing >= MIN_NOT_FOUND_SHARE * len(s))
    if learned is not None:
        enumerates, scans, crawler = "enumeration" in learned, "scan" in learned, False
    if crawler and (enumerates or scans):
        score = max(score, 10)          # shown as low risk; never raises a risk the payloads gave
        reasons.append(f"a search-engine crawler by its user agent (can be faked) reading many pages: "
                       f"{stats['max_ids_one_resource']} IDs of one resource, {missing} not-found answers")
    else:
        if enumerates:
            behaviours.append("enumeration")
            score += 40
            reasons.append(f"{stats['max_ids_one_resource']} different IDs of {stats['enumerated_resource']}")
        if scans:
            behaviours.append("scan")
            score += 30
            reasons.append(f"{stats['probes']} probes for hidden files, {missing} not-found answers"
                           + (f" ({stats['soft_not_found']} of them the site's catch-all page)" if stats["soft_not_found"] else ""))
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


def analyze_sessions(df, context_model=None):
    """
    context_model: the learned behaviour model (ml/context_model.py). With it, the model
    decides which requests are brute force / enumeration / scan and the thresholds above
    are not used; without it, the hand-written rules decide (kept as the baseline).

    df: one row per request with columns ip, timestamp, method, path, status,
    and pred (1 if the per-request model called it an attack).
    Returns (sessions DataFrame sorted by risk, request-level DataFrame with a
    `session` column and `session_attack` = 1 for requests that belong to a
    detected behaviour).
    """
    d = add_session_ids(df)
    bodies = d["body"] if "body" in d else pd.Series("", index=d.index)
    d["_path0"] = d["path"].str.split("?").str[0]
    d["_soft404"] = soft_not_found(d)
    d["_login"] = [is_login_attempt(m, p, b) for m, p, b in zip(d["method"], d["path"], bodies)]
    id_info = d["path"].map(_id_of)
    d["_res"], d["_id"] = id_info.str[0], id_info.str[1]
    learned = None
    if context_model is not None:
        from ml.context_model import context_features, predict_behaviours
        X, ordered = context_features(df.assign(proba=df["proba"] if "proba" in df else df["pred"].astype(float)))
        names, _ = predict_behaviours(context_model, X)
        d["_learned"] = pd.Series(names, index=ordered.index).reindex(d.index).values
        learned = d.groupby("session")["_learned"].agg(lambda b: set(b) - {""})
    sessions = pd.DataFrame([_one_session(s, None if learned is None else learned[k]) | {"session": k}
                             for k, s in d.groupby("session", sort=False)])

    # Mark the requests that make up each detected behaviour.
    flags = sessions.set_index("session")["behaviours"]
    beh = d["session"].map(flags)
    # A brute force is the many attempts on one form, not the attacker's own login to the site.
    on_form = d["_login"] & (d["_path0"] == d["session"].map(sessions.set_index("session")["login_form"]))
    enum_res = d["session"].map(sessions.set_index("session")["enumerated_resources"])
    in_enum = pd.Series([r in e for r, e in zip(d["_res"], enum_res)], index=d.index)   # every resource swept
    # In a scan, the probes are plain GETs of a path (no query, no form): a
    # search or a login from the same IP is ordinary use and is not marked.
    scan_like = ((d["method"] == "GET") & ~d["path"].str.contains(r"\?", regex=True)) | (d["status"] == 404) | d["_soft404"]
    # Pages that ordinary visitors of this site open too (sessions with no detected
    # behaviour) are not probes: an attacker loading the login page is not scanning it.
    quiet = d["session"].map(flags.map(len)) == 0
    # Pages are compared by shape (numbers -> {n}), so /filter/b12,b40 and /filter/b7 are one page.
    shape = d["path"].map(_shape)
    common = set(shape[quiet].value_counts().loc[lambda c: c >= MIN_COMMON_VISITS].index)
    scan_like &= ~shape.isin(common)
    marks = {
        "bruteforce": beh.map(lambda b: "bruteforce" in b) & on_form,
        "enumeration": beh.map(lambda b: "enumeration" in b) & in_enum,
        "scan": beh.map(lambda b: "scan" in b) & scan_like,
    }
    # `behaviour`: which detected behaviour each request is part of ("" if none).
    d["behaviour"] = ""
    if learned is not None:
        d["behaviour"] = d.pop("_learned")
    else:
        for name in reversed(list(marks)):           # bruteforce wins over enumeration over scan
            d.loc[marks[name], "behaviour"] = name
    d["session_attack"] = (d["behaviour"] != "").astype(int)
    d = d.drop(columns=["_t", "_path0", "_soft404", "_login", "_res", "_id"])
    return sessions.sort_values("risk_score", ascending=False, kind="stable").reset_index(drop=True), d
