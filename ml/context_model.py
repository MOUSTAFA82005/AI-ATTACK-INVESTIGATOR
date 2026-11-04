"""
Context model: a learned classifier for the attacks that live in behaviour rather than
in one request (brute force, ID enumeration, scanning). It replaces the hand-written
session rules (ml/sessions.py thresholds), which stay only as a baseline.

Each request is described by itself (is it a password form, does it carry an ID, how
popular its page is in this log, what answer it got) and by its session around it (how
many attempts on the same form, how many different IDs of the same resource, how many
different pages got the same answer, ...). A gradient-boosted model learns from data
which combinations are an attack. Nothing below is a threshold: the features only
describe; the model decides.

Every feature is relative or a count that means the same on any site (page popularity
is scaled by the log's number of visitors, an "answer" is status + rough size, so a
404 page and a catch-all 200 page look alike), so the model is not tied to one site.

Training data (ml/train_context.py): labelled lab runs of two sites, real traffic of a
real shop as normal, and real tools (nikto, ffuf, hydra) laid over normal visitors.
"""
import re

import joblib
import numpy as np
import pandas as pd

from ml import graphql
from ml.sessions import LOGIN_PATH, _STATIC, _id_of, _shape, add_session_ids, field_names

MODEL_PATH = "models/context.joblib"
BEHAVIOURS = ["normal", "bruteforce", "enumeration", "scan"]
LABEL_OF = {"bruteforce": "bruteforce", "enum": "enumeration", "scan": "scan"}
PASSWORD = re.compile(r"pass|pwd", re.I)

# A permanent redirect or a "not modified" says the page exists: it is that page's own
# answer, never the one not-found answer a scanner gets for everything it tries.
UNIQUE_ANSWER_STATUSES = [301, 304]
# For a login attempt, how many other pages share its answer says nothing about it.
APL_LOGIN_ZERO = True
SHARED_BY = 3          # a request sent by this many visitors or more is navigation, not input
NO_SIZE_SHARE = 0.9    # v10: this share of 2xx answers with no size = the log does not record sizes
MIN_SIZED_ANSWERS = 50
FEATURES = [
    # the request itself
    "password_field", "payload_score", "page_popularity", "answer_pages_log",
    # the request inside its session
    "same_page_in_session", "ids_this_resource", "attempts_this_form", "form_same_answer",
    "form_values",
    # the request against the other visitors of the same page or form (v9)
    "ids_vs_typical", "values_vs_typical",
    # the session
    "s_requests", "s_pages", "s_max_ids",
    "s_unpopular_share", "s_mean_popularity", "s_top_answer_share",
]
# Left out on purpose (computed below, not given to the model):
# - size_vs_page: how one site sizes its pages. With five lab sites, leaving one site out
#   showed the model learning each site's habits from it (with it and the raw
#   answer_pages_log, brute force on Juice Shop was 0.2-0.3 caught; 1.0 without).
# - the session's payload
# count/share and its largest login count. In the lab every enumerator logs in first and
# most scanners also send payloads, so with them the model learned "no login, no payload
# = not an attack", which is the generator talking, not the attack.


_NAMED_ID = re.compile(r"/([A-Za-z][A-Za-z_-]{1,30}?)(\d+)$")     # last segment only: not /v1/


def _object_id(path, body=""):
    """(resource, id) of the object a request names: a number in the path or query
    (/api/orders/42, ?id=7), a name ending in a number (/books/v1/bookTitle42), or a
    numeric ID argument of a GraphQL query (paste(id: 7)); else (None, None)."""
    res, rid = _id_of(path)
    if rid is not None:
        return res, rid
    gql = graphql.object_ids(body)
    if gql:
        return str(path).split("?")[0] + "#" + gql[0][0], gql[0][1]
    p = str(path or "").split("?")[0]
    m = _NAMED_ID.search(p)
    if m and not _STATIC.search(p):
        return p[:m.start()] + "/" + m.group(1) + "{id}" + p[m.end():], m.group(2)
    return None, None


_PAGE_VALUE = r"^[\w./-]*\.(?:php\d?|html?|aspx?|jspx?|cgi|do)$"
# A value no person types: a long mix of letters and digits that is different every time
# (a CSRF token, a nonce). Left out of "what this visitor sent", or every login with a
# fresh token would look like a new value.
_TOKEN = re.compile(r"^(?=.*\d)(?=.*[A-Za-z])[A-Za-z0-9+/=_-]{16,}$")


def _sent_signature(path, body):
    """The page plus the name=value pairs a request sends, random tokens left out."""
    from urllib.parse import parse_qsl
    page, _, query = str(path or "").partition("?")
    b = str(body or "")
    pairs = parse_qsl(query, keep_blank_values=True)
    if b and not b.lstrip().startswith(("{", "[", "<")):
        pairs += parse_qsl(b, keep_blank_values=True)
    elif b:
        pairs.append(("", b))
    return page + "?" + "&".join(sorted(f"{k}={v}" for k, v in pairs if not _TOKEN.match(v)))


def _page_shapes(path, ip):
    """The page each request is on: the path without numbers, plus the query values many
    visitors send and that name a page. On a site that routes every page through one script
    (index.php?page=user-poll.php) that value is a link, so it names the page; anything else
    (a search, a name, an ID, a payload) is input and does not."""
    from urllib.parse import parse_qsl
    base = path.map(_shape)
    pairs = [[(k, v) for k, v in parse_qsl(p.partition("?")[2], keep_blank_values=True)] for p in path]
    flat = pd.DataFrame([(i, b, k, v) for i, b, ps in zip(path.index, base, pairs) for k, v in ps],
                        columns=["row", "base", "k", "v"])
    if flat.empty:
        return base
    flat["ip"] = ip.loc[flat["row"]].values
    # Only a value that names a page (user-poll.php, /admin/index.html) can be a link; a
    # name, a button label or a number is input, however many visitors send it.
    shared = (flat.groupby(["base", "k", "v"])["ip"].transform("nunique") >= SHARED_BY) \
        & flat["v"].str.contains(_PAGE_VALUE)
    kv = (flat["k"] + "=" + flat["v"])[shared]
    nav = kv.groupby(flat.loc[shared, "row"]).agg(lambda x: "&".join(sorted(x)))
    return base.where(~base.index.isin(nav.index), base + "?" + nav.reindex(base.index).fillna(""))


def _vs_typical(count, key, session):
    """How far this session goes past a typical visitor of the same resource or form:
    log(1 + this session's count) - log(1 + the median count over all sessions using that key),
    0 when it is not above the median or the request has no key.

    Why (v9): in the lab, enumeration and parameter probing hit pages that normal users of
    the generator never open, so the model learned "popular page = navigation". On WebGoat
    (normal users open their own profile, /IDOR/profile/{id}) and under dalfox (the probed
    form is one normal users fill) that shortcut hid the attack. What makes enumeration and
    probing an attack on any site is going much further than the others on the same page:
    30 different profile IDs where a visitor opens 2, 40 different values in one form where
    a visitor sends 1. A shop where everybody browses many products has a high median, so
    heavy shoppers are not far above it."""
    k = pd.Series(key, index=count.index)
    ok = k.notna() & (k.astype(str) != "")
    per = pd.DataFrame({"k": k[ok], "s": session[ok], "c": count[ok]}).drop_duplicates(["k", "s"])
    typical = k.map(per.groupby("k")["c"].median()).fillna(0)
    out = (np.log1p(count) - np.log1p(typical)).clip(lower=0)
    return out.where(ok, 0.0)


def context_features(df):
    """df: one row per request (ip, timestamp, method, path, status, size, body, and
    proba = the payload detector's probability). Returns (feature table, df with `session`),
    both in the same row order."""
    d = add_session_ids(df).copy()
    body = d["body"].fillna("").astype(str) if "body" in d else pd.Series("", index=d.index)
    path = d["path"].fillna("").astype(str)
    st = pd.to_numeric(d["status"], errors="coerce").fillna(0).astype(int)
    size = pd.to_numeric(d["size"], errors="coerce").fillna(0) if "size" in d else pd.Series(0, index=d.index)
    page = path.str.split("?").str[0]
    who = d["_visitor"]                   # v10: IP + user agent (ml/sessions.py visitor_key)
    shape = _page_shapes(path, who)
    ids = pd.Series([_object_id(p, b) for p, b in zip(path, body)], index=d.index)
    res, rid = ids.str[0], ids.str[1]
    session = d["session"]
    f = pd.DataFrame(index=d.index)

    names = [field_names(p, b) for p, b in zip(path, body)]
    sends_password = pd.Series([any(PASSWORD.search(n) for n in ns) for ns in names], index=d.index)
    # Most real logs do not record the body (v9: AIT, SR-BH, zanbil). There a login attempt is
    # only "a POST to a login page"; when the body is logged, its fields decide as before.
    method = d["method"].fillna("").astype(str).str.upper()
    blind_login = (body.str.strip() == "") & (method == "POST") & page.str.contains(LOGIN_PATH)
    f["password_field"] = (sends_password | blind_login).astype(int)
    # A form is its address and the fields it sends: on a site that routes every page
    # through one script (index.php?page=...), the login form and an account-lookup form
    # share the address but not their fields.
    form = page + "|" + pd.Series([",".join(sorted(set(ns))) for ns in names], index=d.index)
    f["size_vs_page"] = np.log1p(size) - np.log1p(size.groupby(page).transform("median"))
    # The detector's yes/no, not its raw probability: tiny differences between 0.0001 and
    # 0.0003 are noise of one site's wording, and a model split on them does not travel.
    f["payload_score"] = (d["proba"].values >= 0.5).astype(float) if "proba" in d else 0.0
    n_ips = max(2, who.nunique())
    visitors = who.groupby(shape).transform("nunique")
    f["page_popularity"] = np.log(visitors) / np.log(n_ips)      # 0 = only this visitor, 1 = everyone
    # The answer = status + size rounded to 256 bytes: a not-found page that repeats the
    # requested address back changes its size by a few bytes, it is still the same page.
    answer = st.astype(str) + ":" + (size // 256).astype(int).astype(str)
    if UNIQUE_ANSWER_STATUSES:
        own = st.isin(UNIQUE_ANSWER_STATUSES)
        # v10: a log that does not record the answer size (size 0 / "-" on almost every 2xx answer,
        # e.g. logs exported from a WAF) gives every page the same "200:0" answer, which reads as a
        # scanner getting one not-found page. There a 2xx answer says nothing about the page, so it
        # counts as the page's own answer; error answers (404, 403, 5xx) still count as shared.
        ok2 = st.between(200, 299)
        if ok2.sum() >= MIN_SIZED_ANSWERS and (size[ok2] <= 0).mean() >= NO_SIZE_SHARE:
            own = own | ok2
        answer = answer.where(~own, answer + ":" + shape)
    f["answer_pages_log"] = shape.groupby(answer).transform("nunique") / max(1, shape.nunique())
    if APL_LOGIN_ZERO:
        f.loc[f["password_field"] == 1, "answer_pages_log"] = 0.0

    f["same_page_in_session"] = page.groupby([session, page]).transform("size")
    f["ids_this_resource"] = rid.groupby([session, res]).transform("nunique").fillna(0)
    login = f["password_field"]
    f["attempts_this_form"] = login.groupby([session, form]).transform("sum") * login
    # Failed logins look alike however the site answers them (401, or the same 200 page
    # again): the attempts on this form that got this same answer.
    f["form_same_answer"] = login.groupby([session, form, answer]).transform("sum") * login
    # How many different things this session sent to this same form that (almost) no other
    # visitor sent. A person searches or fills a form a few times; a tool probing a parameter
    # (sqlmap, wapiti) sends hundreds of variants nobody else sends. Values many visitors
    # share are navigation (index.php?page=user-poll.php), not input, and do not count.
    has_fields = pd.Series([len(ns) > 0 for ns in names], index=d.index)
    sent = pd.Series([_sent_signature(p, b) for p, b in zip(path, body)], index=d.index)
    own = sent.where(who.groupby(sent).transform("nunique") < SHARED_BY)
    own_values = own.groupby([session, form]).transform("nunique").fillna(0)
    f["form_values"] = np.log1p(own_values) * has_fields
    f["ids_vs_typical"] = _vs_typical(f["ids_this_resource"], res, session)
    f["values_vs_typical"] = _vs_typical(own_values * has_fields, form.where(has_fields), session)

    by = d.groupby("session")
    n = by["ip"].transform("size")
    f["s_requests"] = np.log1p(n)
    f["s_pages"] = np.log1p(shape.groupby(session).transform("nunique"))
    f["s_max_ids"] = f["ids_this_resource"].groupby(session).transform("max")
    f["s_max_form_attempts"] = f["attempts_this_form"].groupby(session).transform("max")
    payload = (f["payload_score"] >= 0.5).astype(int)
    f["s_share_payload"] = payload.groupby(session).transform("mean")
    f["s_payloads"] = np.log1p(payload.groupby(session).transform("sum"))
    f["s_unpopular_share"] = (visitors == 1).groupby(session).transform("mean")
    f["s_mean_popularity"] = f["page_popularity"].groupby(session).transform("mean")
    # A scanner gets one answer (the not-found page, whatever its status) for most of the
    # different pages it tries; a person or a crawler gets real pages of many sizes.
    pages_per_answer = shape.groupby([session, answer]).transform("nunique")
    f["s_top_answer_share"] = pages_per_answer.groupby(session).transform("max") / shape.groupby(session).transform("nunique")
    return f[FEATURES].astype(float), d


def target(attack_type):
    """Training label per request: the behaviour class, or None for payload attacks
    (those are the payload detector's job and are left out of this model's training)."""
    return attack_type.fillna("").map(lambda v: "normal" if v == "" else LABEL_OF.get(v))


def training_target(d, X):
    """target() for training, minus the rows the log cannot tell apart: an attacker's own
    login on the same form they brute-force (same address, same fields, often the same
    answer as a failed guess) is left out instead of being taught as "normal"."""
    y = target(d["attack_type"])
    brute = (d["attack_type"] == "bruteforce").groupby(d["session"]).transform("any")
    y[(y == "normal") & brute & (X["password_field"] == 1)] = None
    return y


def new_model():
    from xgboost import XGBClassifier
    return XGBClassifier(n_estimators=300, max_depth=4, learning_rate=0.1, subsample=0.8,
                         colsample_bytree=0.8, n_jobs=2, random_state=0)


def fit(X, y):
    model = new_model()
    model.fit(X[FEATURES], y.map({b: i for i, b in enumerate(BEHAVIOURS)}))
    return model


def predict_behaviours(model, X):
    """Behaviour name per request ("" = none) and the model's attack probability."""
    # the columns the model was trained with: a model saved before a feature was added still loads
    cols = list(getattr(model, "feature_names_in_", FEATURES))
    proba = model.predict_proba(X[cols])
    names = np.array([""] + BEHAVIOURS[1:])[proba.argmax(axis=1)]
    return names, 1 - proba[:, 0]


def load_context_model(path=MODEL_PATH):
    return joblib.load(path)
