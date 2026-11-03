"""
stage.py - how far each attacker got, in MITRE ATT&CK terms.

Four stages, in order:
  1 recon        looking around: scanning for hidden files, trying IDs that do not exist
  2 intrusion    trying to get in: attack payloads and login guessing that did not work
  3 exploitation it worked: a payload got an unusual answer, or a login succeeded after failures
  4 data_theft   taking data: unusually large answers after exploitation, or many object
                 IDs read with success

A log does not say whether an attack worked, so "worked" is read from the answer:
a 2xx status with a response much larger than what this endpoint normally sends.
"Normally" is learned from the same log (the median size of the requests nobody
flagged), so it works on any site. On sites that answer 200 to everything (DVWA)
this size check is the only signal, which is a stated limitation.

These are rules we wrote, so the stage is our definition, not a ground truth.
See notebooks/10_attack_stage.ipynb.
"""
import joblib
import numpy as np
import pandas as pd

from ml.attack_type import TYPES, rule_scores
from ml.sessions import _is_probe

STAGES = ["recon", "intrusion", "exploitation", "data_theft"]
STAGE_MODEL_PATH = "models/stage.joblib"
_RANK = {s: i + 1 for i, s in enumerate(STAGES)}

BIG_RATIO = 3        # "much larger": at least 3 times the normal size of this endpoint ...
BIG_BYTES = 500      # ... and at least 500 bytes more, so tiny answers do not count


def _normal_sizes(req):
    """Median response size per (endpoint, status) over the requests nobody flagged."""
    quiet = req[(req["pred"] == 0) & (req["session_attack"] == 0)]
    return quiet.groupby([quiet["path"].str.split("?").str[0], quiet["status"]])["size"].median()


def _is_big(req, normal):
    ep = req["path"].str.split("?").str[0]
    base = pd.Series([normal.get((e, s)) for e, s in zip(ep, req["status"])], index=req.index, dtype=float)
    size = pd.to_numeric(req["size"], errors="coerce").fillna(0)
    ok = req["status"].between(200, 299)
    # No normal request to compare with: the attacker asked for something nobody else did
    # (e.g. a file outside the web root). Then any real answer counts as unusual.
    return ok & ((base.isna() & (size >= BIG_BYTES)) | ((size >= BIG_RATIO * base) & (size - base >= BIG_BYTES)))


def probe_only(req):
    """True for requests that ask for a hidden file and carry no attack payload."""
    bodies = req["body"] if "body" in req else pd.Series("", index=req.index)
    return pd.Series([_is_probe(m, p) and not any(rule_scores(m, p, b)[t] for t in TYPES)
                      for m, p, b in zip(req["method"], req["path"], bodies)], index=req.index)


def rule_stages(req):
    """
    req: the request DataFrame from analyze_sessions, with pred, behaviour, status, size.
    Returns a Series with one stage per request ("" for requests that are not part of an attack).
    """
    big = _is_big(req, _normal_sizes(req))
    ok = req["status"].between(200, 299)
    stage = pd.Series("", index=req.index, dtype=object)

    stage[req["behaviour"] == "scan"] = "recon"
    enum = req["behaviour"] == "enumeration"
    stage[enum] = "recon"
    stage[enum & ok] = "data_theft"                       # the object was there and was sent back

    brute = req["behaviour"] == "bruteforce"
    stage[brute] = "intrusion"
    payload = req["pred"] == 1
    stage[payload] = "intrusion"
    stage[payload & big] = "exploitation"
    # A probe for a hidden file (and no attack payload in it) is looking around, whatever the
    # answer: many sites (Juice Shop) send their normal page with 200 for any unknown path.
    probe = probe_only(req)
    stage[(payload | (req["behaviour"] == "scan")) & probe] = "recon"

    # A login that succeeds after failed ones in the same session: the guessing worked.
    order = req.sort_values(["session", "timestamp"], kind="stable").index
    r = req.loc[order]
    failed_before = (brute.loc[order] & ~ok.loc[order]).groupby(r["session"]).cummax()
    win = brute.loc[order] & ok.loc[order] & failed_before.groupby(r["session"]).shift(fill_value=False)
    # Sites that answer 200 to a failed login cannot show this; only real success codes count.
    stage[win[win].index] = "exploitation"

    # After the first exploitation, an unusually large answer is data leaving the site.
    exploited = (stage.loc[order] == "exploitation").groupby(r["session"]).cummax()
    after = exploited.groupby(r["session"]).shift(fill_value=False)
    theft = after & big.loc[order] & (stage.loc[order] != "exploitation")
    stage[theft[theft].index] = "data_theft"
    return stage


def add_stages(req, sessions, model="default"):
    """
    Add `stage` to every request and, per session, the furthest stage reached and the
    order the stages were first seen in. A high-risk session that reached exploitation
    or data theft becomes "critical".
    """
    req = req.copy()
    req["stage"] = request_stages(req, model)
    staged = req[req["stage"] != ""].sort_values(["session", "timestamp"], kind="stable")
    furthest = staged.groupby("session")["stage"].agg(lambda s: max(s, key=_RANK.get))
    path = staged.groupby("session")["stage"].agg(lambda s: list(dict.fromkeys(s)))

    sessions = sessions.copy()
    sessions["stage"] = sessions["session"].map(furthest).fillna("")
    sessions["stage_path"] = sessions["session"].map(path).apply(lambda p: p if isinstance(p, list) else [])
    critical = (sessions["risk_level"] == "high") & sessions["stage"].isin(["exploitation", "data_theft"])
    sessions.loc[critical, "risk_level"] = "critical"
    for i in sessions.index[critical]:
        sessions.at[i, "reasons"] = sessions.at[i, "reasons"] + [f"the attack reached {sessions.at[i, 'stage']}"]
    return req, sessions


# ---------------------------------------------------------------------------
# The learned stage model (the system). rule_stages() above is the baseline.
# ---------------------------------------------------------------------------
# It is trained on the true stage the generator read from the server's whole
# answer (did the file / the token / the records really come back), but it only
# sees what a log shows: status, size compared with the same page's normal
# answers, what the other models said (payload, behaviour, type), and where the
# request sits in its session. python -m ml.train_stage
BEHAVIOURS = ["bruteforce", "enumeration", "scan"]
STAGE_FEATURES = None   # filled by stage_features (fixed order below)


def stage_features(req):
    """One row per request of req (needs pred, behaviour, status, size, session, timestamp)."""
    from ml.attack_type import CLASSES
    from ml.context_model import context_features
    st = pd.to_numeric(req["status"], errors="coerce").fillna(0).astype(int)
    size = pd.to_numeric(req["size"], errors="coerce").fillna(0)
    normal = _normal_sizes(req)
    ep = req["path"].str.split("?").str[0]
    base = pd.Series([normal.get((e, s)) for e, s in zip(ep, st)], index=req.index, dtype=float)
    f = pd.DataFrame(index=req.index)
    for name, cond in [("st_2xx", st.between(200, 299)), ("st_3xx", st.between(300, 399)),
                       ("st_401_403", st.isin([401, 403])), ("st_404", st == 404),
                       ("st_4xx_other", st.between(400, 499) & ~st.isin([401, 403, 404])), ("st_5xx", st >= 500)]:
        f[name] = cond.astype(int)
    f["size_log"] = np.log1p(size)
    f["size_vs_normal"] = (np.log1p(size) - np.log1p(base)).fillna(0)       # 0 when the page has no normal answers
    f["no_normal_answer"] = base.isna().astype(int)
    # Compared with the same page inside this session (an ID sweep: the IDs that exist
    # give a different answer from the ones that do not, whatever the site's status codes).
    page_sess = [req["session"], ep]
    f["size_vs_session_page"] = np.log1p(size) - np.log1p(size.groupby(page_sess).transform("median"))
    answer = st.astype(str) + ":" + (size // 256).astype(int).astype(str)
    f["answer_share_session_page"] = answer.groupby(page_sess).transform(
        lambda a: a.map(a.value_counts(normalize=True)))
    f["payload"] = req["pred"].astype(int)
    for b in BEHAVIOURS:
        f["beh_" + b] = (req["behaviour"] == b).astype(int)
    types = req["type_pred"] if "type_pred" in req else pd.Series("", index=req.index)
    for t in CLASSES:
        f["type_" + t] = (types == t).astype(int)
    f["probe"] = probe_only(req).astype(int)
    X, _ = context_features(req.assign(proba=req["proba"] if "proba" in req else req["pred"].astype(float)))
    for c in ["page_popularity", "answer_pages_log", "same_page_in_session", "ids_this_resource",
              "attempts_this_form", "form_same_answer", "s_requests"]:
        f[c] = X[c].values
    # Order inside the session: what came before this request.
    order = req.sort_values(["session", "timestamp"], kind="stable").index
    r = req.loc[order]
    login_ok = (f.loc[order, "beh_bruteforce"] == 1) & (f.loc[order, "st_2xx"] == 1)
    f.loc[order, "position"] = r.groupby("session").cumcount() / r.groupby("session")["session"].transform("size")
    f.loc[order, "big_before"] = ((f.loc[order, "size_vs_normal"] > 1) & (f.loc[order, "payload"] == 1)) \
        .groupby(r["session"]).cummax().groupby(r["session"]).shift(fill_value=False).astype(int)
    f.loc[order, "login_ok_before"] = login_ok.groupby(r["session"]).cummax() \
        .groupby(r["session"]).shift(fill_value=False).astype(int)
    return f.astype(float)


def attack_rows(req):
    """The requests the other models called part of an attack: only these get a stage."""
    return (req["pred"] == 1) | (req["behaviour"] != "")


def load_stage_model(path=STAGE_MODEL_PATH):
    try:
        return joblib.load(path)
    except FileNotFoundError:
        return None


def request_stages(req, model="default"):
    """Stage per request ("" outside attacks). The learned model if it is trained, else the rules."""
    if isinstance(model, str):
        model = load_stage_model()
    if model is None:
        return rule_stages(req)
    stage = pd.Series("", index=req.index, dtype=object)
    rows = attack_rows(req)
    if rows.any():
        X = stage_features(req)[rows]
        stage[rows] = np.array(STAGES)[model.predict(X)]
    return stage
