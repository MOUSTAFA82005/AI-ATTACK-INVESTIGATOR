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
import pandas as pd

from ml.attack_type import TYPES, rule_scores
from ml.sessions import _is_probe

STAGES = ["recon", "intrusion", "exploitation", "data_theft"]
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


def request_stages(req):
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


def add_stages(req, sessions):
    """
    Add `stage` to every request and, per session, the furthest stage reached and the
    order the stages were first seen in. A high-risk session that reached exploitation
    or data theft becomes "critical".
    """
    req = req.copy()
    req["stage"] = request_stages(req)
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
