"""
The full pipeline on one labelled run, exactly as the backend uses it:
detector (per request) + session layer + attack type, plus the unusual-request mark.
investigate() adds the rest of the investigation (stage, next step, defence), and
run_tool() runs the same pipeline on a real-tool log, where the label comes from the IP.
Used by notebooks/09_final_test.ipynb (run5) and notebooks/16_final_test_run6.ipynb.

    python -m eval.final_test data/raw/dvwa_generated_dvwa_check.log data/labels/requests_dvwa_dvwa_check.csv
"""
import sys

import joblib
import pandas as pd
from sklearn.metrics import precision_score, recall_score

from backend.app.log_parser import decode, parse_log
from eval.match_labels import match
from eval.rules import rule_predict
from ml.attack_type import attack_types, load_type_model
from ml.defense import FixFinder, add_defense, load_block_rules
from ml.detector import MODEL_PATH, to_frame
from ml.next_step import NextStepModel, add_next_steps, merge_steps
from ml.outliers import unusual_requests
from ml.sessions import analyze_sessions
from ml.stage import add_stages

PAYLOAD_TYPES = ["sqli", "xss", "traversal", "cmdi"]
DETECTORS = ["rules", "rules + sessions", "model", "model + sessions"]
TOOL_IP = "172.19.0.7"      # the tools container in the lab; every other IP in a tool log is a normal visitor


def run(log_path, labels_path, drop_body=False):
    """Return (requests DataFrame with predictions, sessions DataFrame, match report)."""
    df, report = match(log_path, labels_path)
    req, sessions = _pipeline(df, drop_body)
    return req, sessions, report


def run_tool(log_path, attacker_ip=TOOL_IP, drop_body=False):
    """A real-tool log: requests from attacker_ip are attacks (type "tool"), all others normal."""
    rows, skipped = parse_log(decode(open(log_path, "rb").read()))
    df = pd.DataFrame(rows)
    is_tool = df["ip"] == attacker_ip
    df["label"] = is_tool.map({True: "attack", False: "normal"})
    df["attack_type"] = is_tool.map({True: "tool", False: ""})
    req, sessions = _pipeline(df, drop_body)
    return req, sessions, {"log_lines": len(rows) + skipped, "parsed": len(rows), "skipped": skipped,
                           "tool requests": int(is_tool.sum()), "other requests": int((~is_tool).sum())}


def _pipeline(df, drop_body=False):
    if drop_body:                                   # what a normal access log (no bodies) gives us
        df["body"] = ""
    detector, type_model = joblib.load(MODEL_PATH), load_type_model()
    X = to_frame(df["method"], df["path"], df["body"])
    df["pred"] = detector.predict(X)
    df["unusual"] = unusual_requests(X)
    df["rules"] = rule_predict(df["method"], df["path"], df["body"])
    df["_key"] = range(len(df))                     # to line up the two session runs
    sessions, req = analyze_sessions(df)
    req["model"] = req["pred"]
    req["model + sessions"] = (req["pred"] | req["session_attack"]).astype(int)
    # Baseline with the same session layer, so the table shows what the model itself adds.
    _, by_rules = analyze_sessions(df.assign(pred=df["rules"]))
    req["rules + sessions"] = (req["rules"] | req["_key"].map(by_rules.set_index("_key")["session_attack"])).astype(int)

    flagged = req["pred"] == 1
    req["type_pred"] = ""
    req.loc[flagged, "type_pred"] = attack_types(req.loc[flagged, "method"], req.loc[flagged, "path"],
                                                 req.loc[flagged, "body"], type_model)
    truth = req.groupby("session")["attack_type"].agg(lambda s: "attacker" if (s != "").any() else "normal")
    sessions["truth"] = sessions["session"].map(truth)
    return req, sessions


def summary(req):
    """One row per detector: recall, precision, false alarms."""
    y = (req["label"] != "normal").values
    rows = []
    for d in DETECTORS:
        p = req[d].values
        rows.append({"detector": d, "recall": recall_score(y, p), "precision": precision_score(y, p, zero_division=0),
                     "false alarms": int(p[~y].sum()), "normal requests": int((~y).sum()),
                     "attacks": int(y.sum())})
    return pd.DataFrame(rows).set_index("detector").round(3)


def recall_by_type(req):
    atk = req[req["label"] != "normal"]
    return atk.groupby("attack_type")[DETECTORS].mean().round(3)


def type_accuracy(req):
    """Of the payload attacks the model caught, how many got the right type."""
    c = req[(req["pred"] == 1) & req["attack_type"].isin(PAYLOAD_TYPES)]
    return pd.crosstab(c["attack_type"], c["type_pred"], rownames=["true"], colnames=["predicted"]), \
        float((c["attack_type"] == c["type_pred"]).mean()) if len(c) else float("nan")


def investigate(req, sessions):
    """The rest of the investigation, as the backend runs it: stage, next step, defence."""
    req, sessions = add_stages(req, sessions)
    sessions = add_next_steps(req, sessions, NextStepModel.load())
    sessions = add_defense(req, sessions, FixFinder(), load_block_rules())
    return req, sessions


def true_actions(req, sessions):
    """The right action per session from the labels: payload attack -> block,
    brute force / enumeration / scanning only -> rate_limit, normal -> allow."""
    kinds = req[req["attack_type"] != ""].groupby("session")["attack_type"].agg(set)

    def action(session):
        k = kinds.get(session, set())
        return "block" if k & (set(PAYLOAD_TYPES) | {"tool"}) else "rate_limit" if k else "allow"
    return sessions["session"].map(action)


def defence_summary(req, sessions):
    """Action per session against the right action. Attackers allowed and normal users
    blocked are the two mistakes that matter."""
    truth = true_actions(req, sessions)
    got = sessions["action"]
    attacker = truth != "allow"
    return pd.Series({"sessions": len(sessions), "action right": round(float((got == truth).mean()), 3),
                      "attackers allowed": int((attacker & (got == "allow")).sum()),
                      "normal users blocked": int((~attacker & (got == "block")).sum()),
                      "normal users rate-limited": int((~attacker & (got == "rate_limit")).sum()),
                      "payload attackers not blocked": int(((truth == "block") & (got != "block")).sum())})


def stage_summary(sessions):
    """Stage reached per session, attackers vs normal users (normal users should have none)."""
    return pd.crosstab(sessions["truth"], sessions["stage"].replace("", "none"))


def unusual_summary(req):
    """The unusual-request mark: how often it fires on normal requests and on attacks,
    and how many attacks the detector + session layer missed that it marks."""
    normal = req["label"] == "normal"
    missed = ~normal & (req["model + sessions"] == 0)
    return pd.Series({"marked": int(req["unusual"].sum()),
                      "normal requests marked": int((req["unusual"] & normal).sum()),
                      "attacks marked": int((req["unusual"] & ~normal).sum()),
                      "attacks missed by model + sessions": int(missed.sum()),
                      "of those, marked unusual": int((req["unusual"] & missed).sum())})


def next_step_summary(req, sessions_labels_path, model=None):
    """Campaign sessions only: is the step order read right from the log, and how often is
    the next step in the model's top 1 / top 3 (on the true order and on the order read)."""
    model = model or NextStepModel.load()
    lab = pd.read_csv(sessions_labels_path, keep_default_na=False)
    truth = {ip: merge_steps(s.split(">"), min_run=1)
             for ip, s in lab.loc[lab["attack_type"] == "campaign"].set_index("ip")["steps"].items()}
    from ml.next_step import session_steps
    read = session_steps(req)
    ip_of = req.drop_duplicates("session").set_index("session")["ip"]
    read = {ip_of[s]: st for s, st in read.items()}
    normal_ips = set(lab.loc[lab["label"] == "normal", "ip"])
    out = {"campaigns": len(truth), "order read exactly": sum(read.get(ip) == st for ip, st in truth.items()),
           "normal users with steps": sum(ip in read for ip in normal_ips)}
    for name, seqs in [("true order", list(truth.values())),
                       ("order read", [read[ip] for ip in truth if ip in read])]:
        for k in (1, 3):
            acc, n = model.top_k_accuracy(seqs, k)
            out[f"top-{k} ({name})"] = round(acc, 3)
        out[f"steps scored ({name})"] = n
    return pd.Series(out)


if __name__ == "__main__":
    req, sessions, report = run(sys.argv[1], sys.argv[2])
    print(report)
    print(summary(req))
    print(recall_by_type(req))
    print(type_accuracy(req)[1])
    print(pd.crosstab(sessions["truth"], sessions["risk_level"]))
