"""
The full pipeline on one labelled run, exactly as the backend uses it:
detector (per request) + session layer + attack type. Used by
notebooks/09_final_test.ipynb.

    python -m eval.final_test data/raw/dvwa_generated_dvwa_check.log data/labels/requests_dvwa_dvwa_check.csv
"""
import sys

import joblib
import pandas as pd
from sklearn.metrics import precision_score, recall_score

from eval.match_labels import match
from eval.rules import rule_predict
from ml.attack_type import attack_types, load_type_model
from ml.detector import MODEL_PATH, to_frame
from ml.sessions import analyze_sessions

PAYLOAD_TYPES = ["sqli", "xss", "traversal", "cmdi"]
DETECTORS = ["rules", "rules + sessions", "model", "model + sessions"]


def run(log_path, labels_path, drop_body=False):
    """Return (requests DataFrame with predictions, sessions DataFrame, match report)."""
    df, report = match(log_path, labels_path)
    if drop_body:                                   # what a normal access log (no bodies) gives us
        df["body"] = ""
    detector, type_model = joblib.load(MODEL_PATH), load_type_model()
    df["pred"] = detector.predict(to_frame(df["method"], df["path"], df["body"]))
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
    return req, sessions, report


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


if __name__ == "__main__":
    req, sessions, report = run(sys.argv[1], sys.argv[2])
    print(report)
    print(summary(req))
    print(recall_by_type(req))
    print(type_accuracy(req)[1])
    print(pd.crosstab(sessions["truth"], sessions["risk_level"]))
