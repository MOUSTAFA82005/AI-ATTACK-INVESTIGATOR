"""
Train the block-rule Decision Tree (ml/defense.py) on the development runs.

    python -m ml.train_defense

For every dev run found in data/ (run3, run4, camp7, both sites) the full pipeline is run
(detector, sessions, attack type, stage), and every session gets the action a defender
should take from its TRUE kind (labels): block if it sent attack payloads, rate_limit if
it only abused normal-looking requests (brute force, ID enumeration, scanning), allow if
it is a normal visitor. The tree learns to give that action from the session numbers.

Saves models/block_rules.joblib (do not commit) and prints the rules as if/else text.
The locked final runs are never used here.
"""
import joblib
import pandas as pd
from sklearn.tree import DecisionTreeClassifier, export_text

from eval.final_test import run
from ml.defense import BLOCK_RULES_PATH, FEATURES, PAYLOAD_STEPS, session_features
from ml.detector import ROOT
from ml.stage import add_stages

DEV_RUNS = [  # (log, request labels); only these, never run5/run6 or the real-tool files
    ("juiceshop_generated_run3.log", "requests_run3.csv"),
    ("juiceshop_generated_run4.log", "requests_run4.csv"),
    ("dvwa_generated_run4.log", "requests_dvwa_run4.csv"),
    ("juiceshop_generated_camp7.log", "requests_camp7.csv"),
    ("dvwa_generated_camp7.log", "requests_dvwa_camp7.csv"),
]
TREE = dict(max_depth=4, min_samples_leaf=5, class_weight="balanced", random_state=0)


def true_actions(req, sessions):
    """The action per session from the labels of its requests."""
    kinds = req[req["attack_type"] != ""].groupby("session")["attack_type"].agg(set)

    def action(session):
        k = kinds.get(session, set())
        return "block" if k & set(PAYLOAD_STEPS) else "rate_limit" if k else "allow"
    return sessions["session"].map(action)


def dev_table():
    """Session features + true action for every dev run present, with the run name."""
    parts = []
    for log, labels in DEV_RUNS:
        log_path, labels_path = ROOT / "data" / "raw" / log, ROOT / "data" / "labels" / labels
        if not (log_path.exists() and labels_path.exists()):
            print("skipped (not found):", log)
            continue
        req, sessions, _ = run(log_path, labels_path)
        req, sessions = add_stages(req, sessions)
        x = session_features(sessions, req)
        x["action"] = true_actions(req, sessions).values
        x["run"] = log
        parts.append(x)
    return pd.concat(parts)


if __name__ == "__main__":
    data = dev_table()
    tree = DecisionTreeClassifier(**TREE).fit(data[FEATURES], data["action"])
    BLOCK_RULES_PATH.parent.mkdir(exist_ok=True)
    joblib.dump(tree, BLOCK_RULES_PATH)
    print(f"trained on {len(data)} sessions from {data['run'].nunique()} runs, saved to {BLOCK_RULES_PATH}")
    print(data["action"].value_counts().to_string())
    print(export_text(tree, feature_names=FEATURES))
