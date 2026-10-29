"""
Why the session-layer thresholds are where they are, as a table for the report.

For one labelled run it prints:
  1. the headroom: how close normal sessions get to every threshold, and
  2. what each value of MIN_LOGIN_ATTEMPTS catches, and what it costs.

MIN_LOGIN_ATTEMPTS is the threshold with the least headroom. Normal users reach
3 login attempts on one form (people who mistype their own password), and the
slow brute force sends only 3 to 5 attempts, so the two nearly touch. 4 is the
lowest value that still flags nobody normal; 5 missed most of the slow brute
force on DVWA, which is why it was lowered.

Run it on development data only. Every threshold here was chosen on run3 and
run4, so these numbers explain the choice, they do not test it.

    python -m eval.threshold_check
    python -m eval.threshold_check data/raw/dvwa_generated_run4.log data/labels/requests_dvwa_run4.csv
"""
import sys

import pandas as pd

import ml.sessions as sessions_module
from eval.final_test import run

DEFAULT_LOG = "data/raw/juiceshop_generated_run3.log"
DEFAULT_LABELS = "data/labels/requests_run3.csv"

LOGIN_ATTEMPT_VALUES = [3, 4, 5, 6]

# session column -> the threshold it is compared against
THRESHOLDS = {
    "failed_logins": "MIN_FAILED_LOGINS",
    "login_attempts": "MIN_LOGIN_ATTEMPTS",
    "max_ids_one_resource": "MIN_IDS_PER_RESOURCE",
    "probes": "MIN_PROBES",
    "not_found": "MIN_NOT_FOUND",
    "server_errors": "MIN_SERVER_ERRORS",
}


def headroom(sessions):
    """How far the normal sessions stay below each threshold."""
    normal = sessions[sessions["truth"] == "normal"]
    rows = []
    for column, name in THRESHOLDS.items():
        threshold = getattr(sessions_module, name)
        highest = int(normal[column].max())
        rows.append({"threshold": name, "value": threshold,
                     "highest normal session": highest, "headroom": threshold - highest})
    return pd.DataFrame(rows).set_index("threshold")


def login_attempt_sweep(log_path, labels_path, values=LOGIN_ATTEMPT_VALUES):
    """One row per candidate value of MIN_LOGIN_ATTEMPTS."""
    original = sessions_module.MIN_LOGIN_ATTEMPTS
    rows = []
    try:
        for value in values:
            sessions_module.MIN_LOGIN_ATTEMPTS = value
            req, sessions, _ = run(log_path, labels_path)
            attacks = req["label"] != "normal"
            brute = req["attack_type"] == "bruteforce"
            normal = sessions["truth"] == "normal"
            rows.append({
                "MIN_LOGIN_ATTEMPTS": value,
                "recall": req.loc[attacks, "model + sessions"].mean(),
                "bruteforce recall": req.loc[brute, "model + sessions"].mean() if brute.any() else float("nan"),
                "false alarms": int(req.loc[~attacks, "model + sessions"].sum()),
                "normal sessions flagged": int((sessions.loc[normal, "risk_level"] != "none").sum()),
                "normal sessions": int(normal.sum()),
            })
    finally:
        sessions_module.MIN_LOGIN_ATTEMPTS = original
    return pd.DataFrame(rows).set_index("MIN_LOGIN_ATTEMPTS").round(4)


if __name__ == "__main__":
    log_path = sys.argv[1] if len(sys.argv) > 1 else DEFAULT_LOG
    labels_path = sys.argv[2] if len(sys.argv) > 2 else DEFAULT_LABELS
    print(log_path)

    _, sessions, report = run(log_path, labels_path)
    print(report)
    print("\n1. Headroom: how close do normal sessions get to each threshold?")
    print(headroom(sessions).to_string())
    print("\n2. MIN_LOGIN_ATTEMPTS: what each value catches, and what it costs")
    print(login_attempt_sweep(log_path, labels_path).to_string())
    print("\nNote: on Juice Shop the brute force is caught by failed_logins (it answers a failed "
          "login with 401),\nso this threshold only shows its cost here. The gain shows on DVWA, "
          "which answers 200\nand where the attempt count is the only signal.")
