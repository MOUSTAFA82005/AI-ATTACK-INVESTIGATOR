"""
v11 adoption check (results/final_v11/PREREGISTRATION.md): payload false alarms on the v10 sealed logs, which are DEV
data for v11 (ClarkNet, USask: converted rows in data/processed/v10/sealed/, never committed).

    python -m eval.v11_fa_check models/detector_v10_cloud.joblib models/detector_v11_try1.joblib

FA = share of rows flagged among rows the payload rules do not call attacks (same definition as the v10 sealed test,
payload layer only, threshold 0.7).
"""
import sys

import joblib
import pandas as pd

from eval.rules import rule_predict
from ml.detector import DETECTOR_THRESHOLD, ROOT, to_frame

LOGS = ["clarknet", "usask"]


def main(models):
    rows = []
    for log in LOGS:
        df = pd.read_csv(ROOT / "data" / "processed" / "v10" / "sealed" / f"{log}.csv", dtype=str, keep_default_na=False)
        normal = ~pd.Series(rule_predict(df["method"].tolist(), df["path"].tolist(), df["body"].tolist())).astype(bool).values
        X = to_frame(df["method"], df["path"], df["body"])
        for m in models:
            p = joblib.load(m).predict_proba(X)[:, 1] >= DETECTOR_THRESHOLD
            rows.append({"log": log, "model": m, "normal rows": int(normal.sum()),
                         "payload FA": round(float(p[normal].mean()), 5)})
    out = pd.DataFrame(rows)
    print(out.to_string(index=False))
    return out


if __name__ == "__main__":
    main(sys.argv[1:])
