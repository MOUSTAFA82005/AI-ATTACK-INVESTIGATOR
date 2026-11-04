"""
What are the v9 false alarms on SR-BH held-out DEV days? (CRS says normal, the model says attack.)
Prints only summaries: page shapes, which attack signals fired, methods. DEV data only.

    python -m eval.v9_fa_look models/detector_v9_holdout2.joblib
"""
import re
import sys
from collections import Counter
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

from ml.detector import served_files, signal_columns, to_frame

HOLDOUT = ["2020-07-19", "2020-07-23", "2020-07-24"]


def shape(p):
    p = p.split("?", 1)
    base = re.sub(r"\d+", "0", p[0])[:70]
    keys = sorted({kv.split("=", 1)[0][:20] for kv in p[1].split("&")}) if len(p) > 1 else []
    return base + ("?" + "&".join(keys)[:60] if keys else "")


def main(model_path):
    m = joblib.load(model_path)
    s = pd.read_csv("data/processed/v9/srbh_dev.csv", dtype=str, keep_default_na=False)
    s = s[s["timestamp"].str[:10].isin(HOLDOUT) & (s["label"] == "0")].reset_index(drop=True)
    for c in ("status", "size"):
        s[c] = pd.to_numeric(s[c], errors="coerce").fillna(0).astype(int)
    X = to_frame(s["method"], s["path"], s["body"])
    proba = m.predict_proba(X)[:, 1]
    pred = (proba >= 0.5).astype(int)
    pred[np.asarray(served_files(s, X, pred))] = 0
    fa = pred == 1
    print(f"CRS-normal requests: {len(s)}, flagged by the model: {int(fa.sum())} ({fa.mean():.4f})")
    print(f"distinct flagged requests (method+path+body): {s[fa].drop_duplicates(['method', 'path', 'body']).shape[0]}")
    print("\nmethods:", dict(Counter(s.loc[fa, "method"])))
    print("status codes:", dict(Counter(s.loc[fa, "status"]).most_common(8)))
    sig = X.loc[fa, signal_columns(X)].gt(0).mean().sort_values(ascending=False)
    print("\nattack signals firing in the flagged requests (share):")
    print(sig[sig > 0.02].round(3).to_string())
    print(f"\nflagged requests with NO attack signal at all: {(X.loc[fa, signal_columns(X)].sum(axis=1) == 0).mean():.3f}")
    print("\ntop 25 page shapes among the flagged (digits -> 0, only parameter names):")
    for k, v in Counter(shape(p) for p in s.loc[fa, "path"]).most_common(25):
        print(f"{v:7d}  {k}")
    print("\nshare flagged by score band:", pd.cut(proba[fa], [0.5, 0.7, 0.9, 0.99, 1.0]).value_counts().sort_index().to_dict())


if __name__ == "__main__":
    main(sys.argv[1] if len(sys.argv) > 1 else "models/detector_v9_holdout2.joblib")
