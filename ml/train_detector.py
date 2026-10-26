"""
Train the detection model on CSIC 2010 (+ HttpParams if present) and save it
to models/detector.joblib.

Run from the repo root, after notebooks/01_csic_baseline.ipynb has written
data/processed/csic_clean.csv:

    python -m ml.train_detector

CSIC labels as "anomalous" many requests that carry no attack at all (a
renamed parameter, a value that is only wrong for that one shop). No general
model can learn those, and they teach it that clean requests look like attacks.
So we train on CSIC normal traffic + the anomalous requests that carry a payload.
See notebooks/04_site_independent_detector.ipynb.

HttpParams (https://github.com/Morzeux/HttpParamsDataset) adds attack values
made with other tools (sqlmap, FuzzDB, Vega), so the model sees more kinds of
attacks than CSIC has. Download payload_train.csv from that repo and save it as
data/raw/httpparams_train.csv; if the file is missing we train on CSIC only.
See notebooks/07_second_dataset.ipynb.
"""
import time
from urllib.parse import quote

import joblib
import pandas as pd

from ml.detector import MODEL_PATH, ROOT, build_pipeline, has_payload, to_frame

HTTPPARAMS = ROOT / "data" / "raw" / "httpparams_train.csv"


def load_httpparams(path):
    """HttpParams rows are single parameter values: send each one as ?q=<value>."""
    df = pd.read_csv(path, keep_default_na=False)
    X = to_frame(["GET"] * len(df), ["/?q=" + quote(v, safe="") for v in df["payload"]], [""] * len(df))
    return X, (df["label"] == "anom").astype(int)


def main():
    df = pd.read_csv(ROOT / "data" / "processed" / "csic_clean.csv", keep_default_na=False)
    X = to_frame(df["Method"], df["path"], df["body"])
    y = df["label"]
    if HTTPPARAMS.exists():
        Xh, yh = load_httpparams(HTTPPARAMS)
        print(f"adding {len(yh)} HttpParams values ({yh.sum()} attacks)")
        X, y = pd.concat([X, Xh], ignore_index=True), pd.concat([y, yh], ignore_index=True)
    else:
        print(f"{HTTPPARAMS} not found: training on CSIC only")

    keep = (y == 0) | has_payload(X)
    print(f"dropping {(~keep).sum()} anomalies with no attack payload")
    X, y = X[keep].reset_index(drop=True), y[keep].reset_index(drop=True)
    hand_cols = [c for c in X.columns if c != "text"]

    pos, neg = (y == 1).sum(), (y == 0).sum()
    print(f"training on {len(y)} requests ({pos} attacks, {neg} normal)...")
    t = time.time()
    pipe = build_pipeline(hand_cols, pos_weight=neg / pos).fit(X, y)
    print(f"done in {time.time() - t:.0f}s")

    MODEL_PATH.parent.mkdir(exist_ok=True)
    joblib.dump(pipe, MODEL_PATH)
    print("saved", MODEL_PATH)


if __name__ == "__main__":
    main()
