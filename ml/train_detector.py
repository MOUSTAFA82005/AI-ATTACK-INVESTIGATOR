"""
Train the detection model on CSIC 2010 and save it to models/detector.joblib.

Run from the repo root, after notebooks/01_csic_baseline.ipynb has written
data/processed/csic_clean.csv:

    python -m ml.train_detector
"""
import time

import joblib
import pandas as pd

from ml.detector import MODEL_PATH, ROOT, build_pipeline, to_frame


def main():
    df = pd.read_csv(ROOT / "data" / "processed" / "csic_clean.csv", keep_default_na=False)
    X = to_frame(df["Method"], df["path"], df["body"])
    y = df["label"]
    hand_cols = [c for c in X.columns if c != "text"]

    pos, neg = (y == 1).sum(), (y == 0).sum()
    print(f"training on {len(df)} requests ({pos} attacks, {neg} normal)...")
    t = time.time()
    pipe = build_pipeline(hand_cols, pos_weight=neg / pos).fit(X, y)
    print(f"done in {time.time() - t:.0f}s")

    MODEL_PATH.parent.mkdir(exist_ok=True)
    joblib.dump(pipe, MODEL_PATH)
    print("saved", MODEL_PATH)


if __name__ == "__main__":
    main()
