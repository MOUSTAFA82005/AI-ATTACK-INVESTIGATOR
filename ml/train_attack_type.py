"""
Train the attack-type model on the HttpParams attack values and save it to
models/attack_type.joblib. Run from the repo root:

    python -m ml.train_attack_type

Needs data/raw/httpparams_train.csv (see ml/train_detector.py). Only the
attack rows are used; each value is sent as ?q=<value>, like in the detector.
The classes are unbalanced (mostly SQLi), so each class gets the same weight.
"""
from urllib.parse import quote

import joblib
import pandas as pd
from sklearn.utils.class_weight import compute_sample_weight
from xgboost import XGBClassifier

from ml.attack_type import TYPE_MODEL_PATH, TYPES
from ml.detector import ROOT, to_frame

HTTPPARAMS = ROOT / "data" / "raw" / "httpparams_train.csv"


def load(path):
    df = pd.read_csv(path, keep_default_na=False)
    df = df[df["label"] == "anom"]
    X = to_frame(["GET"] * len(df), ["/?q=" + quote(v, safe="") for v in df["payload"]], [""] * len(df))
    y = df["attack_type"].replace({"path-traversal": "traversal"}).map(TYPES.index)
    return X.drop(columns="text"), y.values


def build_model():
    return XGBClassifier(n_estimators=300, max_depth=6, learning_rate=0.1, tree_method="hist",
                         max_bin=32, n_jobs=2, random_state=42)


def main():
    X, y = load(HTTPPARAMS)
    print("training on", pd.Series(y).map(dict(enumerate(TYPES))).value_counts().to_dict())
    model = build_model().fit(X, y, sample_weight=compute_sample_weight("balanced", y))
    TYPE_MODEL_PATH.parent.mkdir(exist_ok=True)
    joblib.dump(model, TYPE_MODEL_PATH)
    print("saved", TYPE_MODEL_PATH)


if __name__ == "__main__":
    main()
