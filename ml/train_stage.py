"""
Train the attack-stage model (ml/stage.py) -> models/stage.joblib

Training data: lab runs whose label files carry the true stage (generator v5 reads it
from the server's whole answer). Each run goes through the same pipeline as the
backend (detector, behaviour model, attack type), and the model learns the true stage
of every request the pipeline called an attack, from what the log shows.

    python -m ml.train_stage [tag ...]      (default tags: st21 st22 st31 st32)

Runs are data/raw/<site>_generated_<tag>.log + data/labels/requests[_<site>]_<tag>.csv
for the five lab sites (Juice Shop's label files have no site prefix); missing runs are skipped.
"""
import os
import sys

import joblib
import numpy as np
import pandas as pd
from sklearn.utils.class_weight import compute_sample_weight
from xgboost import XGBClassifier

from eval.final_test import run
from ml.stage import STAGE_MODEL_PATH, STAGES, attack_rows, stage_features

LAB_SITES = ["juiceshop", "dvwa", "bwapp", "mutillidae", "dvna", "vampi", "dvga"]
DEFAULT_TAGS = ["st21", "st22", "st31", "st32"]


def run_paths(site, tag):
    prefix = "" if site == "juiceshop" else site + "_"
    return f"data/raw/{site}_generated_{tag}.log", f"data/labels/requests_{prefix}{tag}.csv"


def labelled_rows(tags):
    X, y = [], []
    for tag in tags:
        for site in LAB_SITES:
            log, labels = run_paths(site, tag)
            if not (os.path.exists(log) and os.path.exists(labels)):
                continue
            req, _, _ = run(log, labels)
            if "true_stage" not in req:
                print("skipped (no stage column, generator before v5):", labels)
                continue
            rows = attack_rows(req) & (req["true_stage"] != "")
            X.append(stage_features(req)[rows])
            y.append(req.loc[rows, "true_stage"])
            print(site, tag, y[-1].value_counts().to_dict())
    return pd.concat(X, ignore_index=True), pd.concat(y, ignore_index=True)


def new_model():
    return XGBClassifier(n_estimators=300, max_depth=4, learning_rate=0.1, subsample=0.8,
                         colsample_bytree=0.8, n_jobs=2, random_state=0)


def fit(X, y):
    codes = y.map(STAGES.index).values
    model = new_model()
    model.fit(X, codes, sample_weight=compute_sample_weight("balanced", codes))
    return model


if __name__ == "__main__":
    X, y = labelled_rows(sys.argv[1:] or DEFAULT_TAGS)
    joblib.dump(fit(X, y), STAGE_MODEL_PATH)
    print("saved", STAGE_MODEL_PATH)
