"""
Train the attack-stage model (ml/stage.py) -> models/stage.joblib

Training data: lab runs whose label files carry the true stage (generator v5 reads it
from the server's whole answer). Each run goes through the same pipeline as the
backend (detector, behaviour model, attack type), and the model learns the true stage
of every request the pipeline called an attack, from what the log shows.

    python -m ml.train_stage [tag ...]      (default tags: st21 st22 st31 st32)

v9: --ait-hosts adds AIT-LDS v1.1 hosts (real nikto = recon, hydra guesses = intrusion,
web-shell upload and use = exploitation; eval/v9_convert_ait.py), at most AIT_MAX_PER_STAGE
requests per stage and host; --model / --context / --type pick the models the pipeline runs
with (the stage model learns from what they say), --out where to save:

    python -m ml.train_stage --ait-hosts cup,insect --model models/detector_v9_holdout2.joblib \
        --context models/context_v9.joblib --type models/attack_type_v9.joblib --out models/stage_v9.joblib

Runs are data/raw/<site>_generated_<tag>.log + data/labels/requests[_<site>]_<tag>.csv
for the five lab sites (Juice Shop's label files have no site prefix); missing runs are skipped.
"""
import argparse
import os

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


AIT_MAX_PER_STAGE = 3000


def ait_rows(hosts):
    import eval.final_test as ft
    from eval.v9_ait_eval import load
    X, y = [], []
    for host in hosts:
        if not os.path.exists(f"data/processed/v9/ait_{host}.csv"):
            print("skipped (missing): AIT", host)
            continue
        req, _ = ft._pipeline(load(host))
        rows = attack_rows(req) & (req["true_stage"] != "")
        F, t = stage_features(req)[rows], req.loc[rows, "true_stage"]
        keep = pd.concat([t[t == s].sample(min(int((t == s).sum()), AIT_MAX_PER_STAGE), random_state=0)
                          for s in t.unique()]).index
        X.append(F.loc[keep]), y.append(t.loc[keep])
        print("AIT", host, y[-1].value_counts().to_dict())
    return X, y


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("tags", nargs="*", default=DEFAULT_TAGS)
    ap.add_argument("--ait-hosts", default="")
    ap.add_argument("--model", default=None)
    ap.add_argument("--context", default=None)
    ap.add_argument("--type", default=None)
    ap.add_argument("--out", default=STAGE_MODEL_PATH)
    args = ap.parse_args()
    import eval.final_test as ft
    if args.model:
        ft.MODEL_PATH = args.model
    if args.context:
        _ctx = joblib.load(args.context)
        ft.load_context_model = lambda: _ctx
    if args.type:
        _typ = joblib.load(args.type)
        ft.load_type_model = lambda: _typ
    X, y = labelled_rows(args.tags or DEFAULT_TAGS)
    Xa, ya = ait_rows([h for h in args.ait_hosts.split(",") if h])
    X, y = pd.concat([X] + Xa, ignore_index=True), pd.concat([y] + ya, ignore_index=True)
    print("training on", y.value_counts().to_dict())
    joblib.dump(fit(X, y), args.out)
    print("saved", args.out)
