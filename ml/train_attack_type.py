"""
Train the attack-type model and save it to models/attack_type.joblib. From the repo root:

    python -m ml.train_attack_type

Public data only (never our generator, so the lab runs stay a fair test):
  - HttpParams attack values (data/raw/httpparams_train.csv). Each value is put in
    three places of a request: the query (?q=), a form body, and, for traversal and
    XSS, a path segment (also encoded twice, the usual filter bypass). The same payload
    can arrive anywhere; without this the model only knew payloads in ?q=.
  - ECML/PKDD 2007 train split (data/raw/ecml_pkdd.csv): sqli, xss, traversal, cmdi,
    ldap, xpath from another site.
  - the "train" payloads of the newer families (data/raw/new_families.csv).
  - a real ffuf directory scan (data/raw/tool_ffuf_dvwa.log) as "scan".
  - v9, with --srbh-days: SR-BH 2020 DEV days (real attacks on a real WordPress site; type =
    the CRS rule family, CAPEC). Only requests with ONE family that maps to our types (sqli,
    traversal, cmdi) and that carry a payload; distinct requests, at most SRBH_PER_TYPE each.
Missing files are skipped. Each class gets the same weight.

    python -m ml.train_attack_type --srbh-days 2020-07-17,2020-07-18,2020-07-20,2020-07-21,2020-07-22 \
        --out models/attack_type_v9.joblib
"""
import argparse
from pathlib import Path
from urllib.parse import quote

import joblib
import numpy as np
import pandas as pd
from sklearn.utils.class_weight import compute_sample_weight
from xgboost import XGBClassifier

from backend.app.log_parser import decode, parse_log
from ml import new_families
from ml.attack_type import CLASSES, TYPE_MODEL_PATH, type_features
from ml.detector import ROOT

RAW = ROOT / "data" / "raw"
ECML_CLASSES = {"SqlInjection": "sqli", "XSS": "xss", "PathTransversal": "traversal",
                "OsCommanding": "cmdi", "LdapInjection": "ldap", "XPathInjection": "xpath"}
TOOL_IP = "172.19.0.7"


def httpparams(path=RAW / "httpparams_train.csv"):
    if not path.exists():
        return []
    d = pd.read_csv(path, keep_default_na=False)
    d = d[d["label"] == "anom"]
    vals, types = list(d["payload"]), list(d["attack_type"].replace({"path-traversal": "traversal"}))
    rows = [("GET", "/?q=" + quote(v, safe=""), "", t) for v, t in zip(vals, types)]
    rows += [("POST", "/form", "q=" + quote(v, safe=""), t) for v, t in zip(vals, types)]
    for v, t in zip(vals, types):
        if t in ("traversal", "xss"):
            rows.append(("GET", "/files/" + quote(v, safe="/"), "", t))
            rows.append(("GET", "/files/" + quote(quote(v, safe=""), safe=""), "", t))
    return rows


def ecml(path=RAW / "ecml_pkdd.csv"):
    if not path.exists():
        return []
    d = pd.read_csv(path, keep_default_na=False)
    d = d[(d["split"] == "train") & d["cls"].isin(ECML_CLASSES)]
    return list(zip(d["method"], d["path"], d["body"], d["cls"].map(ECML_CLASSES)))


def newer_families():
    if not new_families.NEW_FAMILIES_CSV.exists():
        return []
    _, _, fam, reqs = new_families.load("train")
    return [(r[0], r[1], r[2], f) for r, f in zip(reqs, fam)]


def ffuf_scan(path=RAW / "tool_ffuf_dvwa.log"):
    if not path.exists():
        return []
    d = pd.DataFrame(parse_log(decode(path.read_bytes()))[0])
    d = d[d["ip"] == TOOL_IP]
    return [(m, p, b, "scan") for m, p, b in zip(d["method"], d["path"], d["body"])]


SRBH_TYPES = {"sqli": "sqli", "traversal": "traversal", "cmdi": "cmdi"}
SRBH_PER_TYPE = 5000


def srbh_rows(days, path=ROOT / "data" / "processed" / "v9" / "srbh_dev.csv"):
    """[(method, path, body, type)] of SR-BH attacks on the given days (see the note above)."""
    from ml.detector import has_payload, to_frame
    if not days or not path.exists():
        return []
    d = pd.read_csv(path, usecols=["timestamp", "method", "path", "body", "label", "families"],
                    dtype=str, keep_default_na=False)
    d = d[(d["label"] == "1") & d["timestamp"].str[:10].isin(days) & d["families"].isin(SRBH_TYPES)]
    d = d.drop_duplicates(["method", "path", "body"])
    d = d[has_payload(to_frame(d["method"], d["path"], d["body"])).values]
    d = pd.concat([g.sample(min(len(g), SRBH_PER_TYPE), random_state=0) for _, g in d.groupby("families")]) if len(d) else d
    print("SR-BH rows by type:", d["families"].value_counts().to_dict())
    return list(zip(d["method"], d["path"], d["body"], d["families"].map(SRBH_TYPES)))


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--srbh-days", default="", help="comma-separated SR-BH DEV days (YYYY-MM-DD); empty = none")
    ap.add_argument("--out", default=str(TYPE_MODEL_PATH))
    args = ap.parse_args(argv)
    days = [x for x in args.srbh_days.split(",") if x]
    rows = httpparams() + ecml() + newer_families() + ffuf_scan() + srbh_rows(days)
    m, p, b, t = map(list, zip(*rows))
    y = np.array([CLASSES.index(c) for c in t])
    print("training on", pd.Series(t).value_counts().to_dict())
    model = XGBClassifier(n_estimators=300, max_depth=6, learning_rate=0.1, tree_method="hist",
                          n_jobs=2, random_state=0)
    model.fit(type_features(m, p, b), y, sample_weight=compute_sample_weight("balanced", y))
    out = Path(args.out)
    out.parent.mkdir(exist_ok=True)
    joblib.dump(model, out)
    print("saved", out)


if __name__ == "__main__":
    main()
