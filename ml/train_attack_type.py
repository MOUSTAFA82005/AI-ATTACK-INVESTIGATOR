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
Missing files are skipped. Each class gets the same weight.
"""
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


def main():
    rows = httpparams() + ecml() + newer_families() + ffuf_scan()
    m, p, b, t = map(list, zip(*rows))
    y = np.array([CLASSES.index(c) for c in t])
    print("training on", pd.Series(t).value_counts().to_dict())
    model = XGBClassifier(n_estimators=300, max_depth=6, learning_rate=0.1, tree_method="hist",
                          n_jobs=2, random_state=0)
    model.fit(type_features(m, p, b), y, sample_weight=compute_sample_weight("balanced", y))
    TYPE_MODEL_PATH.parent.mkdir(exist_ok=True)
    joblib.dump(model, TYPE_MODEL_PATH)
    print("saved", TYPE_MODEL_PATH)


if __name__ == "__main__":
    main()
