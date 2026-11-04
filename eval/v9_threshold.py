"""Pick the payload detector's decision threshold on DEV data (v9), before the sealed test.

For each threshold, per request (detector alone, then the served-files rule, as in the pipeline):
  - SR-BH held-out DEV days: recall vs CRS, false alarms on CRS-normal; the false alarms are
    split into "probe-like" (backup / archive / config file names, TRACE / OPTIONS / other
    unusual methods), which CRS may have missed, and the rest;
  - zanbil DEV lines 3,000,001-3,200,000 (real shop): share flagged;
  - Glastopf DEV months from 2015-01-01 (honeypot): share of IPs flagged;
  - lab run7 (opened): recall on payload attacks and false alarms on normal users' requests.
The payload rules are one fixed row. Nothing here reads data/sealed/ (run7 lab files are
data/raw + data/labels).

    python -m eval.v9_threshold models/detector_v9_holdout2.joblib
"""
import re
import sys
from itertools import islice
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

from backend.app.log_parser import decode, parse_log
from eval.rules import rule_predict
from ml.detector import served_files, to_frame

V9 = Path("data/processed/v9")
OUT = Path("results/final_v9/threshold")
THRESHOLDS = [0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 0.95]
SRBH_HOLDOUT = ["2020-07-19", "2020-07-23", "2020-07-24"]
ZANBIL, ZANBIL_FROM, ZANBIL_N = Path("data/raw/zanbil_access.log"), 3_000_000, 200_000
LAB_SITES = ["juiceshop", "dvwa", "bwapp", "mutillidae", "dvna", "vampi", "dvga", "webgoat"]
PAYLOAD_TYPES = {"sqli", "xss", "traversal", "cmdi", "ssrf", "xxe", "ssti", "nosql", "log4shell", "ldap", "xpath"}
PROBE = re.compile(r"(?:\.(?:bak|old|orig|save|swp|tmp|zip|tar|tgz|gz|rar|7z|sql|conf|ini|env|log)|~)$", re.I)
ODD_METHODS = {"TRACE", "TRACK", "OPTIONS", "CONNECT", "PROPFIND", "DEBUG", "PUT", "DELETE"}


def md(t):
    t = t.astype(object).where(t.notna(), "").astype(str)
    return "\n".join(["| " + " | ".join(t.columns) + " |", "|" + "---|" * len(t.columns)]
                     + ["| " + " | ".join(r) + " |" for r in t.values])


def scored(model, df):
    """(X, proba) once per data set; thresholds are applied afterwards."""
    X = to_frame(df["method"], df["path"], df["body"])
    return X, model.predict_proba(X)[:, 1]


def decide(df, X, proba, thr):
    pred = (proba >= thr).astype(int)
    pred[np.asarray(served_files(df, X, pred))] = 0
    return pred == 1


def num(d):
    for c in ("status", "size"):
        d[c] = pd.to_numeric(d[c], errors="coerce").fillna(0).astype(int)
    return d.reset_index(drop=True)


def main(argv):
    model = joblib.load(argv[0] if argv else "models/detector_v9_holdout2.joblib")
    sets = {}
    s = num(pd.read_csv(V9 / "srbh_dev.csv", dtype=str, keep_default_na=False))
    sets["srbh"] = s[s["timestamp"].str[:10].isin(SRBH_HOLDOUT)].reset_index(drop=True)
    g = num(pd.read_csv(V9 / "glastopf_dev.csv", dtype=str, keep_default_na=False))
    sets["glastopf"] = g[g["timestamp"].str[:10] >= "2015-01-01"].reset_index(drop=True)
    if ZANBIL.exists():
        with open(ZANBIL, "rb") as f:
            z = pd.DataFrame(parse_log(decode(b"".join(islice(f, ZANBIL_FROM, ZANBIL_FROM + ZANBIL_N))))[0])
        if "body" not in z:
            z["body"] = ""
        sets["zanbil"] = num(z)
    from eval.match_labels import match
    labs = []
    for site in LAB_SITES:
        pre = "" if site == "juiceshop" else site + "_"
        log, lab = f"data/raw/{site}_generated_run7.log", f"data/labels/requests_{pre}run7.csv"
        if Path(log).exists() and Path(lab).exists():
            d, _ = match(log, lab)
            labs.append(d.assign(site=site))
    if labs:
        lab = pd.concat(labs, ignore_index=True)
        lab["attack_type"] = lab["attack_type"].fillna("")
        sets["lab"] = num(lab)
    sc = {k: scored(model, d) for k, d in sets.items()}
    print("scored:", {k: len(d) for k, d in sets.items()}, flush=True)

    s = sets["srbh"]
    att = (s["label"] == "1").values
    probe = (s["path"].str.split("?").str[0].str.contains(PROBE) | s["method"].str.upper().isin(ODD_METHODS)).values
    if "lab" in sets:
        L = sets["lab"]
        l_pay = L["attack_type"].isin(PAYLOAD_TYPES).values
        l_attacker = L.groupby("ip")["attack_type"].transform(lambda x: (x != "").any()).values
    rows = []
    for thr in THRESHOLDS + ["payload rules"]:
        r = {"threshold": thr}
        for k, d in sets.items():
            X, p = sc[k]
            flag = rule_predict(d["method"], d["path"], d["body"]).astype(bool) if thr == "payload rules" else decide(d, X, p, thr)
            flag = np.asarray(flag)
            if k == "srbh":
                r["SR-BH recall"] = round(float(flag[att].mean()), 3)
                r["SR-BH FA"] = round(float(flag[~att].mean()), 4)
                r["SR-BH FA probe-like"] = round(float((flag & probe)[~att].mean()), 4)
                r["SR-BH FA other"] = round(float((flag & ~probe)[~att].mean()), 4)
            elif k == "zanbil":
                r["zanbil flagged"] = round(float(flag.mean()), 5)
            elif k == "glastopf":
                r["Glastopf IPs flagged"] = round(float(pd.Series(flag).groupby(d["ip"]).max().mean()), 3)
            elif k == "lab":
                r["lab payload recall"] = round(float(flag[l_pay].mean()), 3)
                r["lab FA normal users"] = int(flag[~l_attacker].sum())
        rows.append(r)
        print(r, flush=True)
    T = pd.DataFrame(rows)
    OUT.mkdir(parents=True, exist_ok=True)
    T.to_csv(OUT / "threshold_curve.csv", index=False)
    (OUT / "THRESHOLD.md").write_text("\n".join([
        f"# Detector threshold on DEV data: `{argv[0] if argv else 'models/detector_v9_holdout2.joblib'}`", "",
        f"SR-BH held-out days {', '.join(SRBH_HOLDOUT)}; zanbil lines 3,000,001-3,200,000; Glastopf from 2015-01-01; lab run7.",
        "Per request, detector + served-files rule, no sessions. FA probe-like = CRS-normal requests for backup/archive/config "
        "file names or with unusual methods: CRS may have missed these, so part of that column may be real attacks.", "",
        md(T), ""]), encoding="utf-8")
    print("written", OUT / "THRESHOLD.md")


if __name__ == "__main__":
    main(sys.argv[1:])
