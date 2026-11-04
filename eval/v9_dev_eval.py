"""
v9 dev check: payload detectors compared PER REQUEST on DEV data held out from their training.
Nothing here reads data/sealed/.

    python -m eval.v9_dev_eval models/detector.joblib models/detector_v9_holdout.joblib
    python -m eval.v9_dev_eval --srbh-holdout=2020-07-19,2020-07-23,2020-07-24 models/detector.joblib models/x.joblib

- SR-BH held-out DEV days (default 20-24 Jul 2020): recall vs CRS labels, false alarms on CRS-normal.
- Glastopf held-out DEV months (default 2015-01..2015-03): share of requests and of IPs flagged.
- zanbil DEV lines 3,000,001-3,200,000 (real shop, normal): share flagged = false-alarm rate.
The payload rules are shown as the baseline. Writes results/final_v9/dev_eval.md.
"""
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
OUT = Path("results/final_v9")
SRBH_HOLDOUT = ["2020-07-20", "2020-07-21", "2020-07-22", "2020-07-23", "2020-07-24"]
GLASTOPF_FROM = "2015-01-01"
ZANBIL, ZANBIL_FROM, ZANBIL_N = Path("data/raw/zanbil_access.log"), 3_000_000, 200_000


def md(t):
    t = t.astype(object).where(t.notna(), "").astype(str)
    lines = ["| " + " | ".join(t.columns) + " |", "|" + "---|" * len(t.columns)]
    return "\n".join(lines + ["| " + " | ".join(r) + " |" for r in t.values])


def predict(model, df):
    X = to_frame(df["method"], df["path"], df["body"])
    pred = (model.predict_proba(X)[:, 1] >= 0.5).astype(int)
    pred[np.asarray(served_files(df, X, pred))] = 0
    return pred


def load(name, cols=None):
    d = pd.read_csv(V9 / name, dtype=str, keep_default_na=False)
    for c in ("status", "size"):
        d[c] = pd.to_numeric(d[c], errors="coerce").fillna(0).astype(int)
    return d.reset_index(drop=True)


def main(argv):
    holdout = [a.split("=", 1)[1] for a in argv if a.startswith("--srbh-holdout=")]
    if holdout:
        SRBH_HOLDOUT[:] = holdout[0].split(",")
    paths = [a for a in argv if not a.startswith("--")]
    models = {Path(p).stem: joblib.load(p) for p in paths}
    out = []

    s = load("srbh_dev.csv")
    s = s[s["timestamp"].str[:10].isin(SRBH_HOLDOUT)].reset_index(drop=True)
    att = s["label"] == "1"
    preds = {**{k: predict(m, s) for k, m in models.items()}, "payload rules": rule_predict(s["method"], s["path"], s["body"]).astype(int)}
    rows = []
    for k, p in preds.items():
        p = np.asarray(p) == 1
        rows.append({"detector": k, "attacks": int(att.sum()), "recall vs CRS": round(float(p[att].mean()), 3) if att.any() else None,
                     "normals": int((~att).sum()), "false alarms": round(float(p[~att].mean()), 4)})
    out += [f"## SR-BH held-out DEV days {SRBH_HOLDOUT[0]}..{SRBH_HOLDOUT[-1]} (per request)", "", md(pd.DataFrame(rows)), ""]
    fam = s[att].assign(fam=s.loc[att, "families"].str.split("|")).explode("fam")
    ft = fam.groupby("fam").size().rename("requests").to_frame()
    for k, p in preds.items():
        ft[k] = pd.Series(np.asarray(p)[fam.index] == 1, index=fam.index).groupby(fam["fam"]).mean().round(3)
    out += [md(ft.sort_values("requests", ascending=False).reset_index()), ""]

    g = load("glastopf_dev.csv")
    g = g[g["timestamp"].str[:10] >= GLASTOPF_FROM].reset_index(drop=True)
    rows = []
    for k, p in {**{k: predict(m, g) for k, m in models.items()}, "payload rules": rule_predict(g["method"], g["path"], g["body"]).astype(int)}.items():
        p = pd.Series(np.asarray(p) == 1)
        rows.append({"detector": k, "requests": len(g), "requests flagged": round(float(p.mean()), 3),
                     "IPs": g["ip"].nunique(), "IPs flagged": round(float(p.groupby(g["ip"]).max().mean()), 3)})
    out += [f"## Glastopf held-out DEV months from {GLASTOPF_FROM} (payload detector alone, no sessions)", "",
            md(pd.DataFrame(rows)), ""]

    if ZANBIL.exists():
        with open(ZANBIL, "rb") as f:
            z = pd.DataFrame(parse_log(decode(b"".join(islice(f, ZANBIL_FROM, ZANBIL_FROM + ZANBIL_N))))[0])
        rows = []
        for k, p in {**{k: predict(m, z) for k, m in models.items()}, "payload rules": rule_predict(z["method"], z["path"], z["body"]).astype(int)}.items():
            rows.append({"detector": k, "requests": len(z), "flagged (false alarms)": round(float(np.mean(np.asarray(p) == 1)), 5)})
        out += ["## zanbil DEV lines 3,000,001-3,200,000 (real shop, normal traffic)", "", md(pd.DataFrame(rows)), ""]

    text = "\n".join(["# v9 dev check (payload detector, per request)", "", "DEV data only, held out from training.", ""] + out)
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "dev_eval.md").write_text(text, encoding="utf-8")
    print(text)


if __name__ == "__main__":
    main(sys.argv[1:] if len(sys.argv) > 1 else ["models/detector.joblib"])
