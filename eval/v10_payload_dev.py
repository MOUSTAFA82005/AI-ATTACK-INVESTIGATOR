"""
v10 DEV check of the payload detector: v9 model vs a v10 candidate, on data the v9 sealed test used (now dev).
Aggregates only.

    python -m eval.v10_payload_dev models/detector.joblib models/detector_v10.joblib  -> results/final_v10/dev/PAYLOAD_DEV.md
"""
import sys
from pathlib import Path

import joblib
import pandas as pd

from ml.detector import DETECTOR_THRESHOLD, to_frame
from ml.train_detector import modsecwp_half

CONV = Path("data/processed/v9/sealed")
OUT = Path("results/final_v10/dev")


def md(t):
    t = t.astype(object).where(t.notna(), "").astype(str)
    return "\n".join(["| " + " | ".join(map(str, t.columns)) + " |", "|" + "---|" * len(t.columns)]
                     + ["| " + " | ".join(r) + " |" for r in t.values])


def sets():
    m = pd.read_csv(CONV / "modsecwp.csv", dtype=str, keep_default_na=False)
    m = m[modsecwp_half(m["method"], m["path"], m["body"]) == 1]
    login = (m["method"].str.upper() == "POST") & m["path"].str.lower().str.split("?").str[0].str.contains("wp-login")
    yield "ModSec-WP half 1: normal", m[m["label"] == "0"], "flag"
    yield "ModSec-WP half 1: normal login POSTs", m[(m["label"] == "0") & login], "flag"
    for fam in ["sqli", "xss", "fileinclusion", "rce", "bruteforce"]:
        yield f"ModSec-WP half 1: {fam}", m[m["families"] == fam], "flag"
    ind = pd.read_csv(CONV / "indonesia.csv", dtype=str, keep_default_na=False, usecols=["method", "path", "body", "label"])
    ind = ind.sample(min(300_000, len(ind)), random_state=0)
    yield "Indonesian (300k sample): normal", ind[ind["label"].isin(["0", "normal"])], "flag"
    yield "Indonesian (300k sample): rule attacks", ind[~ind["label"].isin(["0", "normal"])], "flag"
    s = pd.read_csv(CONV / "srbh.csv", dtype=str, keep_default_na=False, usecols=["method", "path", "body", "label"])
    yield "SR-BH sealed days: normal", s[s["label"].isin(["0", "normal"])], "flag"
    z = pd.read_csv(CONV / "zanbil.csv", dtype=str, keep_default_na=False, usecols=["method", "path", "body", "label"])
    yield "zanbil 10.0M: all", z, "flag"
    g = pd.read_csv(CONV / "glastopf.csv", dtype=str, keep_default_na=False)
    yield "Glastopf sealed: requests", g, "flag"


def main():
    models = {Path(p).stem: joblib.load(p) for p in sys.argv[1:]}
    rows = []
    for name, d, _ in sets():
        r = {"set": name, "rows": len(d)}
        if len(d):
            X = to_frame(d["method"], d["path"], d["body"])
            for k, m in models.items():
                r[f"{k} flagged"] = round(float((m.predict_proba(X)[:, 1] >= DETECTOR_THRESHOLD).mean()), 4)
        rows.append(r)
        print(r, flush=True)
    OUT.mkdir(parents=True, exist_ok=True)
    text = "# v10 dev: payload detector, share flagged at threshold %.1f\n\n" % DETECTOR_THRESHOLD + md(pd.DataFrame(rows))
    (OUT / "PAYLOAD_DEV.md").write_text(text, encoding="utf-8")
    print(text)


if __name__ == "__main__":
    main()
