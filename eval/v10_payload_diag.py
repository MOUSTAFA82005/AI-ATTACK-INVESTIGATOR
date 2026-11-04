"""
v10 DEV diagnosis of two payload-detector problems seen in the v9 sealed test, on ModSec-WP (now dev data):
the WordPress login shortcut and the RCE recall drop. Aggregates only (no request text).

    python -m eval.v10_payload_diag      -> results/final_v10/dev/PAYLOAD_DIAG.md
"""
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

from ml.detector import DETECTOR_THRESHOLD, MODEL_PATH, signal_columns, to_frame

CONV = Path("data/processed/v9/sealed")
OUT = Path("results/final_v10/dev")


def md(t):
    t = t.astype(object).where(t.notna(), "").astype(str)
    return "\n".join(["| " + " | ".join(map(str, t.columns)) + " |", "|" + "---|" * len(t.columns)]
                     + ["| " + " | ".join(r) + " |" for r in t.values])


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    d = pd.read_csv(CONV / "modsecwp.csv", dtype=str, keep_default_na=False)
    det = joblib.load(MODEL_PATH)
    X = to_frame(d["method"], d["path"], d["body"])
    p = det.predict_proba(X)[:, 1]
    fam = d["families"].str.lower()
    normal = d["label"].isin(["0", "normal"])
    page = d["path"].str.split("?").str[0].str.lower()
    login = (d["method"].str.upper() == "POST") & page.str.contains("wp-login")
    groups = {
        "normal login POSTs": normal & login,
        "normal, other": normal & ~login,
        "bruteforce login POSTs": fam.str.contains("brute") & login,
        "rce": fam.str.contains("rce"),
        "sqli": fam.str.contains("sqli"),
        "xss": fam.str.contains("xss"),
        "fileinclusion": fam.str.contains("fileinclusion|file"),
    }
    rows, sig = [], []
    sc = signal_columns(X)
    for name, m in groups.items():
        if not m.any():
            continue
        q = p[m.values]
        rows.append({"rows": name, "n": int(m.sum()), "flag@0.5": round(float((q >= .5).mean()), 3),
                     "flag@0.7": round(float((q >= DETECTOR_THRESHOLD).mean()), 3), "flag@0.8": round(float((q >= .8).mean()), 3),
                     "share with any signal": round(float((X.loc[m.values, sc].sum(axis=1) > 0).mean()), 3),
                     "median proba": round(float(np.median(q)), 3)})
        fired = (X.loc[m.values, sc] > 0).mean().sort_values(ascending=False).head(8)
        sig.append({"rows": name, "top signals (share of rows)": ", ".join(f"{k} {v:.2f}" for k, v in fired.items() if v > 0)})
    # RCE caught vs missed: which signals differ
    r = groups["rce"].values
    miss, hit = r & (p < DETECTOR_THRESHOLD), r & (p >= DETECTOR_THRESHOLD)
    diff = pd.DataFrame({"missed rce": (X.loc[miss, sc] > 0).mean(), "caught rce": (X.loc[hit, sc] > 0).mean()})
    diff = diff[(diff.max(axis=1) > 0.05)].round(3).sort_values("missed rce", ascending=False).reset_index().rename(columns={"index": "signal"})
    # v8 on the same rows (from the sealed run)
    v8 = pd.read_csv(CONV / "pred_v8_modsecwp.csv.gz", usecols=["proba"])["proba"].values
    v9 = pd.read_csv(CONV / "pred_v9_modsecwp.csv.gz", usecols=["proba"])["proba"].values
    same_order = len(v8) == len(d) and np.allclose(v9, p, atol=1e-4)
    cmp = []
    if same_order:
        for name in ["rce", "normal login POSTs", "bruteforce login POSTs"]:
            m = groups[name].values
            cmp.append({"rows": name, "v8 flag@0.5": round(float((v8[m] >= .5).mean()), 3), "v9 flag@0.7": round(float((p[m] >= .7).mean()), 3),
                        "v9 flag@0.5": round(float((p[m] >= .5).mean()), 3)})
    text = ["# v10 dev: payload detector on ModSec-WP (v9 model, aggregates only)", "", md(pd.DataFrame(rows)), "",
            md(pd.DataFrame(sig)), "", "## RCE: signals in missed vs caught rows", md(diff), "",
            "## v8 vs v9 on the same rows" + ("" if same_order else " (row order differs: skipped)"),
            md(pd.DataFrame(cmp)) if cmp else ""]
    (OUT / "PAYLOAD_DIAG.md").write_text("\n".join(text), encoding="utf-8")
    print("\n".join(text))


if __name__ == "__main__":
    main()
