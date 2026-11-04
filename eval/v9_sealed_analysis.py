"""
Post-hoc analysis of the v9 sealed test (ANALYSIS ONLY: nothing here changes a model, a rule or a reported number).
Prints aggregates only (no request, no IP). Sites are numbered, not named.

    python -m eval.v9_sealed_analysis
Writes results/final_v9/sealed/ANALYSIS.md
"""
from pathlib import Path

import joblib
import numpy as np
import pandas as pd

CONV = Path("data/processed/v9/sealed")
OUT = Path("results/final_v9/sealed")
ML, RULES = "model + sessions", "rules + rule sessions"


def md(t):
    t = t.astype(object).where(t.notna(), "").astype(str)
    return "\n".join(["| " + " | ".join(t.columns) + " |", "|" + "---|" * len(t.columns)]
                     + ["| " + " | ".join(r) + " |" for r in t.values])


def ip_concentration(p, extra=None):
    d = pd.read_csv(p, usecols=lambda c: c in {"label", "ip", "session", ML, RULES, "org", "site", "group"},
                    dtype=str, keep_default_na=False)
    rows = []
    groups = d.groupby(extra, sort=True) if extra else [("all", d)]
    for i, (k, g) in enumerate(groups, 1):
        n = g["label"] == "normal"
        top = g["ip"].value_counts()
        sess = g.loc[n, "session"].value_counts()
        rows.append({"part": f"{i} ({k.split('/')[0]})" if isinstance(k, str) else i,
                     "requests": len(g), "normal": int(n.sum()), "distinct IPs": int(top.size),
                     "share of requests from top IP": round(float(top.iloc[0] / len(g)), 3) if len(g) else None,
                     "share of normal requests in the largest session": round(float(sess.iloc[0] / n.sum()), 3) if n.any() else None,
                     "v9 sessions FA": round(float((g.loc[n, ML] == "1").mean()), 3) if n.any() else None,
                     "rules sessions FA": round(float((g.loc[n, RULES] == "1").mean()), 3) if n.any() else None})
    return pd.DataFrame(rows)


def login_shortcut():
    """Does the v9 payload model flag every WordPress login POST (also normal ones) in ModSec-WP?"""
    from ml.detector import MODEL_PATH, DETECTOR_THRESHOLD, to_frame
    d = pd.read_csv(CONV / "modsecwp.csv", dtype=str, keep_default_na=False)
    login = d["path"].str.contains("wp-login", case=False) & (d["method"] == "POST")
    m = joblib.load(MODEL_PATH)
    rows = []
    for name, sel in (("normal login POSTs", login & (d["families"] == "normal")),
                      ("bruteforce login POSTs", login & (d["families"] == "bruteforce")),
                      ("bruteforce, not a login POST", ~login & (d["families"] == "bruteforce"))):
        g = d[sel]
        p = (m.predict_proba(to_frame(g["method"], g["path"], g["body"]))[:, 1] >= DETECTOR_THRESHOLD) if len(g) else np.array([])
        rows.append({"ModSec-WP rows": name, "requests": len(g), "v9 payload flags": round(float(p.mean()), 3) if len(g) else None,
                     "with a body": round(float((g["body"] != "").mean()), 3) if len(g) else None})
    return pd.DataFrame(rows)


def main():
    out = ["# v9 sealed test: post-hoc analysis (no changes made)", ""]
    out += ["## Why the session layer flags normal traffic on the Indonesian sites", "",
            md(ip_concentration(CONV / "pred_v9_indonesia.csv.gz", "group")), ""]
    out += ["## Same for ModSec-WP", "", md(ip_concentration(CONV / "pred_v9_modsecwp.csv.gz")), ""]
    out += ["## Brute force caught by the payload model in ModSec-WP: login shortcut?", "", md(login_shortcut()), ""]
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "ANALYSIS.md").write_text("\n".join(out), encoding="utf-8")
    print("\n".join(out))


if __name__ == "__main__":
    main()
