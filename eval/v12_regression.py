"""
v12 regression on the old real-traffic sets (results/final_v12/PREREGISTRATION.md, step 3). Dev use only: every set
here was opened by an earlier sealed run, so these numbers only check that v12 is not worse than v11.

    python -m eval.v12_regression real --tag v12                  # this tree (v12 code, v11 models)
    (in a worktree of c58e161 = v11 code, same models folder content:)
    python "<repo>/eval/v12_regression.py" real --tag v11 --repo "<repo>"
    python -m eval.v12_regression biblio --tag v12  /  (worktree) ... biblio --tag v11 --repo "<repo>"
    python -m eval.v12_regression report                          # -> results/final_v12/regression/REGRESSION.md

Real sets: the converted v10 sealed rows (ClarkNet, USask, NASA, zanbil, secrepo Oct days), whole v10 pipeline.
Biblio: the converted v11 sealed rows (payload layer). Lab sites + tools: eval/v9_lab_regression --name v12.
Predictions with real lines stay in data/processed/v12/regression (git-ignored); only numbers go to results/.
"""
import argparse
import json
import os
import sys
import time
from pathlib import Path

import pandas as pd

PRED = Path("data/processed/v12/regression")
OUT = Path("results/final_v12/regression")
ML = "model + sessions"


def real(tag, repo):
    import eval.v10_sealed_test as v10
    conv, out, t0 = Path(repo) / v10.CONV, Path(repo) / PRED, time.time()
    out.mkdir(parents=True, exist_ok=True)
    for src in v10.SOURCES:
        p = conv / f"{src}.csv"
        if not p.exists():
            print("  missing", p)
            continue
        df = pd.read_csv(p, dtype=str, keep_default_na=False)
        parts = []
        for key, g in df.groupby("source", sort=True):
            r = v10._pipeline(g.reset_index(drop=True))
            parts.append(r[[c for c in ["source", "label", "ip", "model", ML] if c in r]])
            print(f"  {tag} {src} {key}: {len(g)} rows ({time.time() - t0:.0f}s)", flush=True)
        pd.concat(parts, ignore_index=True).to_csv(out / f"pred_{tag}_{src}.csv.gz", index=False)


def biblio(tag, repo):
    import joblib
    import eval.v11_sealed_test as v11
    from eval.v11_dev_eval import flags
    v11.CONV = Path(repo) / v11.CONV
    att, cln, fp, lvl = (v11._load(n) for n in ("attack", "clean", "fp", "lvl234"))
    model = joblib.load(Path(repo) / v11.MODELS["v11"])
    r = v11._stats(att, cln, fp, lvl, lambda d: flags(d, model, 0.7))
    out = Path(repo) / PRED
    out.mkdir(parents=True, exist_ok=True)
    (out / f"biblio_{tag}.json").write_text(json.dumps({k: float(v) for k, v in r.items()}))
    print(tag, r)


def report():
    import eval.v10_sealed_test as v10
    rows = []
    for src in v10.SOURCES:
        P = {t: PRED / f"pred_{t}_{src}.csv.gz" for t in ("v11", "v12")}
        if not all(p.exists() for p in P.values()):
            continue
        r = {"log": v10.TITLES[src]}
        for t, p in P.items():
            g = pd.read_csv(p, keep_default_na=False, dtype={"ip": str})
            n = g["label"] == "normal"
            r[f"{t} payload FA"] = round(float((g.loc[n, "model"] == 1).mean()), 5)
            r[f"{t} + sessions FA"] = round(float((g.loc[n, ML] == 1).mean()), 5)
            r[f"{t} IPs flagged"] = int(g.loc[g[ML] == 1, "ip"].nunique())
        rows.append(r)
    md = ["# v12 regression (dev use, sets opened before)", "",
          "Pass rule (PREREGISTRATION step 3): v12 not worse than v11 by more than 0.005 on any headline number.", ""]
    if rows:
        t = pd.DataFrame(rows).astype(str)
        md += ["## Real traffic (false alarms on rule-normal requests)", "",
               "| " + " | ".join(t.columns) + " |", "|" + "---|" * len(t.columns)]
        md += ["| " + " | ".join(v) + " |" for v in t.values]
        md += [""]
    B = {t: PRED / f"biblio_{t}.json" for t in ("v11", "v12")}
    if all(p.exists() for p in B.values()):
        b = {t: json.loads(p.read_text()) for t, p in B.items()}
        md += ["## Biblio-US17 sealed rows (payload layer, 0.7)", "", "| | " + " | ".join(b["v11"]) + " |",
               "|---|" + "---|" * len(b["v11"])]
        md += [f"| {t} | " + " | ".join(f"{v:.5f}" for v in b[t].values()) + " |" for t in b]
        md += [""]
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "REGRESSION.md").write_text("\n".join(md), encoding="utf-8")
    print("\n".join(md))


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("step", choices=["real", "biblio", "report"])
    ap.add_argument("--tag", default="v12", choices=["v12", "v11"])
    ap.add_argument("--repo", default=".")
    a = ap.parse_args(argv)
    if a.step == "real":
        real(a.tag, a.repo)
    elif a.step == "biblio":
        biblio(a.tag, a.repo)
    else:
        report()


if __name__ == "__main__":
    sys.path = [os.getcwd()] + [p for p in sys.path if Path(p).resolve() != Path(__file__).resolve().parent]
    main()
