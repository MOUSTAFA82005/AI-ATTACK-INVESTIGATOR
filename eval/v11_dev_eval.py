"""
v11 dev check on Biblio-US17 (results/final_v11/PREREGISTRATION.md). DEV data only (data/processed/v11, from
eval/v11_convert.py). The sealed part is never read here.

    python -m eval.v11_dev_eval --split holdout --model models/detector.joblib --name v10
    python -m eval.v11_dev_eval --split holdout --model models/detector_v11_try1.joblib --name v11_try1

Writes results/final_v11/dev/<name>_<split>.md: payload rules and the given detector at 0.7 and 0.8.
- recall on LVL1 attacks: per unique (method, path), and weighted by the raw rows each one stands for
- false alarms on the clean sample: per row, and per unique path
- recall on LVL2/3 rows (secondary)
"""
import argparse
import re

import joblib
import pandas as pd

from eval.rules import rule_predict
from ml.detector import ROOT, to_frame

V11 = ROOT / "data" / "processed" / "v11"
OUT = ROOT / "results" / "final_v11" / "dev"


def family(method, path):
    """Attack family key (Amendment 1): method + first two path segments, no query, escape runs -> %, digits -> 0."""
    p = re.sub(r"(%[0-9A-Fa-f]{2})+", "%", path.split("?")[0])
    p = re.sub(r"[0-9]+", "0", p)
    return f"{method} " + "/".join(p.split("/")[:3])[:50]


def macro(df, f):
    """Recall per family, averaged over families (each family counts once)."""
    return df.assign(f=f.values, fam=[family(m, p) for m, p in zip(df["method"], df["path"])]).groupby("fam")["f"].mean().mean()


def load(name, split):
    df = pd.read_csv(V11 / f"biblio_dev_{name}.csv", dtype=str, keep_default_na=False)
    df = df[df["split"] == split].reset_index(drop=True)
    df["count"] = df["count"].astype(int)
    return df


def flags(df, model, threshold):
    if model is None:
        return pd.Series(rule_predict(df["method"].tolist(), df["path"].tolist(), [""] * len(df)), dtype=bool)
    p = model.predict_proba(to_frame(df["method"], df["path"], [""] * len(df)))[:, 1]
    return pd.Series(p >= threshold)


def row(name, att, cln, fp, lvl, f_att, f_cln, f_fp, f_lvl):
    unique_fa = cln.assign(f=f_cln.values).groupby("path")["f"].max().mean()
    return (f"| {name} | {macro(att, f_att):.4f} | {f_att.mean():.4f} | "
            f"{(f_att * att['count']).sum() / att['count'].sum():.4f} | "
            f"{f_cln.mean():.4f} | {unique_fa:.4f} | {f_fp.mean():.4f} | {f_lvl.mean():.4f} |")


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--split", default="holdout", choices=["train", "holdout"])
    ap.add_argument("--model", default=str(ROOT / "models" / "detector.joblib"))
    ap.add_argument("--name", default="v10")
    args = ap.parse_args(argv)
    att, cln, lvl = load("attack", args.split), load("clean", args.split), load("lvl234", args.split)
    fp = load("fp", args.split)
    model = joblib.load(args.model)
    lines = [f"# Biblio-US17 dev check: {args.name}, split {args.split}", "",
             f"Unique LVL1 attacks {len(att)} (raw rows {att['count'].sum()}), clean sample {len(cln)} rows "
             f"({cln['path'].nunique()} unique paths), signature false positives {len(fp)} unique, "
             f"LVL2/3 unique {len(lvl)}, attack families {att.assign(k=[family(m, p) for m, p in zip(att['method'], att['path'])])['k'].nunique()}.",
             "",
             "| detector | recall (macro over families, headline) | recall (unique) | recall (raw-weighted) | FA clean (rows) "
             "| FA clean (unique paths) | FA on signature false positives | LVL2/3 recall |",
             "|---|---|---|---|---|---|---|---|",
             row("payload rules", att, cln, fp, lvl, *(flags(d, None, 0) for d in (att, cln, fp, lvl)))]
    for t in (0.7, 0.8):
        lines.append(row(f"{args.name} @{t}", att, cln, fp, lvl, *(flags(d, model, t) for d in (att, cln, fp, lvl))))
    OUT.mkdir(parents=True, exist_ok=True)
    out = OUT / f"{args.name}_{args.split}.md"
    out.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))
    # Misses and false alarms for the dev look (real paths: stay in data/, never committed).
    f_att, f_cln = flags(att, model, 0.7), flags(cln, model, 0.7)
    att[~f_att.values].to_csv(V11 / f"look_{args.name}_{args.split}_missed.csv", index=False)
    cln[f_cln.values].to_csv(V11 / f"look_{args.name}_{args.split}_fa.csv", index=False)


if __name__ == "__main__":
    main()
