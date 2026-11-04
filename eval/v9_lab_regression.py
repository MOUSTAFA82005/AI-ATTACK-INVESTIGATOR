"""Lab regression for v9 (dev data only).

Re-runs the run7 lab sites and tool logs (already opened, so dev data now) with the
current code and a chosen detector model, writes to results/final_v9/lab_regression/
(never over the run7 results), and compares with the frozen run7 numbers.

Usage:
    python -m eval.v9_lab_regression                       # current models/detector.joblib
    python -m eval.v9_lab_regression --model models/detector_v9.joblib --name v9
"""
import argparse
import sys
from pathlib import Path

import pandas as pd

import eval.final_test as ft
import eval.run7_final as r7

BASE = Path("results/final_v8/run7")
ML, RULES = r7.ML, r7.RULES


def md(df):
    df = df.astype(object).where(df.notna(), "")
    cols = [str(c) for c in df.columns]
    out = ["| " + " | ".join(cols) + " |", "|" + "---|" * len(cols)]
    out += ["| " + " | ".join(str(v) for v in row) + " |" for row in df.values]
    return "\n".join(out)


def compare(new, old, keys, cols):
    m = new[keys + cols].merge(old[keys + cols], on=keys, how="left", suffixes=(" now", " run7"))
    order = keys + [f"{c} {s}" for c in cols for s in ("run7", "now")]
    return m[[c for c in order if c in m.columns]]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", default=None, help="detector model path (default: models/detector.joblib)")
    ap.add_argument("--context", default=None, help="context model path (default: models/context.joblib)")
    ap.add_argument("--type", default=None, help="attack-type model path (default: models/attack_type.joblib)")
    ap.add_argument("--stage", default=None, help="stage model path (default: models/stage.joblib)")
    ap.add_argument("--name", default="current")
    ap.add_argument("--parts", default="lab,tools", help="add ,real for zanbil 9.0-9.2M + secrepo (opened in run7)")
    ap.add_argument("--tools-dir", default="data/sealed/run7_tools")
    args = ap.parse_args()
    out = Path("results/final_v9/lab_regression") / args.name
    r7.OUT = out
    # the real-log part writes blind samples of real log lines: keep them in data/ (git-ignored),
    # never over the run7 hand-label files and never under results/
    r7.HAND = Path("data/processed/v9/regression_hand") / args.name
    if args.model:
        ft.MODEL_PATH = args.model
    if args.type:
        import joblib
        type_model = joblib.load(args.type)
        ft.load_type_model = lambda: type_model
    if args.stage:
        import joblib
        import ml.stage
        stage_model = joblib.load(args.stage)
        ml.stage.load_stage_model = lambda path=None: stage_model
    if args.context:
        import joblib
        model = joblib.load(args.context)
        ft.load_context_model = lambda: model
    sys.argv = ["run7_final", "--no-verify", "--parts", args.parts, "--tools-dir", args.tools_dir]
    r7.main()

    md_out = [f"# Lab regression: {args.name}", "",
              f"Detector: `{ft.MODEL_PATH}`, context: `{args.context or 'models/context.joblib'}`, type: `{args.type or 'models/attack_type.joblib'}`, stage: `{args.stage or 'models/stage.joblib'}`. Dev data (run7 is opened). run7 = frozen v8 numbers.", ""]
    if "lab" in args.parts:
        L, L0 = pd.read_csv(out / "lab_sites.csv"), pd.read_csv(BASE / "lab_sites.csv")
        md_out += ["## Lab sites", "", md(compare(L, L0, ["site"], ["recall ML", "FA normal users ML",
                   "FA in attacker sessions ML", "type acc ML", "defence action right ML"])), "",
                   "### Stage", "", md(compare(L, L0, ["site"], [c for c in ["stage acc ML", "furthest ML"] if c in L and c in L0])), ""]
        T, T0 = pd.read_csv(out / "lab_recall_by_type.csv"), pd.read_csv(BASE / "lab_recall_by_type.csv")
        bt = compare(T, T0, ["site", "attack_type"], [ML])
        bt["drop"] = (bt[f"{ML} run7"] - bt[f"{ML} now"]).round(3)
        md_out += ["## Recall by attack type (ML)", "", md(bt), "",
                   "Drops of 0.05 or more:", "", md(bt[bt["drop"] >= 0.05]) if (bt["drop"] >= 0.05).any() else "none", ""]
        bf = bt[bt["attack_type"].str.contains("brute", case=False, na=False)]
        md_out += ["## Brute force (must stay caught by sessions)", "", md(bf) if len(bf) else "no brute force rows", ""]
    if "tools" in args.parts and (out / "tools.csv").exists():
        Tt, Tt0 = pd.read_csv(out / "tools.csv"), pd.read_csv(BASE / "tools.csv")
        md_out += ["## Tools", "", md(compare(Tt, Tt0, ["tool", "site"], ["caught ML", "normal users flagged ML"])), ""]
    if "real" in args.parts and (out / "real_logs.csv").exists():
        R, R0 = pd.read_csv(out / "real_logs.csv"), pd.read_csv(BASE / "real_logs.csv")
        md_out += ["## Real logs (share of requests flagged)", "",
                   md(compare(R, R0, ["log"], ["flagged ML", "flagged ML n", "sessions flagged ML"])), ""]
    (out / "REGRESSION.md").write_text("\n".join(md_out), encoding="utf-8")
    print("written", out / "REGRESSION.md")


if __name__ == "__main__":
    main()
