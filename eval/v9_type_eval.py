"""Attack type on SR-BH held-out DEV days (v9): agreement with CRS.

SR-BH's type labels come from the ModSecurity CRS rules (CAPEC families), so this measures
agreement with CRS, not truth (PREREGISTRATION v9, circularity note). Only attacks with ONE
family that maps to our types (sqli, traversal, cmdi) and that carry a payload; distinct requests.

    python -m eval.v9_type_eval                                          # models/attack_type.joblib
    python -m eval.v9_type_eval --type models/attack_type_v9.joblib --name v9
"""
import argparse
from pathlib import Path

import joblib
import pandas as pd

from ml.attack_type import attack_types, rule_types
from ml.detector import has_payload, to_frame

HOLDOUT = "2020-07-19,2020-07-23,2020-07-24"
MAP = {"sqli": "sqli", "traversal": "traversal", "cmdi": "cmdi"}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--type", default="models/attack_type.joblib")
    ap.add_argument("--name", default="current")
    ap.add_argument("--days", default=HOLDOUT)
    args = ap.parse_args()
    days = args.days.split(",")
    d = pd.read_csv("data/processed/v9/srbh_dev.csv", usecols=["timestamp", "method", "path", "body", "label", "families"],
                    dtype=str, keep_default_na=False)
    d = d[(d["label"] == "1") & d["timestamp"].str[:10].isin(days) & d["families"].isin(MAP)]
    d = d.drop_duplicates(["method", "path", "body"])
    d = d[has_payload(to_frame(d["method"], d["path"], d["body"])).values].reset_index(drop=True)
    model = joblib.load(args.type)
    d["truth"] = d["families"].map(MAP)
    d["ML"] = attack_types(d["method"], d["path"], d["body"], model)
    d["rules"] = rule_types(d["method"], d["path"], d["body"])
    rows = []
    for t, g in list(d.groupby("truth")) + [("all", d)]:
        rows.append({"CRS type": t, "requests": len(g),
                     "ML agrees": round(float((g["ML"] == g["truth"]).mean()), 3),
                     "rules agree": round(float((g["rules"] == g["truth"]).mean()), 3)})
    T = pd.DataFrame(rows)
    C = pd.crosstab(d["truth"], d["ML"])
    print(T.to_string(index=False)); print(C.to_string())
    out = Path("results/final_v9/type_dev") / args.name
    out.mkdir(parents=True, exist_ok=True)
    T.to_csv(out / "type_srbh.csv", index=False)
    C.to_csv(out / "confusion_ml.csv")
    print("written", out)


if __name__ == "__main__":
    main()
