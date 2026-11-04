"""
v10 DEV diagnosis of session-layer false alarms (v9 models), on data that the v9 sealed test already used
(now dev for v10, see results/final_v10/PREREGISTRATION.md). Prints aggregates only (no request, no IP).

    python -m eval.v10_session_diag            -> results/final_v10/dev/SESSION_DIAG.md
"""
import sys
from pathlib import Path

import numpy as np
import pandas as pd

sys.path.insert(0, str(Path.cwd()))
from eval.v9_sealed_test import _pipeline            # noqa: E402
from ml.context_model import FEATURES, context_features   # noqa: E402

CONV = Path("data/processed/v9/sealed")
OUT = Path("results/final_v10/dev")
ML = "model + sessions"
CAP = 50_000


def md(t):
    t = t.astype(object).where(t.notna(), "").astype(str)
    return "\n".join(["| " + " | ".join(map(str, t.columns)) + " |", "|" + "---|" * len(t.columns)]
                     + ["| " + " | ".join(r) + " |" for r in t.values])


def groups():
    d = pd.read_csv(CONV / "indonesia.csv", dtype=str, keep_default_na=False)
    for i, (k, g) in enumerate(d.groupby(d["org"] + "/" + d["site"], sort=True), 1):
        n_ip = g["ip"].nunique()
        if n_ip > 100 or i in (3, 5, 13, 20):          # all real-IP sites + 4 proxy sites (fixed choice)
            yield f"indonesia {i} ({n_ip} IPs)", g.tail(CAP) if n_ip <= 100 else g
    del d
    yield "modsecwp", pd.read_csv(CONV / "modsecwp.csv", dtype=str, keep_default_na=False)
    yield "zanbil 10.0M", pd.read_csv(CONV / "zanbil.csv", dtype=str, keep_default_na=False).head(100_000)


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    summ, beh, feat, ipua = [], [], [], []
    for name, g in groups():
        g = g.reset_index(drop=True)
        req = _pipeline(g)
        X, ordered = context_features(req.assign(proba=req["proba"]))
        X = X.reindex(req.index)
        normal = req["label"] == "normal"
        flag = normal & (req["session_attack"] == 1)
        s_flag = req.loc[flag, "session"].nunique()
        s_all = req.loc[normal, "session"].nunique()
        summ.append({"group": name, "requests": len(req), "normal": int(normal.sum()),
                     "session FA": round(float(flag.sum() / max(1, normal.sum())), 3),
                     "payload FA": round(float((normal & (req["pred"] == 1)).sum() / max(1, normal.sum())), 4),
                     "normal sessions": s_all, "flagged normal sessions": s_flag,
                     "median requests per flagged session": float(req.loc[flag].groupby("session").size().median()) if s_flag else None})
        b = req.loc[flag, "behaviour"].value_counts(normalize=True).round(3)
        beh.append({"group": name, **b.to_dict()})
        for c in FEATURES:
            feat.append({"group": name, "feature": c,
                         "flagged normal (median)": round(float(X.loc[flag, c].median()), 3) if flag.any() else None,
                         "unflagged normal (median)": round(float(X.loc[normal & ~flag, c].median()), 3)})
        # shared address check: distinct user agents and requests per IP
        per = req.assign(ua=req["user_agent"]).groupby("ip").agg(n=("ip", "size"), ua=("ua", "nunique"),
                                                                       fa=("session_attack", "mean"))
        per = per.sort_values("n", ascending=False)
        top = per.iloc[0]
        ipua.append({"group": name, "top IP share": round(float(top["n"] / len(req)), 3), "top IP distinct UAs": int(top["ua"]),
                     "IPs with >=20 UAs": int((per["ua"] >= 20).sum()),
                     "share of requests from IPs with >=20 UAs": round(float(per.loc[per["ua"] >= 20, "n"].sum() / len(req)), 3),
                     "session FA on those IPs": round(float(req.loc[req["ip"].isin(per.index[per["ua"] >= 20]) & normal, "session_attack"].mean()), 3)
                     if (per["ua"] >= 20).any() else None,
                     "session FA on other IPs": round(float(req.loc[~req["ip"].isin(per.index[per["ua"] >= 20]) & normal, "session_attack"].mean()), 3)})
        print("done", name, flush=True)
    f = pd.DataFrame(feat)
    text = ["# v10 dev: why the session layer flags normal traffic (v9 models, aggregates only)", "",
            "## Summary", md(pd.DataFrame(summ)), "", "## Behaviour of flagged normal requests (share)",
            md(pd.DataFrame(beh).fillna(0)), "", "## Shared addresses (one IP, many user agents)", md(pd.DataFrame(ipua)), "",
            "## Context features: flagged normal vs unflagged normal (median)",
            md(f.pivot(index="feature", columns="group", values="flagged normal (median)").reset_index()), "",
            md(f.pivot(index="feature", columns="group", values="unflagged normal (median)").reset_index())]
    (OUT / "SESSION_DIAG.md").write_text("\n".join(text), encoding="utf-8")
    print("\n".join(text))


if __name__ == "__main__":
    main()
