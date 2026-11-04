"""
v9 step: how does the FROZEN v8 pipeline (and the rules baseline) do on the new DEV data?
DEV only (data/processed/v9/*_dev.csv). Nothing here touches data/sealed/.

    python -m eval.v9_baseline
Writes results/final_v9/dev_v8_baseline.md and .csv.
SR-BH is run one day at a time (the laptop has little RAM; the SR-BH honeypot VM was reset every day).
"""
import time
import warnings
from pathlib import Path

import numpy as np
import pandas as pd

warnings.filterwarnings("ignore")
import eval.final_test as ft

ML, RULES = "model + sessions", "rules + rule sessions"
DEV = Path("data/processed/v9")
OUT = Path("results/final_v9")


def run(df):
    df = df.copy()
    df["label"] = np.where(df["label"].astype(int) == 1, "attack", "normal")
    df["attack_type"] = np.where(df["label"] == "attack", "x", "")
    for c in ("method", "path", "body", "user_agent", "ip", "timestamp"):
        df[c] = df[c].fillna("").astype(str)
    for c in ("status", "size"):
        df[c] = pd.to_numeric(df[c], errors="coerce").fillna(0).astype(int)
    req, _ = ft._pipeline(df)
    return req


def srbh():
    df = pd.read_csv(DEV / "srbh_dev.csv", dtype=str, keep_default_na=False)
    df["day"] = df["timestamp"].str[:10]
    parts = []
    for day, d in df.groupby("day", sort=True):
        t = time.time()
        r = run(d)
        parts.append(r[["label", "families", "model", "rules", ML, RULES, "type_pred", "ip", "session"]].assign(day=day))
        print(f"  SR-BH {day}: {len(d)} rows in {time.time() - t:.0f}s", flush=True)
    return pd.concat(parts, ignore_index=True)


def srbh_table(r):
    att, nor = r["label"] == "attack", r["label"] == "normal"
    rows = []
    for name, d in (("ML (v8)", ML), ("rules", RULES)):
        p = r[d] == 1
        tp, fp = int((p & att).sum()), int((p & nor).sum())
        rows.append({"detector": name, "attacks": int(att.sum()), "caught": tp,
                     "recall vs CRS": round(tp / max(int(att.sum()), 1), 3),
                     "normals": int(nor.sum()), "normals flagged": fp,
                     "false-alarm rate": round(fp / max(int(nor.sum()), 1), 4),
                     "precision vs CRS": round(tp / max(tp + fp, 1), 3)})
    fam = []
    ex = r[att].assign(fam=r.loc[att, "families"].str.split("|")).explode("fam")
    for f, g in ex.groupby("fam"):
        fam.append({"family (CRS)": f, "requests": len(g),
                    "recall ML (v8)": round(float(g[ML].mean()), 3), "recall rules": round(float(g[RULES].mean()), 3)})
    return pd.DataFrame(rows), pd.DataFrame(fam).sort_values("requests", ascending=False)


def srbh_normals(r):
    """Where do the 'false alarms' come from? Normal requests split by who sent them."""
    att = r["label"] == "attack"
    bad_ip = r.groupby(["day", "ip"])["label"].transform(lambda s: (s == "attack").any())
    rows = []
    for grp, m in (("normal requests from IPs that also attacked (same day)", ~att & bad_ip),
                   ("normal requests from IPs that never attacked (same day)", ~att & ~bad_ip)):
        rows.append({"group": grp, "requests": int(m.sum()),
                     "flagged model only (v8)": round(float(r.loc[m, "model"].mean()), 4) if m.any() else None,
                     "flagged model + sessions (v8)": round(float(r.loc[m, ML].mean()), 4) if m.any() else None,
                     "flagged payload rules": round(float(r.loc[m, "rules"].mean()), 4) if m.any() else None,
                     "flagged rules + sessions": round(float(r.loc[m, RULES].mean()), 4) if m.any() else None})
    ips = r.groupby(["day", "ip"])["label"].agg(lambda s: (s == "attack").any())
    note = f"Sources (day, IP): {len(ips)} in total, {int(ips.sum())} sent at least one CRS-labelled attack."
    return pd.DataFrame(rows), note


def glastopf():
    df = pd.read_csv(DEV / "glastopf_dev.csv", dtype=str, keep_default_na=False)
    r = run(df)
    rows = []
    for name, d in (("ML (v8)", ML), ("rules", RULES)):
        by_ip = r.groupby("ip")[d].max()
        rows.append({"detector": name, "requests": len(r), "requests flagged": round(float(r[d].mean()), 3),
                     "IPs": len(by_ip), "IPs flagged (headline)": round(float(by_ip.mean()), 3)})
    pat = r.groupby("pattern").agg(requests=(ML, "size"), **{"flagged ML (v8)": (ML, "mean"),
                                                             "flagged rules": (RULES, "mean")}).round(3)
    return pd.DataFrame(rows), pat.sort_values("requests", ascending=False).reset_index()


def md(t):
    t = t.astype(object).where(t.notna(), "").astype(str)
    lines = ["| " + " | ".join(t.columns) + " |", "|" + "---|" * len(t.columns)]
    return "\n".join(lines + ["| " + " | ".join(r) + " |" for r in t.values])


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    print("Glastopf dev ...", flush=True)
    g, gp = glastopf()
    print("SR-BH dev, one day at a time ...", flush=True)
    r = srbh()
    r.to_csv(Path("data/processed/v9/v8_dev_preds_srbh.csv"), index=False)   # so later analysis needs no rerun
    s, sf = srbh_table(r)
    sn, sn_note = srbh_normals(r)
    text = ["# v8 (frozen) and rules on the v9 DEV data", "",
            "DEV only. Not a test result: v9 will be trained and tuned on this data.", "",
            "## SR-BH dev (17-24 Jul 2020), labels = ModSecurity CRS", "", md(s), "", md(sf), "",
            "### Where the flagged normal requests come from", "", md(sn), "", sn_note, "",
            "## Glastopf honeypot dev (2014-09 .. 2015-03), all traffic hits a honeypot", "", md(g), "", md(gp), ""]
    (OUT / "dev_v8_baseline.md").write_text("\n".join(text), encoding="utf-8")
    pd.concat([s.assign(data="srbh"), g.assign(data="glastopf")]).to_csv(OUT / "dev_v8_baseline.csv", index=False)
    print("\n".join(text))


if __name__ == "__main__":
    main()
