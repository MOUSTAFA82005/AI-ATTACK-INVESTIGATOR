"""
v12 SEALED TEST (results/final_v12/PREREGISTRATION.md). Run ONCE, at the v12 freeze (commit 1ddddea).

    python -m eval.v12_label data/sealed/v12 data/processed/v12/sealed/labels.csv   # hand-label rules, no system
    python -m eval.v12_sealed_test run --tag v12                                     # this tree
    (in the worktree of c58e161 = v11 code, same models:)
    python "<repo>/eval/v12_sealed_test.py" run --tag v11 --repo "<repo>"
    python -m eval.v12_sealed_test report                                            # -> results/final_v12/sealed/

Visitor = (day, IP). caught = any request of the IP flagged by the system (payload or session layer); for the app
(v11 / v12) also the defence action of its sessions. Rules baseline = payload rules + rule sessions (eval/final_test).
Predictions (real IPs) stay in data/processed/v12/sealed (git-ignored); only numbers go to results/.
"""
import argparse
import gzip
import hashlib
import os
import re
import sys
import time
from pathlib import Path

import pandas as pd

SEALED = Path("data/sealed/v12")
CONV = Path("data/processed/v12/sealed")
OUT = Path("results/final_v12/sealed")
DRY = os.environ.get("V12_DRY")          # code test on FAKE files only (never set at the real run)
if DRY:
    SEALED, CONV, OUT = Path(DRY) / "sealed", Path(DRY) / "conv", Path(DRY) / "out"
ML, RULES = "model + sessions", "rules + rule sessions"
ALARM = {"medium", "high", "critical"}


def _sha256(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest().lower()


def verify(repo):
    if DRY:
        return
    want = {}
    for line in (Path(repo) / "results/final_v12/hashes.txt").read_text().splitlines():
        h, name = line.split()[:2]
        want[name.replace("\\", "/")] = h.lower()
    bad = [n for n, h in want.items() if _sha256(Path(repo) / n) != h]
    lab = (Path(repo) / "results/final_v12/labels_sha256.txt").read_text().split()[0].lower()
    if _sha256(Path(repo) / CONV / "labels.csv") != lab:
        bad.append("labels.csv")
    if bad:
        sys.exit(f"hash mismatch: {bad}")
    print(f"hashes ok ({len(want)} sealed files + labels)")


def run(tag, repo):
    import eval.final_test as ft
    import eval.v10_sealed_test as v10
    from backend.app import main as M
    verify(repo)
    out, rows, t0 = Path(repo) / CONV, [], time.time()
    out.mkdir(parents=True, exist_ok=True)
    for f in sorted((Path(repo) / SEALED if not DRY else SEALED).glob("access.log.*.gz")):
        day = f.name[len("access.log."):-3]
        raw = gzip.open(f, "rb").read()
        inv = M._investigate(raw, M.MODES["sensitive"], f.name, "sensitive")
        app = {}
        for s in inv["sessions"]:
            a = app.setdefault(s["ip"], {"alarm": False, "block": False, "limit": False})
            a["alarm"] |= s["risk_level"] in ALARM
            a["block"] |= s.get("action") == "block"
            a["limit"] |= s.get("action") == "rate_limit"
        df = pd.DataFrame(v10._parse_lines(raw.splitlines(keepends=True)))
        for c in ("method", "path", "body", "user_agent", "ip", "timestamp"):
            df[c] = df[c].fillna("").astype(str)
        for c in ("status", "size"):
            df[c] = pd.to_numeric(df[c], errors="coerce").fillna(0).astype(int)
        df["label"], df["families"], df["attack_type"] = "normal", "", ""
        req, _ = ft._pipeline(df)
        flag = req.groupby("ip")[[ML, RULES]].max()
        for ip, r in flag.iterrows():
            a = app.get(ip, {"alarm": False, "block": False, "limit": False})
            rows.append({"day": day, "ip": ip, "ml": int(r[ML]), "rules": int(r[RULES]), "app_alarm": int(a["alarm"]),
                         "app_block": int(a["block"]), "app_limit": int(a["limit"])})
        print(f"  {tag} {day}: {len(df)} requests, {len(flag)} IPs ({time.time() - t0:.0f}s)", flush=True)
    pd.DataFrame(rows).to_csv(out / f"pred_{tag}.csv", index=False)


def _md(t):
    t = t.astype(str)
    return "\n".join(["| " + " | ".join(t.columns) + " |", "|" + "---|" * len(t.columns)]
                     + ["| " + " | ".join(r) + " |" for r in t.values])


def report():
    lab = pd.read_csv(CONV / "labels.csv", keep_default_na=False)
    P = {t: pd.read_csv(CONV / f"pred_{t}.csv").merge(lab, on=["day", "ip"], how="left") for t in ("v11", "v12")}
    att, nor = (lambda d: d[d["label"] == "attacker"]), (lambda d: d[d["label"] == "normal"])
    rows = []
    for name, d, col in [("rules + rule sessions", P["v12"], "rules"), ("v11 (app)", P["v11"], None),
                         ("v12 (app)", P["v12"], None)]:
        a, n = att(d), nor(d)
        caught = (a[col] if col else (a["ml"] | a["app_alarm"])).astype(bool)
        alarm = (n[col] if col else (n["ml"] | n["app_alarm"])).astype(bool)
        r = {"system": name, "attacker visitors": len(a), "caught": f"{caught.mean():.3f} ({caught.sum()})",
             "normal visitors": len(n), "normal with alarm": f"{alarm.mean():.4f} ({alarm.sum()})"}
        if col is None:
            r["normal blocked"] = int(n["app_block"].sum())
            r["attackers blocked or rate-limited"] = f"{(a['app_block'] | a['app_limit']).mean():.3f}"
        rows.append(r)
    t = pd.DataFrame(rows).fillna("")
    v11, v12 = P["v11"], P["v12"]
    c = {k: (att(d)["ml"] | att(d)["app_alarm"]).astype(bool).mean() for k, d in (("v11", v11), ("v12", v12))}
    fa = {k: (nor(d)["ml"] | nor(d)["app_alarm"]).astype(bool).mean() for k, d in (("v11", v11), ("v12", v12))}
    blk = {k: int(nor(d)["app_block"].sum()) for k, d in (("v11", v11), ("v12", v12))}
    better = c["v12"] >= c["v11"] + 0.05 and blk["v12"] <= blk["v11"] and fa["v12"] <= fa["v11"] + 0.01
    unsure = lab["label"].eq("unsure").sum()
    md = ["# v12 sealed test: secrepo.com, 15 unseen days of November 2026 (run once)", "",
          "Preregistration: results/final_v12/PREREGISTRATION.md (+ Amendment 1). Labels per (day, IP) from the raw "
          "lines by eval/v12_label.py, written and hashed before any system ran (results/final_v12/labels_sha256.txt).",
          f"Unsure visitors left out: {unsure} (Chrome/146 scraper fleet, declared crawlers on exploit-looking paths, "
          "one admin guess).", "", _md(t), "", "## Pre-stated reading", "",
          f"v12 better if caught >= v11 + 0.05 ({c['v12']:.3f} vs {c['v11']:.3f}), normal blocked <= v11 "
          f"({blk['v12']} vs {blk['v11']}), normal alarm <= v11 + 0.01 ({fa['v12']:.4f} vs {fa['v11']:.4f}) -> "
          f"**{'BETTER' if better else 'NO CLEAR GAIN'}**.", ""]
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "SEALED-RESULTS.md").write_text("\n".join(md), encoding="utf-8")
    print("\n".join(md))


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("step", choices=["run", "report"])
    ap.add_argument("--tag", default="v12", choices=["v12", "v11"])
    ap.add_argument("--repo", default=".")
    a = ap.parse_args(argv)
    run(a.tag, a.repo) if a.step == "run" else report()


if __name__ == "__main__":
    sys.path = [os.getcwd()] + [p for p in sys.path if Path(p).resolve() != Path(__file__).resolve().parent]
    main()
