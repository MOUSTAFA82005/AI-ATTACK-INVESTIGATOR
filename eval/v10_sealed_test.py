"""
v10 SEALED TEST (results/final_v10/PREREGISTRATION.md + Amendments). Run ONCE, at tag v10.0-final-test.

    python -m eval.v10_sealed_test convert          # hash check, then sealed files -> data/processed/v10/sealed/*.csv
    python -m eval.v10_sealed_test run --tag v10    # v10 models (this tree) -> pred_v10_<source>.csv.gz
    (in a worktree of tag v9.0-final-test, with the frozen v9 models in its models/ folder:)
    python "<repo>/eval/v10_sealed_test.py" run --tag v9 --repo "<repo>"
    python -m eval.v10_sealed_test report           # -> results/final_v10/sealed/SEALED-RESULTS.md

Only numbers go to results/. Converted rows and predictions (real lines, hosts) stay in data/processed/ (git-ignored).
"run" imports the pipeline of the CURRENT folder, so the same file runs the v9 code inside the v9 worktree.
Labels (preregistration): these logs have no attack labels. A request is "normal" unless the payload rules
(eval/rules.py) call it an attack; those are counted apart, never as false alarms.
"""
import argparse
import gzip
import hashlib
import os
import re
import sys
import time
from pathlib import Path

import numpy as np
import pandas as pd

SEALED = Path("data/sealed/v10")
CONV = Path("data/processed/v10/sealed")
OUT = Path("results/final_v10/sealed")
DRY = os.environ.get("V10_DRY")       # code test on FAKE files only (never set at the real run)
if DRY:
    SEALED, CONV, OUT = Path(DRY) / "sealed", Path(DRY) / "conv", Path(DRY) / "out"
ML, RULES = "model + sessions", "rules + rule sessions"
FIRST_N = int(os.environ.get("V10_FIRST_N", 300_000))                     # S1-S3: the first 300,000 parsed requests
OLD_LOGS = {"clarknet": "clarknet_access_log_Aug28.gz", "usask": "usask_access_log.gz", "nasa": "NASA_access_log_Aug95.gz"}
ZANBIL = {"zanbil": ["zanbil_5.0M.log", "zanbil_8.0M.log"]}
SECREPO_DAYS = ["2026-10-25", "2026-10-26", "2026-10-27", "2026-10-29", "2026-10-30", "2026-10-31"]
SOURCES = ["clarknet", "usask", "nasa", "zanbil", "secrepo"]
TITLES = {"clarknet": "S1 ClarkNet (unseen site, headline)", "usask": "S2 USask (unseen site, headline)",
          "nasa": "S3 NASA Aug 1995 (same site as training, secondary)", "zanbil": "S4 zanbil 5.0M + 8.0M (same site, secondary)",
          "secrepo": "S5 secrepo, 6 new days (same site as dev, real scanners unlabelled)"}
N_SEALED = 11


# ------------------------------------------------------------------ hashes
def _sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest().upper()


def _read_hashes(path):
    raw = Path(path).read_bytes()
    text = raw.decode("utf-16") if raw[:2] in (b"\xff\xfe", b"\xfe\xff") else raw.decode("utf-8", "replace")
    out = {}
    for line in text.splitlines():
        m = re.match(r"\s*([0-9A-Fa-f]{64})\s+(\S+)", line)
        if m:
            out[m.group(2).replace("\\", "/")] = m.group(1).upper()
    return out


def verify(models_file="results/final_v10/model_hashes.txt", sealed=True):
    bad = []
    if sealed:
        want = _read_hashes("results/final_v10/hashes.txt")
        for name, h in want.items():
            p = SEALED / name
            got = _sha256(p) if p.exists() else "MISSING"
            print(f"  {'ok ' if got == h else 'BAD'} {name}")
            bad += [name] if got != h else []
        if len(want) != N_SEALED:
            bad.append(f"{len(want)} sealed files listed, expected {N_SEALED}")
    for name, h in (_read_hashes(models_file).items() if models_file else []):
        p = Path(name)
        got = _sha256(p) if p.exists() else "MISSING"
        print(f"  {'ok ' if got == h else 'BAD'} {name}")
        bad += [name] if got != h else []
    if bad:
        raise SystemExit(f"Stopped: hash problem {bad}. Nothing was measured.")


# ------------------------------------------------------------------ convert (v10 tree only)
COLS = ["ip", "time", "timestamp", "method", "path", "status", "size", "user_agent", "body"]


def _parse_lines(lines):
    from backend.app.log_parser import decode, parse_log_detailed
    rows, _, _ = parse_log_detailed(decode(b"".join(lines)))
    return rows


def _first_parsed(path, n, batch=50_000):
    rows = []
    with gzip.open(path, "rb") as f:
        while len(rows) < n:
            chunk = [l for _, l in zip(range(batch), f)]
            if not chunk:
                break
            rows += _parse_lines(chunk)
    return pd.DataFrame(rows[:n], columns=COLS)


def _label(df):
    from eval.rules import rule_predict
    r = rule_predict(df["method"].fillna(""), df["path"].fillna(""), df["body"].fillna(""))
    df["label"] = np.where(np.asarray(r) == 1, "attack", "normal")
    df["families"] = ""
    return df


def convert():
    verify(models_file=None, sealed=True)
    CONV.mkdir(parents=True, exist_ok=True)
    for src, name in OLD_LOGS.items():
        d = _first_parsed(SEALED / name, FIRST_N)
        _label(d.assign(source=src)).to_csv(CONV / f"{src}.csv", index=False)
        print(f"  {src}: {len(d)} rows")
    parts = []
    for name in ZANBIL["zanbil"]:
        with open(SEALED / name, "rb") as f:
            parts.append(pd.DataFrame(_parse_lines(list(f)), columns=COLS).assign(source=name.split(".log")[0]))
    z = _label(pd.concat(parts, ignore_index=True))
    z.to_csv(CONV / "zanbil.csv", index=False)
    print(f"  zanbil: {len(z)} rows")
    parts = []
    for day in SECREPO_DAYS:
        with gzip.open(SEALED / f"access.log.{day}.gz", "rb") as f:
            parts.append(pd.DataFrame(_parse_lines(list(f)), columns=COLS).assign(source=day))
    s = _label(pd.concat(parts, ignore_index=True))
    s.to_csv(CONV / "secrepo.csv", index=False)
    print(f"  secrepo: {len(s)} rows")


# ------------------------------------------------------------------ run (any tree)
KEEP = ["source", "label", "ip", "session", "proba", "model", "rules", ML, RULES, "type_pred"]


def _pipeline(df):
    import eval.final_test as ft
    df = df.copy()
    for c in ("method", "path", "body", "user_agent", "ip", "timestamp", "families"):
        df[c] = df[c].fillna("").astype(str)
    for c in ("status", "size"):
        df[c] = pd.to_numeric(df[c], errors="coerce").fillna(0).astype(int)
    df["attack_type"] = np.where(df["label"] == "attack", "x", "")
    req, _ = ft._pipeline(df)
    return req


def run(tag, data):
    conv, t0 = Path(data), time.time()
    for src in SOURCES:
        p = conv / f"{src}.csv"
        if not p.exists():
            print("  missing", p); continue
        df = pd.read_csv(p, dtype=str, keep_default_na=False)
        parts = []
        # one log = one source file (zanbil slices and secrepo days are separate logs)
        for key, g in df.groupby("source", sort=True):
            r = _pipeline(g.reset_index(drop=True))
            parts.append(r[[c for c in KEEP if c in r]])
            print(f"  {tag} {src} {key}: {len(g)} rows ({time.time() - t0:.0f}s)", flush=True)
        pd.concat(parts, ignore_index=True).to_csv(conv / f"pred_{tag}_{src}.csv.gz", index=False)
    print(f"{tag} done in {time.time() - t0:.0f}s")


# ------------------------------------------------------------------ report (numbers only)
def _md(t):
    t = t.astype(object).where(t.notna(), "").astype(str)
    return "\n".join(["| " + " | ".join(t.columns) + " |", "|" + "---|" * len(t.columns)]
                     + ["| " + " | ".join(r) + " |" for r in t.values])


def report():
    OUT.mkdir(parents=True, exist_ok=True)
    md = ["# v10 sealed test", "", "Run once at tag v10.0-final-test. Rules, frozen v9 and v10 on the same converted rows.",
          "FA = share of normal requests flagged (normal = not called an attack by the payload rules).", ""]
    rows, verdict = [], {}
    for src in SOURCES:
        P = {t: pd.read_csv(CONV / f"pred_{t}_{src}.csv.gz", keep_default_na=False, dtype={"type_pred": str})
             for t in ("v10", "v9") if (CONV / f"pred_{t}_{src}.csv.gz").exists()}
        if "v10" not in P:
            continue
        g = P["v10"]
        normal = g["label"] == "normal"
        r = {"log": TITLES[src], "requests": len(g), "rule-flagged (not counted)": int((~normal).sum()),
             "distinct hosts/IPs": int(g["ip"].nunique()),
             "rules + rule sessions": round(float((g.loc[normal, RULES] == 1).mean()), 4)}
        for t in ("v9", "v10"):
            if t in P:
                n = P[t]["label"] == "normal"
                r[f"{t} payload"] = round(float((P[t].loc[n, "model"] == 1).mean()), 4)
                r[f"{t} + sessions"] = round(float((P[t].loc[n, ML] == 1).mean()), 4)
        rows.append(r)
        if "v9" in P:
            verdict[src] = r["v10 + sessions"] < r["v9 + sessions"]
    md += ["## False alarms on real traffic", "", _md(pd.DataFrame(rows)), ""]
    if "clarknet" in verdict and "usask" in verdict:
        ok = verdict["clarknet"] and verdict["usask"]
        md += ["## Pre-stated reading", "",
               f"v10 session FA lower than v9 on both S1 and S2: **{'yes' if ok else 'no'}** "
               f"(S1 {verdict['clarknet']}, S2 {verdict['usask']}). S6 (lab) is reported separately if it was run.", ""]
    (OUT / "SEALED-RESULTS.md").write_text("\n".join(md), encoding="utf-8")
    print("\n".join(md))


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("step", choices=["convert", "run", "report"])
    ap.add_argument("--tag", default="v10", choices=["v10", "v9"])
    ap.add_argument("--repo", default=".", help="the v10 repo (for its converted data), when run from the v9 worktree")
    a = ap.parse_args(argv)
    if a.step == "convert":
        convert()
    elif a.step == "run":
        if not DRY:
            if a.tag == "v9":
                verify(Path(a.repo) / "results/final_v10/model_hashes_v9.txt", sealed=False)
            else:
                verify(sealed=False)
        run(a.tag, CONV if DRY else Path(a.repo) / CONV)
    else:
        report()


if __name__ == "__main__":
    sys.path = [os.getcwd()] + [p for p in sys.path if Path(p).resolve() != Path(__file__).resolve().parent]
    main()
