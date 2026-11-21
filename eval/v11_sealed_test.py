"""
v11 SEALED TEST (results/final_v11/PREREGISTRATION.md + Amendment 1). Run ONCE, at tag v11.0-final-test.

    python -m eval.v11_sealed_test convert    # hash check, sealed Biblio-US17 (Jun 1 - Jul 17) -> data/processed/v11/sealed/
    python -m eval.v11_sealed_test run        # model hash check, rules + v10 + v11 -> results/final_v11/sealed/SEALED-RESULTS.md

Both detectors share the same feature code (v11 only adds training data), so one tree runs both:
v10 = models/detector.joblib (frozen, hash in results/final_v10/model_hashes.txt), v11 = models/detector_v11.joblib.
Only numbers go to results/. Converted rows (real URIs) stay in data/processed/ (git-ignored).
Sets (same definitions as dev, eval/v11_convert.py): attack = LVL1 deduplicated by (method, URI); clean = uniform
random sample of 1,000,000 clean rows (seed 11); fp = rows the signature tools flagged, judged normal (ManualTP = 0),
deduplicated; lvl234 = LVL2/3 deduplicated (secondary).
"""
import argparse
import hashlib
import os
import random
import re
import sys
from pathlib import Path

import pandas as pd

SEALED = Path("data/sealed/v11/biblio")
CONV = Path("data/processed/v11/sealed")
OUT = Path("results/final_v11/sealed")
DRY = os.environ.get("V11_DRY")         # code test on FAKE files only (never set at the real run)
if DRY:
    SEALED, CONV, OUT = Path(DRY) / "sealed", Path(DRY) / "conv", Path(DRY) / "out"
N_SEALED = 235                          # 47 days x 5 sets
CLEAN_N = int(os.environ.get("V11_CLEAN_N", 1_000_000)) if DRY else 1_000_000
SEED = 11
MODELS = {"v10": Path("models/detector.joblib"), "v11": Path("models/detector_v11.joblib")}
BETTER_RECALL = 0.02


def _sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest().lower()


def _read_hashes(path):
    out = {}
    for line in Path(path).read_text(encoding="utf-8", errors="replace").splitlines():
        m = re.match(r"\s*([0-9A-Fa-f]{64})\s+(\S+)", line)
        if m:
            out[m.group(2).replace("\\", "/")] = m.group(1).lower()
    return out


def _check(want, base):
    bad = []
    for name, h in want.items():
        p = base / name
        got = _sha256(p) if p.exists() else "MISSING"
        bad += [name] if got != h else []
    return bad


def verify_sealed():
    want = _read_hashes("results/final_v11/hashes.txt" if not DRY else Path(DRY) / "hashes.txt")
    bad = _check(want, SEALED)
    if len(want) != N_SEALED and not DRY:
        bad.append(f"{len(want)} sealed files listed, expected {N_SEALED}")
    print(f"sealed files: {len(want) - len(bad)} of {len(want)} hashes ok")
    if bad:
        raise SystemExit(f"Stopped: hash problem {bad[:10]}. Nothing was converted.")


def verify_models():
    if DRY:
        return
    bad = _check(_read_hashes("results/final_v11/model_hashes.txt"), Path("."))
    v10 = _read_hashes("results/final_v10/model_hashes.txt")["models/detector.joblib"]
    bad += [] if _sha256(MODELS["v10"]) == v10 else ["models/detector.joblib is not the frozen v10 detector"]
    if bad:
        raise SystemExit(f"Stopped: model hash problem {bad}. Nothing was measured.")
    print("models: hashes ok")


# ------------------------------------------------------------------ convert
def sample_clean(src, n=None):
    """Uniform random sample of n clean rows over the whole sealed period (one reservoir, seed 11)."""
    from eval.v11_convert import days, read, split_of
    n = n or CLEAN_N
    rng, pool, i = random.Random(SEED), [], 0
    for day, p in days("clean", "cl", src):
        for r in read(p):
            t = (day, r["id"], r["method"], r["path"], r["status"], r["size"])
            if i < n:
                pool.append(t)
            else:
                j = rng.randint(0, i)
                if j < n:
                    pool[j] = t
            i += 1
    print(f"clean rows {i}, sample {len(pool)}", flush=True)
    return [{"split": split_of(d), "day": d, "id": a, "method": m, "path": u, "status": s, "size": z,
             "label": "normal", "level": 0, "count": 1} for d, a, m, u, s, z in pool]


def convert():
    from eval.v11_convert import dedup_rows, label_levels, write
    verify_sealed()
    write("attack.csv", dedup_rows("attack", "att", "attack", src=SEALED), CONV)
    levels = label_levels(src=SEALED)
    write("lvl234.csv", dedup_rows("raw", "raw", "attack", keep=lambda d: levels.get(d, {}), src=SEALED), CONV)
    fps = label_levels(fp=True, src=SEALED)
    write("fp.csv", dedup_rows("raw", "raw", "normal", keep=lambda d: fps.get(d, {}), src=SEALED), CONV)
    write("clean.csv", sample_clean(SEALED), CONV)


# ------------------------------------------------------------------ run + report
def _load(name):
    df = pd.read_csv(CONV / f"{name}.csv", dtype=str, keep_default_na=False)
    df["count"] = df["count"].astype(int)
    return df


def _stats(att, cln, fp, lvl, f):
    """f(df) -> bool Series. Same numbers as eval/v11_dev_eval.py."""
    from eval.v11_dev_eval import macro
    f_att, f_cln, f_fp, f_lvl = f(att), f(cln), f(fp), f(lvl)
    return {"macro": macro(att, f_att), "unique": f_att.mean(),
            "raw": (f_att.values * att["count"].values).sum() / att["count"].sum(),
            "fa_clean": f_cln.mean(), "fa_clean_paths": cln.assign(f=f_cln.values).groupby("path")["f"].max().mean(),
            "fa_fp": f_fp.mean() if len(fp) else float("nan"), "lvl": f_lvl.mean() if len(lvl) else float("nan")}


def run():
    import joblib
    from eval.v11_dev_eval import family, flags
    verify_models()
    att, cln, fp, lvl = (_load(n) for n in ("attack", "clean", "fp", "lvl234"))
    res = {"payload rules": _stats(att, cln, fp, lvl, lambda d: flags(d, None, 0))}
    for tag, path in MODELS.items():
        model = joblib.load(path)
        for t in (0.7, 0.8):
            res[f"{tag} @{t}"] = _stats(att, cln, fp, lvl, lambda d: flags(d, model, t))
    v10, v11 = res["v10 @0.7"], res["v11 @0.7"]
    better = bool(v11["macro"] >= v10["macro"] + BETTER_RECALL and v11["fa_clean"] <= v10["fa_clean"]
              and v11["fa_fp"] <= v10["fa_fp"])
    fams = len({family(m, p) for m, p in zip(att["method"], att["path"])})
    md = ["# v11 SEALED TEST: Biblio-US17, 2017-06-01 .. 2017-07-17 (run once)", "",
          "Preregistration: results/final_v11/PREREGISTRATION.md (+ Amendment 1). Payload layer only (no IP, user agent "
          "or body in this dataset). v10 never saw Biblio-US17 (UNSEEN-SITE row); v11 was trained on Jan-May of the "
          "same site (SAME-SITE row, secondary). Threshold 0.7 preregistered, 0.8 sensitivity row.", "",
          f"Unique LVL1 attacks {len(att)} (raw rows {att['count'].sum()}), attack families {fams}; clean sample "
          f"{len(cln)} rows ({cln['path'].nunique()} unique paths); signature false positives {len(fp)} unique; "
          f"LVL2/3 unique {len(lvl)}.", "",
          "| detector | recall (macro over families, headline) | recall (unique) | recall (raw-weighted) | FA clean (rows) "
          "| FA clean (unique paths) | FA on signature false positives | LVL2/3 recall |",
          "|---|---|---|---|---|---|---|---|"]
    for name, r in res.items():
        md.append(f"| {name} | {r['macro']:.4f} | {r['unique']:.4f} | {r['raw']:.4f} | {r['fa_clean']:.5f} | "
                  f"{r['fa_clean_paths']:.5f} | {r['fa_fp']:.4f} | {r['lvl']:.4f} |")
    md += ["", "## Pre-stated reading", "",
           f"v11 is better on Biblio if macro recall(v11) >= recall(v10) + {BETTER_RECALL} AND FA clean and FA on "
           f"signature false positives are not higher than v10 (all at 0.7): "
           f"{v11['macro']:.4f} vs {v10['macro']:.4f} + {BETTER_RECALL}, FA clean {v11['fa_clean']:.5f} vs "
           f"{v10['fa_clean']:.5f}, FA false positives {v11['fa_fp']:.4f} vs {v10['fa_fp']:.4f} -> "
           f"**{'BETTER' if better else 'NOT BETTER'}**.", "",
           "Known bias (preregistered): labels start from signature tools plus manual review, so recall is recall on "
           "signature-confirmed attacks and FA on clean is an upper bound. This test says nothing new about unseen "
           "sites for v11; site independence evidence stays the v10 sealed test.", ""]
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "SEALED-RESULTS.md").write_text("\n".join(md), encoding="utf-8")
    print("\n".join(md))
    return res, better


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("step", choices=["convert", "run"])
    a = ap.parse_args(argv)
    convert() if a.step == "convert" else run()


if __name__ == "__main__":
    main()
