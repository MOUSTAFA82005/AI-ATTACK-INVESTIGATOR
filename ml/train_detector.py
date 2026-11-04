"""
Train the detection model on CSIC 2010 (+ HttpParams if present), the lab runs of the 7
sites and real normal traffic (zanbil, dev lines only), and save it to models/detector.joblib.
Missing files are skipped with a message.

Why the lab and real traffic: trained on CSIC alone, the detector flagged 0.6-2.6% of a
real shop's ordinary requests, and missed payloads on API sites (results in
team/ml-real/RESULTS.md section 7). Leave-one-site-out shows the gain is not a site's
own words: each site is tested with its own runs left out.

Run from the repo root, after notebooks/01_csic_baseline.ipynb has written
data/processed/csic_clean.csv:

    python -m ml.train_detector

CSIC labels as "anomalous" many requests that carry no attack at all (a
renamed parameter, a value that is only wrong for that one shop). No general
model can learn those, and they teach it that clean requests look like attacks.
So we train on CSIC normal traffic + the anomalous requests that carry a payload.
See notebooks/04_site_independent_detector.ipynb.

HttpParams (https://github.com/Morzeux/HttpParamsDataset) adds attack values
made with other tools (sqlmap, FuzzDB, Vega), so the model sees more kinds of
attacks than CSIC has. Download payload_train.csv from that repo and save it as
data/raw/httpparams_train.csv; if the file is missing we train on CSIC only.
See notebooks/07_second_dataset.ipynb.

New attack families (SSRF, XXE, SSTI, NoSQL, Log4Shell, LDAP, XPath): public payloads
put inside normal CSIC requests (ml/new_families.py). Build data/raw/new_families.csv
with python -m ml.build_new_families; only its "train" payloads are used here, the
"heldout" ones are kept for the check in notebooks/17_new_families.ipynb. If the file
is missing we train without them.

v9 (results/final_v9/PREREGISTRATION.md): `--v9` also adds REAL attacks and normal traffic made by others:
SR-BH 2020 DEV days (labels = ModSecurity CRS; attacks kept only when they carry a payload, as with CSIC)
and the Glastopf honeypot DEV months (real attackers; only requests that carry a payload). Sealed parts are
never read here. `--srbh-days` / `--glastopf-until` hold DEV data out for the dev check, `--out` saves elsewhere.

    python -m ml.train_detector --v9 --out models/detector_v9.joblib
"""
import argparse
import os
import sys
import time
from itertools import islice
from urllib.parse import quote

import joblib
import pandas as pd

from ml import new_families
from ml.detector import MODEL_PATH, ROOT, build_pipeline, detector_columns, has_payload, to_frame

HTTPPARAMS = ROOT / "data" / "raw" / "httpparams_train.csv"
ZANBIL = ROOT / "data" / "raw" / "zanbil_access.log"
ZANBIL_LINES = 200_000          # dev part of the real log; later lines stay unseen for tests
ZANBIL_SAMPLE = 60_000
# Lab runs of the 7 sites: their payload attacks and their normal users' requests. Brute
# force, enumeration and scans are left out: no single one of those requests carries a
# payload; they are the behaviour model's job.
LAB_RUNS = {"juiceshop": ["st21", "st22"], "dvwa": ["st21", "st22"],
            **{s: ["st31", "st32"] for s in ["bwapp", "mutillidae", "dvna", "vampi", "dvga"]}}
BEHAVIOUR_TYPES = {"bruteforce", "enum", "scan"}


def load_httpparams(path):
    """HttpParams rows are single parameter values: send each one as ?q=<value>."""
    df = pd.read_csv(path, keep_default_na=False)
    X = to_frame(["GET"] * len(df), ["/?q=" + quote(v, safe="") for v in df["payload"]], [""] * len(df))
    return X, (df["label"] == "anom").astype(int)


def load_lab(skip_sites=()):
    """Payload attacks and normal requests of the lab runs that exist."""
    from eval.match_labels import match
    from ml.train_stage import run_paths
    parts = []
    for site, tags in LAB_RUNS.items():
        if site in skip_sites:
            continue
        for tag in tags:
            log, labels = run_paths(site, tag)
            if not (os.path.exists(log) and os.path.exists(labels)):
                print("skipped (missing):", log)
                continue
            d = match(log, labels)[0]
            d = d[~d["attack_type"].fillna("").isin(BEHAVIOUR_TYPES)]
            parts.append((to_frame(d["method"], d["path"], d["body"]), (d["label"] == "attack").astype(int)))
    if not parts:
        return pd.DataFrame(), pd.Series(dtype=int)
    print(f"adding {sum(len(p[1]) for p in parts)} lab requests ({sum(int(p[1].sum()) for p in parts)} attacks)")
    return pd.concat([p[0] for p in parts], ignore_index=True), pd.concat([p[1] for p in parts], ignore_index=True)


def load_real_normals():
    """Real traffic from a real shop (zanbil.ir), first ZANBIL_LINES lines, one request per
    distinct address: what ordinary visitors send, from a site the lab never was."""
    from backend.app.log_parser import decode, parse_log
    if not ZANBIL.exists():
        print(f"{ZANBIL} not found: no real normal traffic")
        return pd.DataFrame(), pd.Series(dtype=int)
    with open(ZANBIL, "rb") as f:
        df = pd.DataFrame(parse_log(decode(b"".join(islice(f, ZANBIL_LINES))))[0])
    df = df.drop_duplicates(["path"])
    df = df.sample(min(ZANBIL_SAMPLE, len(df)), random_state=0)
    print(f"adding {len(df)} real normal requests (zanbil)")
    return to_frame(df["method"], df["path"], [""] * len(df)), pd.Series(0, index=range(len(df)))


V9_DIR = ROOT / "data" / "processed" / "v9"
SRBH_DEV_DAYS = ["2020-07-17", "2020-07-18", "2020-07-19", "2020-07-20",
                 "2020-07-21", "2020-07-22", "2020-07-23", "2020-07-24"]
SRBH_MAX_ATTACKS, SRBH_MAX_NORMAL = 40_000, 60_000   # the laptop has little RAM


def load_srbh(days):
    """SR-BH DEV rows of the given days: distinct requests only, attacks only with a payload."""
    path = V9_DIR / "srbh_dev.csv"
    if not path.exists():
        print(f"{path} not found: run python eval/v9_convert.py")
        return pd.DataFrame(), pd.Series(dtype=int)
    cols = ["timestamp", "method", "path", "body", "label", "families"]
    df = pd.read_csv(path, usecols=cols, dtype=str, keep_default_na=False)
    df = df[df["timestamp"].str[:10].isin(days)].drop_duplicates(["method", "path", "body", "label"])
    att, nor = df[df["label"] == "1"], df[df["label"] == "0"]
    att = att.sample(min(len(att), SRBH_MAX_ATTACKS * 3), random_state=0)
    Xa = to_frame(att["method"], att["path"], att["body"])
    keep = has_payload(Xa).values
    Xa = Xa[keep].reset_index(drop=True)
    if len(Xa) > SRBH_MAX_ATTACKS:
        Xa = Xa.sample(SRBH_MAX_ATTACKS, random_state=0).reset_index(drop=True)
    nor = nor.sample(min(len(nor), SRBH_MAX_NORMAL), random_state=0)
    Xn = to_frame(nor["method"], nor["path"], nor["body"])
    print(f"adding SR-BH days {days[0]}..{days[-1]}: {len(Xa)} attacks with a payload "
          f"(of {len(att)} distinct sampled), {len(Xn)} normal")
    return (pd.concat([Xa, Xn], ignore_index=True),
            pd.concat([pd.Series(1, index=range(len(Xa))), pd.Series(0, index=range(len(Xn)))], ignore_index=True))


def load_glastopf(until):
    """Glastopf DEV requests before `until` that carry a payload (honeypot: no real users)."""
    path = V9_DIR / "glastopf_dev.csv"
    if not path.exists():
        return pd.DataFrame(), pd.Series(dtype=int)
    df = pd.read_csv(path, dtype=str, keep_default_na=False)
    df = df[df["timestamp"].str[:10] < until].drop_duplicates(["method", "path", "body"])
    X = to_frame(df["method"], df["path"], df["body"])
    X = X[has_payload(X).values].reset_index(drop=True)
    print(f"adding Glastopf before {until}: {len(X)} distinct requests with a payload")
    return X, pd.Series(1, index=range(len(X)))


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("--v9", action="store_true", help="also train on SR-BH and Glastopf DEV data")
    ap.add_argument("--srbh-days", default=",".join(SRBH_DEV_DAYS))
    ap.add_argument("--glastopf-until", default="2015-04-01")
    ap.add_argument("--out", default=str(MODEL_PATH))
    args = ap.parse_args(argv)
    df = pd.read_csv(ROOT / "data" / "processed" / "csic_clean.csv", keep_default_na=False)
    X = to_frame(df["Method"], df["path"], df["body"])
    y = df["label"]
    if HTTPPARAMS.exists():
        Xh, yh = load_httpparams(HTTPPARAMS)
        print(f"adding {len(yh)} HttpParams values ({yh.sum()} attacks)")
        X, y = pd.concat([X, Xh], ignore_index=True), pd.concat([y, yh], ignore_index=True)
    else:
        print(f"{HTTPPARAMS} not found: training on CSIC only")
    if new_families.NEW_FAMILIES_CSV.exists():
        normals = df[df["label"] == 0]
        Xn, yn, fam, _ = new_families.load("train", normals)
        print(f"adding {len(yn)} requests with new-family payloads {fam.value_counts().to_dict()}")
        X, y = pd.concat([X, Xn], ignore_index=True), pd.concat([y, yn], ignore_index=True)
    else:
        print(f"{new_families.NEW_FAMILIES_CSV} not found: no new attack families")

    keep = (y == 0) | has_payload(X)
    print(f"dropping {(~keep).sum()} anomalies with no attack payload")
    X, y = X[keep].reset_index(drop=True), y[keep].reset_index(drop=True)

    Xl, yl = load_lab()
    Xz, yz = load_real_normals()
    X, y = pd.concat([X, Xl, Xz], ignore_index=True), pd.concat([y, yl, yz], ignore_index=True)
    if args.v9:
        Xs, ys = load_srbh(args.srbh_days.split(","))
        Xg, yg = load_glastopf(args.glastopf_until)
        X, y = pd.concat([X, Xs, Xg], ignore_index=True), pd.concat([y, ys, yg], ignore_index=True)
        X = X.fillna(0)
    hand_cols = detector_columns(X)

    pos, neg = (y == 1).sum(), (y == 0).sum()
    print(f"training on {len(y)} requests ({pos} attacks, {neg} normal)...")
    t = time.time()
    pipe = build_pipeline(hand_cols).fit(X, y)
    print(f"done in {time.time() - t:.0f}s")

    out = os.path.abspath(args.out)
    os.makedirs(os.path.dirname(out), exist_ok=True)
    joblib.dump(pipe, out)
    print("saved", out)


if __name__ == "__main__":
    main()
