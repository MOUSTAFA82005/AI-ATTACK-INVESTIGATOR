"""
Train the context model (ml/context_model.py) -> models/context.joblib

Training data, three kinds:
  1. labelled lab runs of five sites: Juice Shop and DVWA (run3, run4, run5, camp7, v4dev,
     st21, st22) and bWAPP, Mutillidae, DVNA (st31, st32); missing runs are skipped
  2. real traffic of a real shop (zanbil.ir, first 200,000 lines) as normal visitors
     (unlabelled: a few bad bots in it are counted as normal, a known source of noise)
  (each lab behaviour attack is also added alone from a new address, and inside a normal
  visitor's browsing: see with_solo_copies, mixed_copies)
  3. real tools (scanners/fuzzers = scan, hydra = brute force; TOOL_BEHAVIOUR) laid over
     the normal visitors of a run of the same site, so the tool is one visitor among
     many, as in a real log

    python -m ml.train_context [tools_dir] [zanbil_log]

tools_dir defaults to data/raw (files tool_<tool>_<site>.log); missing files are skipped.
"""
import glob
import os
import sys
from itertools import islice

import joblib
import pandas as pd

from backend.app.log_parser import decode, parse_log
from eval.match_labels import match
from ml.context_model import LABEL_OF, MODEL_PATH, PASSWORD, context_features, fit, target, training_target
from ml.sessions import field_names, is_login_attempt
from ml.detector import MODEL_PATH as DETECTOR_PATH, to_frame

LAB_RUNS = ["run3", "run4", "run5", "camp7", "v4dev", "st21", "st22", "st31", "st32"]
LAB_SITES = ["juiceshop", "dvwa", "bwapp", "mutillidae", "dvna", "vampi", "dvga"]
# Real tools, by family: what behaviour each one is. A file tool_<name>_<site>.log is one
# run; its family is the part of <name> before "_" (nikto_ev -> nikto). Payload tools
# (sqlmap, wapiti) are the detector's job and are not used here.
TOOL_BEHAVIOUR = {"nikto": "scan", "ffuf": "scan", "dirb": "scan", "nmap": "scan", "whatweb": "scan",
                  "hydra": "bruteforce", "sqlmap": "scan", "wapiti": "scan"}
PROBING_TOOLS = {"sqlmap", "wapiti"}
BACKGROUND_RUNS = ["run4", "st31"]      # whose normal visitors the tool is laid over (first found)
ZANBIL_LINES = 200_000
# More real traffic from other kinds of sites, all taken as normal (a few scanners may hide in
# them; that label noise is small). With one real site only, every retrain found a different
# shortcut that flagged ordinary clients somewhere else (package managers retrying a URL,
# crawlers). Each is tested with itself left out (results/real_loo.csv).
REAL_NORMAL_LOGS = {"publog": "public_apache_logs.log",        # elastic examples, apache
                    "nasa": "nasa_access_jul95.log",            # NASA KSC, July 1995
                    "nginx": "nginx_elastic.log"}               # elastic examples, nginx
REAL_LINES = 100_000
# AIT-LDS v1.1 (v9, real tools against a webmail server with simulated users; converted by
# eval/v9_convert_ait.py). Two hosts train, the other two are kept for the dev check
# (eval/v9_ait_eval.py). nikto = scan, hydra = brute force; upload / web shell are not behaviour.
AIT_TRAIN_HOSTS = ("cup", "insect")
AIT_DIR = "data/processed/v9"
AIT_COLS = ["ip", "timestamp", "method", "path", "status", "size", "user_agent", "body", "attack_type"]


def _with_proba(df, detector):
    df["proba"] = detector.predict_proba(to_frame(df["method"], df["path"], df["body"]))[:, 1]
    return df


def lab_runs(detector):
    from ml.train_stage import run_paths
    for site in LAB_SITES:
        for run in LAB_RUNS:
            log, labels = run_paths(site, run)
            if os.path.exists(log) and os.path.exists(labels):
                yield site, run, _with_proba(match(log, labels)[0], detector)


def _normal_users(df):
    attacker = df.groupby("ip")["attack_type"].transform(lambda s: (s.fillna("") != "").any())
    return df[~attacker]


def with_solo_copies(df):
    """Each brute force / enumeration / scan of the run again, sent alone from a new
    address. In the lab every attacker also logs in and opens other pages; a script that
    only sweeps IDs or only guesses passwords must look like the same attack."""
    behaviour = df["attack_type"].fillna("").isin(list(LABEL_OF))
    solo = df[behaviour].copy()
    solo["ip"] = "solo-" + solo["ip"].astype(str) + "-" + solo["attack_type"]
    # ... and an ID sweep of a resource ordinary visitors never open (in the lab they
    # open the same baskets and records the enumerator walks through).
    enum = solo["attack_type"] == "enum"
    solo.loc[enum, "path"] = "/internal" + solo.loc[enum, "path"].astype(str)
    return pd.concat([df, solo, mixed_copies(df)], ignore_index=True)


# Mixed in for scans and ID sweeps only. Mixing brute forces too was tried: a normal user who
# logs in again a few times then looked like a brute force (DVWA: 42 normal requests flagged).
MIXED_KINDS = ["enum", "scan"]


def mixed_copies(df):
    """Each enumeration / scan again, inside an ordinary visitor's browsing: the attack's
    requests plus a copy of one normal visitor's requests, all from one new address. Without
    it the model learned that a scan is a session that does nothing else, and on a real log
    it read short visits that only hit missing pages (clients asking for 2-3 URLs that
    answer 404) as scans: 43% of a real nginx log left out of training, 5% with it."""
    behaviour = df["attack_type"].fillna("").isin(MIXED_KINDS)
    visitors = _normal_users(df)
    names = sorted(visitors["ip"].astype(str).unique())
    if not names or not behaviour.any():
        return df.iloc[:0]
    by_ip = {ip: g for ip, g in visitors.groupby(visitors["ip"].astype(str))}
    out = []
    for k, ((ip, kind), attack) in enumerate(df[behaviour].groupby([df["ip"].astype(str), "attack_type"])):
        visit = by_ip[names[k % len(names)]].copy()
        at, vt = pd.to_datetime(attack["timestamp"], utc=True), pd.to_datetime(visit["timestamp"], utc=True)
        # the visit starts a little before the attack and keeps its own pace
        visit["timestamp"] = (vt - vt.min() + at.min() - pd.Timedelta(seconds=30)).astype(str)
        attack = attack.copy()
        new_ip = f"mixed-{ip}-{kind}"
        attack["ip"] = visit["ip"] = new_ip
        out += [visit, attack]
    return pd.concat(out, ignore_index=True)


def tool_runs(tools_dir):
    """[(name, family, site, path)] of the tool logs in tools_dir."""
    out = []
    for path in sorted(glob.glob(os.path.join(tools_dir, "tool_*_*.log"))):
        name, _, site = os.path.basename(path)[5:-4].rpartition("_")
        if site in LAB_SITES and os.path.getsize(path) > 0:
            out.append((name, name.split("_")[0], site, path))
    return out


def tool_overlay(path, behaviour, background, detector):
    t = pd.DataFrame(parse_log(decode(open(path, "rb").read()))[0])
    t = t[t["ip"] == t["ip"].value_counts().idxmax()].copy()      # the tool's own address
    t["ip"] = "tool-" + os.path.basename(path)
    t = _with_proba(t, detector)
    t["attack_type"] = behaviour
    if behaviour == "scan" and os.path.basename(path).split("_")[1] in PROBING_TOOLS:
        # A parameter prober's own requests are the ones that send values to a form. Its
        # plain page loads (the same page again and again) look like any client that
        # refreshes or retries; labelled "scan" they taught that repeating a page is a scan
        # (real log: package managers retrying one download URL were flagged).
        sends = [len(field_names(p, b)) > 0 for p, b in zip(t["path"], t["body"].fillna(""))]
        t.loc[~pd.Series(sends, index=t.index), "attack_type"] = "tool_other"
    if behaviour == "bruteforce":
        # A brute forcer also loads the login page before each guess. That plain page view
        # looks like any visitor's, so it is left out of training ("tool_other" has no
        # label) instead of teaching that ordinary page views are brute force.
        guess = [bool(PASSWORD.search(",".join(field_names(p, b)))) for p, b in zip(t["path"], t["body"].fillna(""))]
        t.loc[~pd.Series(guess, index=t.index), "attack_type"] = "tool_other"
    bg = _normal_users(background).copy()
    # move the tool's requests into the background's time window, keeping their own pace
    tt, bt = pd.to_datetime(t["timestamp"], utc=True), pd.to_datetime(bg["timestamp"], utc=True)
    t["timestamp"] = (tt - tt.min() + bt.min()).astype(str)
    return pd.concat([bg, t], ignore_index=True)


def real_logs(raw_dir, detector, skip=()):
    """(name, requests) for each REAL_NORMAL_LOGS file found in raw_dir, first REAL_LINES lines."""
    for name, file in REAL_NORMAL_LOGS.items():
        path = os.path.join(raw_dir, file)
        if name in skip or not os.path.exists(path):
            if name not in skip:
                print("skipped (missing):", path)
            continue
        with open(path, "rb") as f:
            df = pd.DataFrame(parse_log(decode(b"".join(islice(f, REAL_LINES))))[0])
        if "body" not in df:
            df["body"] = ""
        df = _with_proba(df, detector)
        df["attack_type"] = ""
        yield name, df


def real_normal(zanbil_log, detector):
    if not os.path.exists(zanbil_log):
        print("skipped (missing):", zanbil_log)
        return None
    with open(zanbil_log, "rb") as f:
        text = decode(b"".join(islice(f, ZANBIL_LINES)))
    df = _with_proba(pd.DataFrame(parse_log(text)[0]), detector)
    df["attack_type"] = ""
    return df


def ait_logs(detector, hosts=AIT_TRAIN_HOSTS):
    """(host, requests) of the AIT hosts found in AIT_DIR. As with the tool overlays, a hydra
    line that sends no password (its page loads, and the ::1 OPTIONS lines the labels also
    mark) is left out of training instead of teaching that plain page views are brute force."""
    for host in hosts:
        path = os.path.join(AIT_DIR, f"ait_{host}.csv")
        if not os.path.exists(path):
            print("skipped (missing):", path)
            continue
        df = pd.read_csv(path, usecols=AIT_COLS, dtype={"body": str, "user_agent": str}, keep_default_na=False)
        df["status"] = pd.to_numeric(df["status"], errors="coerce").fillna(0).astype(int)
        df["size"] = pd.to_numeric(df["size"], errors="coerce").fillna(0).astype(int)
        df["attack_type"] = df["attack_type"].replace({"upload": "tool_other", "webshell": "tool_other"})
        guess = pd.Series([is_login_attempt(m, p, b) for m, p, b in zip(df["method"], df["path"], df["body"])],
                          index=df.index)
        df.loc[(df["attack_type"] == "bruteforce") & ~guess, "attack_type"] = "tool_other"
        yield host, _with_proba(df, detector)


def build(tools_dir="data/raw", zanbil_log="data/raw/zanbil_access.log", skip_sites=(), skip_families=(),
          skip_real=(), raw_dir="data/raw", ait_hosts=AIT_TRAIN_HOSTS):
    """skip_sites / skip_families / skip_real: left out of training (leave-one-site-out /
    leave-one-tool-out / leave-one-real-log-out)."""
    detector = joblib.load(DETECTOR_PATH)
    X, y, backgrounds = [], [], {}
    for site, run, df in lab_runs(detector):
        if site in skip_sites:
            continue
        F, d = context_features(with_solo_copies(df))
        X.append(F), y.append(training_target(d, F))
        if run in BACKGROUND_RUNS and site not in backgrounds:
            backgrounds[site] = df
    for name, family, site, path in tool_runs(tools_dir):
        if family not in TOOL_BEHAVIOUR or family in skip_families or site not in backgrounds:
            continue
        mixed = tool_overlay(path, TOOL_BEHAVIOUR[family], backgrounds[site], detector)
        F, d = context_features(mixed)
        X.append(F), y.append(training_target(d, F))
    real = real_normal(zanbil_log, detector)
    if real is not None:
        F, d = context_features(real)
        X.append(F), y.append(training_target(d, F))
    for _, df in real_logs(raw_dir, detector, skip_real):
        F, d = context_features(df)
        X.append(F), y.append(training_target(d, F))
    for _, df in ait_logs(detector, ait_hosts):
        F, d = context_features(df)
        X.append(F), y.append(training_target(d, F))
    X, y = pd.concat(X, ignore_index=True), pd.concat(y, ignore_index=True)
    keep = y.notna()                     # payload attacks are the detector's job
    return X[keep], y[keep]


if __name__ == "__main__":
    # python -m ml.train_context [tools_dir] [zanbil_log] [out_path]
    X, y = build(*sys.argv[1:3])
    print(y.value_counts().to_string())
    out = sys.argv[3] if len(sys.argv) > 3 else MODEL_PATH
    joblib.dump(fit(X, y), out)
    print("saved", out)
