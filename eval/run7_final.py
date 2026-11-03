"""
run7: the single final test of the frozen v8 models (results/final_v8/PREREGISTRATION.md).

Run once, from the repository root, at tag v8.0-final-test plus the run7 data commits:

    python -m eval.run7_final

It first checks every hash (models and every run7 file) and stops if one does not match.
Then it measures, for the ML pipeline ("model + sessions") and the rules baseline
("rules + rule sessions") side by side:

  1. lab sites (7 seen + WebGoat unseen): recall, false alarms on normal users and inside
     attacker sessions, attack type, stage, defence action, next step;
  2. sealed tools: share of the tool's requests caught, normal users flagged next to it,
     defence action given to the tool's session;
  3. real logs (zanbil slice + 5 secrepo days): share of requests flagged;
  4. a blind sample of flagged real requests for hand labelling (no verdict or score in it).

Everything goes to results/final_v8/run7/ (tables, RUN7-RESULTS.md). The hand-label sample
holds real log lines and goes to data/run7_hand_label/, which is never committed.
"""
import argparse
import gzip
import hashlib
import json
import os
import sys
import time
import warnings
from pathlib import Path

import numpy as np
import pandas as pd

warnings.filterwarnings("ignore")

import eval.final_test as ft
from backend.app.log_parser import decode, parse_log
from ml.attack_type import TYPES, rule_types
from ml.defense import FixFinder, add_defense, load_block_rules
from ml.next_step import NextStepModel, add_next_steps
from ml.stage import STAGES, _RANK, attack_rows, rule_stages
from ml.stage import add_stages

ML, RULES = "model + sessions", "rules + rule sessions"
SITES = ["juiceshop", "dvwa", "bwapp", "mutillidae", "dvna", "vampi", "dvga", "webgoat"]
UNSEEN = {"webgoat"}
TOOLS = ["gobuster", "feroxbuster", "wfuzz", "dalfox", "medusa"]
TOOL_IP = "172.19.0.17"                 # the run7 tools container (run7_tools_runs.txt)
SECREPO_DAYS = ["2024-10-03", "2024-10-10", "2024-10-15", "2025-04-22", "2026-06-01"]
NEXT_STEP_CEILING = 0.38
SAMPLE_PER_LOG, SAMPLE_SEED = 200, 7007
OUT = Path("results/final_v8/run7")
HAND = Path("data/run7_hand_label")


# ---------------------------------------------------------------- files and hashes
def lab_paths(site, tag):
    pre = "" if site == "juiceshop" else site + "_"
    return (f"data/raw/{site}_generated_{tag}.log", f"data/labels/requests_{pre}{tag}.csv",
            f"data/labels/sessions_{pre}{tag}.csv")


def tool_path(tool, site, tools_dir):
    return f"{tools_dir}/tool_{tool}_{site}.log"


def sha256(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest().upper()


def read_hashes(path):
    """'HASH  name ...' lines -> {name: HASH} (the name is the first word after the hash)."""
    out = {}
    for line in Path(path).read_text(encoding="utf-8-sig").splitlines():
        parts = line.split()
        if len(parts) >= 2 and len(parts[0]) == 64:
            out[os.path.basename(parts[1])] = parts[0].upper()
    return out


def verify(args):
    """Every model and every run7 file must match its committed hash. Returns the check table."""
    checks = []

    def check(path, expected, what):
        got = sha256(path) if os.path.exists(path) else "MISSING"
        checks.append({"what": what, "file": path, "ok": got == expected})

    models = read_hashes("results/final_v8/models.sha256")
    for name, h in models.items():
        check(f"models/{name}", h, "model")
    lab = read_hashes("results/final_v8/run7_lab_hashes.txt")
    for site in SITES:
        for p in lab_paths(site, args.tag):
            check(p, lab.get(os.path.basename(p), "NOT IN HASH FILE"), "lab " + site)
    tools = read_hashes("results/final_v8/run7_tools_hashes.txt")
    for name, h in tools.items():
        check(f"{args.tools_dir}/{name}", h, "tool")
    zanbil = read_hashes("results/final_v8/run7_zanbil_hash.txt")
    check(args.zanbil, zanbil.get(os.path.basename(args.zanbil), "NOT IN HASH FILE"), "real zanbil")
    secrepo = read_hashes(args.secrepo_hashes)
    for day in SECREPO_DAYS:
        p = f"{args.sealed_dir}/access.log.{day}.gz"
        check(p, secrepo.get(os.path.basename(p), "NOT IN HASH FILE"), "real secrepo")
    table = pd.DataFrame(checks)
    if not table["ok"].all():
        print(table[~table["ok"]].to_string())
        raise SystemExit("Stopped: a hash does not match. Nothing was measured.")
    print(f"hashes: all {len(table)} match")
    return table


# ---------------------------------------------------------------- measures
def _rate(mask_num, mask_den):
    return round(float(mask_num[mask_den].mean()), 3) if mask_den.any() else None


def stage_scores(req):
    """Request accuracy and furthest stage per attacker session, ML and rules."""
    rows = attack_rows(req) & (req.get("true_stage", pd.Series("", index=req.index)) != "")
    if not rows.any():
        return {}
    t = req.loc[rows, "true_stage"]
    pm = req.loc[rows, "stage"]
    pr = rule_stages(req)[rows]

    def furthest(p):
        d = pd.DataFrame({"s": req.loc[rows, "session"], "t": t, "p": p})
        g = d.groupby("s")
        ft_ = g["t"].agg(lambda s: max(s, key=_RANK.get))
        fp = g["p"].agg(lambda s: max([x for x in s if x] or [""], key=lambda x: _RANK.get(x, 0)))
        return round(float((ft_ == fp).mean()), 3)
    out = {"stage requests": int(rows.sum()),
           "stage acc ML": round(float((pm == t).mean()), 3), "stage acc rules": round(float((pr == t).mean()), 3),
           "furthest ML": furthest(pm), "furthest rules": furthest(pr)}
    ex = t == "exploitation"
    out["exploitation found ML/rules"] = (f"{(pm[ex] == 'exploitation').mean():.2f}/{(pr[ex] == 'exploitation').mean():.2f} (n={int(ex.sum())})"
                                          if ex.any() else "n=0")
    return out


def defence_both(req, sessions):
    """Defence with the learned block rules (ML) and with the risk-level rules (baseline)."""
    ml = ft.defence_summary(req, add_defense(req, sessions, FixFinder(), load_block_rules()))
    base = ft.defence_summary(req, add_defense(req, sessions, FixFinder(), None))
    return ml, base


def lab_site(site, tag):
    log, labels, sess_labels = lab_paths(site, tag)
    req, sessions, report = ft.run(log, labels)
    y = req["label"] != "normal"
    attacker = req.groupby("session")["label"].transform(lambda s: (s != "normal").any())
    row = {"site": site, "seen in training": site not in UNSEEN, **{k: report[k] for k in ("log_lines", "matched")},
           "attacks": int(y.sum()), "normal requests": int((~y).sum()),
           "recall ML": _rate(req[ML] == 1, y), "recall rules": _rate(req[RULES] == 1, y),
           "FA normal users ML": int(req.loc[~attacker, ML].sum()), "FA normal users rules": int(req.loc[~attacker, RULES].sum()),
           "FA in attacker sessions ML": int(req.loc[attacker & ~y, ML].sum()),
           "FA in attacker sessions rules": int(req.loc[attacker & ~y, RULES].sum())}
    # attack type, of the payload attacks the detector caught: model vs the payload rules
    c = (req["pred"] == 1) & req["attack_type"].isin(TYPES)
    if c.any():
        rt = rule_types(req.loc[c, "method"], req.loc[c, "path"], req.loc[c, "body"])
        row["type acc ML"] = round(float((req.loc[c, "type_pred"] == req.loc[c, "attack_type"]).mean()), 3)
        row["type acc rules"] = round(float((pd.Series(rt, index=req.index[c]) == req.loc[c, "attack_type"]).mean()), 3)
        row["typed requests"] = int(c.sum())
    req2, sessions2 = add_stages(req, sessions)
    row.update(stage_scores(req2))
    sessions2 = add_next_steps(req2, sessions2, NextStepModel.load())
    dml, dbase = defence_both(req2, sessions2)
    for k in ("action right", "attackers allowed", "normal users blocked"):
        row[f"defence {k} ML"], row[f"defence {k} rules"] = dml[k], dbase[k]
    ns = ft.next_step_summary(req2, sess_labels)
    for k in ("campaigns", "top-1 (true order)", "top-3 (true order)", "top-1 (order read)", "top-3 (order read)"):
        row["next " + k] = ns[k]
    by_type = req[y].groupby("attack_type")[[ML, RULES]].mean().round(3).reset_index().assign(site=site)
    return row, by_type


def lab_normals(site, tag):
    """The run7 normal users of one site, as background for that site's tool logs."""
    log, labels, _ = lab_paths(site, tag)
    df, _ = __import__("eval.match_labels", fromlist=["match"]).match(log, labels)
    att = df.groupby("ip")["attack_type"].transform(lambda s: (s.fillna("") != "").any())
    return df[~att][["ip", "timestamp", "method", "path", "status", "size", "user_agent", "body"]].copy()


def tool_run(tool, site, tools_dir, tag):
    path = tool_path(tool, site, tools_dir)
    if not os.path.exists(path):
        return None
    t = pd.DataFrame(parse_log(decode(open(path, "rb").read()))[0])
    row = {"tool": tool, "site": site, "seen site": site not in UNSEEN, "tool requests": len(t)}
    if t.empty:
        return {**row, "note": "no requests"}
    t = t[t["ip"] == TOOL_IP].copy()
    bg = lab_normals(site, tag)
    # The tool ran alone against the lab: its lines are put next to the run7 normal users
    # of the same site, starting with them, so false alarms on normal users can be counted.
    tt, bt = pd.to_datetime(t["timestamp"], utc=True), pd.to_datetime(bg["timestamp"], utc=True)
    t["timestamp"] = (tt - tt.min() + bt.min()).astype(str)
    df = pd.concat([bg, t[bg.columns]], ignore_index=True)
    is_tool = df["ip"] == TOOL_IP
    df["label"] = np.where(is_tool, "attack", "normal")
    df["attack_type"] = np.where(is_tool, "tool", "")
    req, sessions = ft._pipeline(df)
    tr = req["ip"] == TOOL_IP
    req2, sessions2 = add_stages(req, sessions)
    sessions2 = add_next_steps(req2, sessions2, NextStepModel.load())
    tool_sessions = set(req2.loc[tr, "session"])
    act_ml = add_defense(req2, sessions2, FixFinder(), load_block_rules())
    act_rules = add_defense(req2, sessions2, FixFinder(), None)
    pick = lambda s: ",".join(sorted(set(s.loc[s["session"].isin(tool_sessions), "action"])))
    row.update({"caught ML": _rate(req[ML] == 1, tr), "caught rules": _rate(req[RULES] == 1, tr),
                "normal users flagged ML": int(req.loc[~tr, ML].sum()),
                "normal users flagged rules": int(req.loc[~tr, RULES].sum()),
                "tool action ML": pick(act_ml), "tool action rules": pick(act_rules),
                "normal users blocked ML": int(((~act_ml["session"].isin(tool_sessions)) & (act_ml["action"] == "block")).sum())})
    return row


def read_real(path):
    raw = open(path, "rb").read()
    if path.endswith(".gz"):
        raw = gzip.decompress(raw)
    rows, skipped = parse_log(decode(raw))
    df = pd.DataFrame(rows)
    df["label"], df["attack_type"] = "normal", ""
    return df, skipped


def real_log(name, path):
    df, skipped = read_real(path)
    req, sessions = ft._pipeline(df)
    row = {"log": name, "requests": len(req), "skipped lines": skipped,
           "flagged ML": round(float(req[ML].mean()), 4), "flagged rules": round(float(req[RULES].mean()), 4),
           "flagged ML n": int(req[ML].sum()), "flagged rules n": int(req[RULES].sum()),
           "sessions": int(req["session"].nunique()),
           "sessions flagged ML": int(req.loc[req[ML] == 1, "session"].nunique()),
           "sessions flagged rules": int(req.loc[req[RULES] == 1, "session"].nunique())}
    # Blind hand-label sample: up to 200 ML-flagged requests, with their session, no verdict or score.
    flagged = req[req[ML] == 1]
    pick = flagged.sample(n=min(SAMPLE_PER_LOG, len(flagged)), random_state=SAMPLE_SEED) if len(flagged) else flagged
    cols = ["session", "ip", "timestamp", "method", "path", "status", "size", "user_agent", "body"]
    sample = pick[[c for c in cols if c in pick]].copy()
    sample.insert(0, "item", range(1, len(sample) + 1))
    sample["judgement (attack / not attack / unclear)"] = ""
    context = req[req["session"].isin(set(sample["session"]))][[c for c in cols if c in req]]
    HAND.mkdir(parents=True, exist_ok=True)
    sample.to_csv(HAND / f"{name}_sample.csv", index=False)
    context.sort_values(["session", "timestamp"]).to_csv(HAND / f"{name}_sessions.csv", index=False)
    row["hand-label sample"] = len(sample)
    return row


# ---------------------------------------------------------------- report
def markdown(table):
    """A Markdown table without extra packages."""
    cells = lambda r: "| " + " | ".join("" if pd.isna(v) else str(v) for v in r) + " |"
    lines = [cells(table.columns), "|" + "---|" * len(table.columns)]
    return "\n".join(lines + [cells(r) for r in table.itertuples(index=False)])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--tag", default="run7")
    ap.add_argument("--tools-dir", default="data/sealed/run7_tools")
    ap.add_argument("--zanbil", default="data/sealed/zanbil_run7.log")
    ap.add_argument("--sealed-dir", default="data/sealed")
    ap.add_argument("--secrepo-hashes", default="results/final_v8/run7_secrepo_hashes.txt")
    ap.add_argument("--no-verify", action="store_true", help="dev data only: skip the hash check")
    ap.add_argument("--parts", default="lab,tools,real")
    args = ap.parse_args()
    OUT.mkdir(parents=True, exist_ok=True)
    t0 = time.time()
    if not args.no_verify:
        verify(args).to_csv(OUT / "hash_checks.csv", index=False)
    parts = args.parts.split(",")
    md = ["# run7 final results", "",
          "Frozen v8 models, run once, measured as fixed in `PREREGISTRATION.md`. "
          "ML = learned pipeline (`model + sessions`), rules = baseline (`rules + rule sessions`). "
          "Every number is reported whatever it shows.", ""]
    if "lab" in parts:
        rows, types = [], []
        for site in SITES:
            if not os.path.exists(lab_paths(site, args.tag)[0]):
                print("missing lab run", site); continue
            r, bt = lab_site(site, args.tag); rows.append(r); types.append(bt)
            print("lab", site, r["recall ML"], r["recall rules"], flush=True)
        L = pd.DataFrame(rows); L.to_csv(OUT / "lab_sites.csv", index=False)
        pd.concat(types).to_csv(OUT / "lab_recall_by_type.csv", index=False)
        md += ["## 1. Lab sites (WebGoat = unseen site)", "", markdown(L[[c for c in L.columns if not c.startswith(("next", "defence", "stage", "furthest", "exploitation"))]]), "",
               "### Stage and defence", "", markdown(L[["site"] + [c for c in L.columns if c.startswith(("stage", "furthest", "exploitation", "defence"))]]), "",
               f"### Next step (ceiling {NEXT_STEP_CEILING} from the generator's random choice)", "",
               markdown(L[["site"] + [c for c in L.columns if c.startswith("next")]]), ""]
    if "tools" in parts:
        rows = [r for tool in TOOLS for site in SITES if (r := tool_run(tool, site, args.tools_dir, args.tag))]
        for r in rows:
            print("tool", r["tool"], r["site"], r.get("caught ML"), flush=True)
        T = pd.DataFrame(rows); T.to_csv(OUT / "tools.csv", index=False)
        md += ["## 2. Sealed tools", "", "medusa ran on bWAPP and Mutillidae only (Amendment 2).", "", markdown(T), ""]
    if "real" in parts:
        logs = [("zanbil_9.0-9.2M", args.zanbil)] + [(f"secrepo_{d}", f"{args.sealed_dir}/access.log.{d}.gz") for d in SECREPO_DAYS]
        rows = []
        for name, path in logs:
            if os.path.exists(path):
                rows.append(real_log(name, path)); print("real", name, rows[-1]["flagged ML"], flush=True)
        R = pd.DataFrame(rows); R.to_csv(OUT / "real_logs.csv", index=False)
        md += ["## 3. Real logs: share of requests flagged", "", markdown(R), "",
               "## 4. Hand-labelled precision", "",
               f"Blind samples (up to {SAMPLE_PER_LOG} ML-flagged requests per log, seed {SAMPLE_SEED}) are in "
               f"`{HAND}/` (not committed: real log lines). Labelled with the criteria of PREREGISTRATION section 4; "
               "precision with a 95% interval comes from `python -m eval.run7_precision` after labelling.", ""]
    md += [f"Run time: {time.time() - t0:.0f} s.", ""]
    (OUT / "RUN7-RESULTS.md").write_text("\n".join(md), encoding="utf-8")
    print("written", OUT / "RUN7-RESULTS.md")


if __name__ == "__main__":
    main()
