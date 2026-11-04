"""Defence replay on real attack chains (v9, dev): AIT-LDS v1.1 hosts kept out of training.

The log is replayed up to a series of checkpoints (after the attacker's 1st, 3rd, 10th, ...
attack request, and just after the first password guess and the first upload). At each
checkpoint the whole pipeline runs on what the log holds so far and decides an action for
the attacker's session (block / rate_limit / allow), with the learned block rules (ML) and
with the risk-level rules (baseline). Reported:
  - the first checkpoint where the attacker is blocked (or rate-limited);
  - which later steps of the chain (brute force, web-shell upload, web-shell use) come after
    that point, i.e. would have been stopped by the block;
  - share of the attacker's attack requests that come after the block;
  - on the full log: normal users' sessions blocked / rate-limited. The attacker shares its IP
    with a normal user (NAT), so blocking that IP also blocks that user; counted apart.
Checkpoints are coarse: the real block point is at or before the one reported.

    python -m eval.v9_defence_replay --model models/detector_v9_holdout2.joblib \
        --context models/context_v9.joblib --type models/attack_type_v9.joblib --stage models/stage_v9.joblib --name v9
"""
import argparse
from pathlib import Path

import joblib
import pandas as pd

import eval.final_test as ft
from eval.v9_ait_eval import load
from ml.defense import FixFinder, add_defense, load_block_rules
from ml.next_step import NextStepModel, add_next_steps
from ml.stage import add_stages

HOSTS = ["onion", "spiral"]
COUNTS = [1, 3, 10, 30, 100, 300, 1000, 3000]
SEVERITY = {"allow": 0, "rate_limit": 1, "block": 2}


def decide(df, stage_model, tree, finder, nsm):
    """Pipeline on df; returns per-session actions (ML, rules) and the request table."""
    req, sessions = ft._pipeline(df.copy())
    req2, s2 = add_stages(req, sessions, stage_model)
    s2 = add_next_steps(req2, s2, nsm)
    ml = add_defense(req2, s2, finder, tree)[["session", "ip", "action"]]
    rules = add_defense(req2, s2, finder, None)[["session", "ip", "action"]]
    return ml, rules, req2


def ip_action(actions, ip):
    a = actions.loc[actions["ip"] == ip, "action"]
    return max(a, key=SEVERITY.get) if len(a) else "allow"


def replay(host, stage_model, tree, finder, nsm):
    df = load(host).copy()
    df["_t"] = pd.to_datetime(df["timestamp"], utc=True)
    df = df.sort_values("_t", kind="stable").reset_index(drop=True)
    att = df["label"] != "normal"
    real = att & (df["attack_type"] != "bruteforce page loads") & (df["ip"] != "::1")
    ip = df.loc[real, "ip"].value_counts().idxmax()
    a = df[real & (df["ip"] == ip)]
    marks = {f"after attack request {n}": a["_t"].iloc[n - 1] for n in COUNTS if n <= len(a)}
    for kind in ["bruteforce", "upload"]:
        k = a[a["attack_type"] == kind]
        if len(k):
            marks[f"after first {kind}"] = k["_t"].iloc[0]
    marks = dict(sorted(marks.items(), key=lambda kv: kv[1]))
    steps = {k: a.loc[a["attack_type"] == k, "_t"].min() for k in ["scan", "bruteforce", "upload", "webshell"]}
    rows, first = [], {"ML": None, "rules": None}
    for name, t in marks.items():
        ml, rules, _ = decide(df[df["_t"] <= t].drop(columns="_t"), stage_model, tree, finder, nsm)
        r = {"host": host, "checkpoint": name, "time": str(t), "ML": ip_action(ml, ip), "rules": ip_action(rules, ip)}
        rows.append(r)
        print(r, flush=True)
        for who in ("ML", "rules"):
            if first[who] is None and r[who] == "block":
                first[who] = t
    summary = []
    ml, rules, req = decide(df.drop(columns="_t"), stage_model, tree, finder, nsm)
    for who, acts in (("ML", ml), ("rules", rules)):
        t = first[who]
        stopped = {k: (t is not None and pd.notna(v) and v > t) for k, v in steps.items()}
        normal_ips = set(df.loc[~df["ip"].isin([ip, "::1"]), "ip"])
        other = acts[acts["ip"].isin(normal_ips)]
        summary.append({"host": host, "who": who, "blocked at": "never" if t is None else str(t),
                        "attack requests after block": round(float((a["_t"] > t).mean()), 3) if t is not None else 0.0,
                        **{f"{k} stopped": v for k, v in stopped.items() if k != "scan"},
                        "action on attacker at end": ip_action(acts, ip),
                        "other users' sessions blocked": int((other["action"] == "block").sum()),
                        "other users' sessions rate-limited": int((other["action"] == "rate_limit").sum()),
                        "other users' sessions": len(other)})
    return rows, summary


def md(df):
    df = df.astype(object).where(df.notna(), "")
    cols = [str(c) for c in df.columns]
    return "\n".join(["| " + " | ".join(cols) + " |", "|" + "---|" * len(cols)]
                     + ["| " + " | ".join(str(v) for v in r) + " |" for r in df.values])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model"), ap.add_argument("--context"), ap.add_argument("--type"), ap.add_argument("--stage")
    ap.add_argument("--name", default="current")
    ap.add_argument("--hosts", default=",".join(HOSTS))
    args = ap.parse_args()
    if args.model:
        ft.MODEL_PATH = args.model
    if args.context:
        c = joblib.load(args.context)
        ft.load_context_model = lambda: c
    if args.type:
        t = joblib.load(args.type)
        ft.load_type_model = lambda: t
    stage_model = joblib.load(args.stage) if args.stage else "default"
    tree, finder, nsm = load_block_rules(), FixFinder(), NextStepModel.load()
    rows, summ = [], []
    for h in args.hosts.split(","):
        r, s = replay(h, stage_model, tree, finder, nsm)
        rows += r
        summ += s
        print(pd.DataFrame(s).to_string(index=False), flush=True)
    out = Path("results/final_v9/defence_replay") / args.name
    out.mkdir(parents=True, exist_ok=True)
    R, S = pd.DataFrame(rows), pd.DataFrame(summ)
    R.to_csv(out / "checkpoints.csv", index=False)
    S.to_csv(out / "summary.csv", index=False)
    (out / "DEFENCE-REPLAY.md").write_text("\n".join([
        f"# Defence replay on AIT: {args.name}", "", "Hosts not used in training. See the module docstring for the method.", "",
        "## Summary", "", md(S), "", "## Action on the attacker at each checkpoint", "", md(R), ""]), encoding="utf-8")
    print("written", out / "DEFENCE-REPLAY.md")


if __name__ == "__main__":
    main()
