"""Dev check on AIT-LDS v1.1 hosts kept out of context training (v9, Amendment 4).

For each host: the full pipeline ("model + sessions") and the rules baseline ("rules + rule
sessions") on every request, then
  - recall per AIT step (scan = nikto, bruteforce = hydra password POSTs, upload, webshell)
  - false alarms on normal requests, split into the normal user who shares the attacker's
    IP (NAT) and all other users.
Hydra's plain page loads and the ::1 OPTIONS lines the labels also mark are reported apart
("bruteforce page loads"): no log-only method can tell them from a visitor's.

    python -m eval.v9_ait_eval --name v8                       # current models
    python -m eval.v9_ait_eval --context models/context_v9.joblib --name v9ctx
"""
import argparse
from pathlib import Path

import joblib
import pandas as pd

import eval.final_test as ft
from ml.sessions import is_login_attempt

HOSTS = ["onion", "spiral"]          # dev hosts; cup and insect train the context model
ML, RULES = "model + sessions", "rules + rule sessions"
COLS = ["ip", "timestamp", "method", "path", "status", "size", "user_agent", "body", "label", "attack_type", "stage"]


def md(df):
    df = df.astype(object).where(df.notna(), "")
    cols = [str(c) for c in df.columns]
    return "\n".join(["| " + " | ".join(cols) + " |", "|" + "---|" * len(cols)]
                     + ["| " + " | ".join(str(v) for v in r) + " |" for r in df.values])


def load(host):
    df = pd.read_csv(f"data/processed/v9/ait_{host}.csv", usecols=COLS, dtype=str, keep_default_na=False)
    df["status"] = pd.to_numeric(df["status"], errors="coerce").fillna(0).astype(int)
    df["size"] = pd.to_numeric(df["size"], errors="coerce").fillna(0).astype(int)
    guess = [is_login_attempt(m, p, b) for m, p, b in zip(df["method"], df["path"], df["body"])]
    page_load = (df["attack_type"] == "bruteforce") & ~pd.Series(guess, index=df.index)
    df.loc[page_load, "attack_type"] = "bruteforce page loads"
    df["true_stage"] = df.pop("stage").where(~page_load, "")
    return df


def evaluate(host, stage_model="default"):
    from eval.run7_final import stage_scores
    from ml.stage import add_stages
    df = load(host)
    req, sessions = ft._pipeline(df.copy())
    att = req["label"] != "normal"
    attacker_ips = set(req.loc[att & (req["attack_type"] != "bruteforce page loads"), "ip"]) - {"::1"}
    rows = []
    for t, g in req[att].groupby("attack_type"):
        rows.append({"host": host, "what": t, "requests": len(g),
                     "ML": round(float(g[ML].mean()), 3), "rules": round(float(g[RULES].mean()), 3)})
    norm = req[~att]
    for name, m in [("FA: normal user on the attacker's IP", norm["ip"].isin(attacker_ips)),
                    ("FA: all other normal users", ~norm["ip"].isin(attacker_ips))]:
        g = norm[m]
        rows.append({"host": host, "what": name, "requests": len(g),
                     "ML": int(g[ML].sum()), "rules": int(g[RULES].sum())})
    # Stage (AIT: nikto = recon, hydra guesses = intrusion, upload / web shell = exploitation)
    req2, _ = add_stages(req, sessions, stage_model)
    st = stage_scores(req2)
    rows.append({"host": host, "what": "stage accuracy (attack requests the pipeline flagged)",
                 "requests": st.get("stage requests"), "ML": st.get("stage acc ML"), "rules": st.get("stage acc rules")})
    rows.append({"host": host, "what": "furthest stage per attacker session",
                 "requests": "", "ML": st.get("furthest ML"), "rules": st.get("furthest rules")})
    rows.append({"host": host, "what": "exploitation found ML/rules", "requests": "",
                 "ML": st.get("exploitation found ML/rules"), "rules": ""})
    for t in ["recon", "intrusion", "exploitation"]:
        m = req2["true_stage"] == t
        if m.any():
            rows.append({"host": host, "what": f"stage {t}: predicted as", "requests": int(m.sum()),
                         "ML": req2.loc[m, "stage"].replace("", "none").value_counts().to_dict(), "rules": ""})
    beh = req.loc[~att & (req[ML] == 1)].groupby("behaviour").size() if "behaviour" in req else pd.Series(dtype=int)
    return rows, beh.rename(host)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--context", default=None, help="context model path (default: models/context.joblib)")
    ap.add_argument("--model", default=None, help="detector path (default: models/detector.joblib)")
    ap.add_argument("--type", default=None, help="attack-type model path")
    ap.add_argument("--stage", default=None, help="stage model path (default: models/stage.joblib)")
    ap.add_argument("--name", default="current")
    ap.add_argument("--hosts", default=",".join(HOSTS))
    args = ap.parse_args()
    if args.context:
        model = joblib.load(args.context)
        ft.load_context_model = lambda: model
    if args.model:
        ft.MODEL_PATH = args.model
    if args.type:
        type_model = joblib.load(args.type)
        ft.load_type_model = lambda: type_model
    stage_model = joblib.load(args.stage) if args.stage else "default"
    out = Path("results/final_v9/ait_dev") / args.name
    out.mkdir(parents=True, exist_ok=True)
    rows, behs = [], []
    for h in args.hosts.split(","):
        r, b = evaluate(h, stage_model)
        rows += r
        behs.append(b)
        print(pd.DataFrame(r).to_string(index=False), flush=True)
    T = pd.DataFrame(rows)
    T.to_csv(out / "ait_dev.csv", index=False)
    B = pd.concat(behs, axis=1).fillna(0).astype(int).reset_index() if behs else pd.DataFrame()
    text = [f"# AIT dev check: {args.name}", "",
            f"Context model: `{args.context or 'models/context.joblib'}`. Hosts {args.hosts} (not used in training).",
            "Recall rows = share caught; FA rows = number of normal requests flagged.", "", md(T), "",
            "## Normal requests flagged by ML, by behaviour", "", md(B) if len(B) else "none", ""]
    (out / "AIT-DEV.md").write_text("\n".join(text), encoding="utf-8")
    print("written", out / "AIT-DEV.md")


if __name__ == "__main__":
    main()
