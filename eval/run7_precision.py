"""
run7 hand-labelled precision (PREREGISTRATION sections 3.4 and 4).

The blind samples are in data/sealed/run7_hand_label/<log>_sample.csv (written by
eval/run7_final.py). Fill the last column of each row with one of:
    a = attack      n = not attack      u = unclear
(the full words work too). <log>_sessions.csv holds every request of the sampled
sessions, for context. Neither file shows the model's verdict or score.

    python -m eval.run7_precision --make-second     # 50 random items for the second labeller
    python -m eval.run7_precision                   # precision + 95% interval (+ agreement)

The second labeller fills data/sealed/run7_hand_label/second/second_sample.csv the same
way, without looking at the first labeller's answers. Results go to
results/final_v8/run7/precision.csv and precision.md (numbers only, no log lines).
"""
import argparse
import math
from pathlib import Path

import pandas as pd

HAND = Path("data/sealed/run7_hand_label")
SECOND = HAND / "second" / "second_sample.csv"
OUT = Path("results/final_v8/run7")
COL = "judgement (attack / not attack / unclear)"
CODES = {"a": "attack", "attack": "attack", "n": "not attack", "not attack": "not attack",
         "not": "not attack", "u": "unclear", "unclear": "unclear"}


def norm(v):
    return CODES.get(str(v).strip().lower(), "" if pd.isna(v) or not str(v).strip() else "INVALID")


def wilson(k, n, z=1.96):
    """95% Wilson interval for k successes out of n."""
    if n == 0:
        return float("nan"), float("nan")
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return round(c - h, 3), round(c + h, 3)


def samples():
    for f in sorted(HAND.glob("*_sample.csv")):
        yield f.name[: -len("_sample.csv")], pd.read_csv(f, keep_default_na=False)


def make_second(n=50, seed=7007):
    rows = [df.assign(log=log)[["log", "item", "session", "ip", "timestamp", "method", "path", "status",
                                "size", "user_agent", "body"]] for log, df in samples()]
    allrows = pd.concat(rows, ignore_index=True)
    pick = allrows.sample(n=min(n, len(allrows)), random_state=seed)
    pick[COL] = ""
    SECOND.parent.mkdir(parents=True, exist_ok=True)
    pick.to_csv(SECOND, index=False)
    print(f"wrote {len(pick)} items to {SECOND}")


def kappa(a, b):
    labels = sorted(set(a) | set(b))
    n = len(a)
    po = sum(x == y for x, y in zip(a, b)) / n
    pe = sum((list(a).count(l) / n) * (list(b).count(l) / n) for l in labels)
    return round((po - pe) / (1 - pe), 3) if pe < 1 else 1.0


def label(path):
    """Label one sample file in the terminal: each item is shown with its session; answer a / n / u.
    Progress is saved after every answer, so it can be stopped (q) and resumed."""
    df = pd.read_csv(path, keep_default_na=False)
    log = path.name[: -len("_sample.csv")] if path.name.endswith("_sample.csv") else None
    ctx = pd.read_csv(HAND / f"{log}_sessions.csv", keep_default_na=False) if log and (HAND / f"{log}_sessions.csv").exists() else None
    todo = [i for i in df.index if norm(df.at[i, COL]) in ("", "INVALID")]
    print(f"{path.name}: {len(df) - len(todo)} of {len(df)} done")
    for n, i in enumerate(todo, 1):
        r = df.loc[i]
        print("\n" + "=" * 100)
        print(f"item {r['item']} ({n}/{len(todo)} left in this file)")
        if ctx is not None:
            s = ctx[ctx["session"].astype(str) == str(r["session"])]
            print(f"session: {len(s)} requests (first 15 shown)")
            for _, q in s.head(15).iterrows():
                print(f"   {q['method']} {q['path'][:140]}  -> {q['status']}")
        print(f"\n>> {r['method']} {r['path']}\n   status {r['status']}  size {r['size']}  agent {str(r['user_agent'])[:80]}")
        if str(r.get("body", "")):
            print(f"   body {str(r['body'])[:300]}")
        while True:
            a = input("attack (a) / not attack (n) / unclear (u) / quit (q): ").strip().lower()
            if a in ("a", "n", "u", "q"):
                break
        if a == "q":
            return
        df.at[i, COL] = a
        df.to_csv(path, index=False)
    print("file done")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--make-second", action="store_true")
    ap.add_argument("--label", metavar="FILE", help="label one sample file in the terminal")
    args = ap.parse_args()
    if args.make_second:
        return make_second()
    if args.label:
        return label(Path(args.label))
    rows, first = [], {}
    for log, df in samples():
        j = df[COL].map(norm)
        bad = int((j == "INVALID").sum()); empty = int((j == "").sum())
        a, na, u = int((j == "attack").sum()), int((j == "not attack").sum()), int((j == "unclear").sum())
        lo, hi = wilson(a, a + na)
        rows.append({"log": log, "sampled": len(df), "labelled": a + na + u, "not labelled": empty, "invalid": bad,
                     "attack": a, "not attack": na, "unclear": u,
                     "precision": round(a / (a + na), 3) if a + na else None, "95% low": lo, "95% high": hi})
        for item, v in zip(df["item"], j):
            first[(log, item)] = v
    P = pd.DataFrame(rows)
    A, N = int(P["attack"].sum()), int(P["not attack"].sum())
    lo, hi = wilson(A, A + N)
    P.loc[len(P)] = {"log": "all real logs", "sampled": int(P["sampled"].sum()), "labelled": int(P["labelled"].sum()),
                     "not labelled": int(P["not labelled"].sum()), "invalid": int(P["invalid"].sum()),
                     "attack": A, "not attack": N, "unclear": int(P["unclear"].sum()),
                     "precision": round(A / (A + N), 3) if A + N else None, "95% low": lo, "95% high": hi}
    OUT.mkdir(parents=True, exist_ok=True)
    P.to_csv(OUT / "precision.csv", index=False)
    md = ["# run7 hand-labelled precision", "",
          "Precision = attack / (attack + not attack); unclear is counted apart (PREREGISTRATION section 4). "
          "95% Wilson interval.", "", P.to_string(index=False), ""]
    if SECOND.exists():
        s = pd.read_csv(SECOND, keep_default_na=False)
        s["second"] = s[COL].map(norm)
        s["first"] = [first.get((l, i), "") for l, i in zip(s["log"], s["item"])]
        both = s[(s["first"].isin(CODES.values())) & (s["second"].isin(CODES.values()))]
        if len(both):
            agree = round(float((both["first"] == both["second"]).mean()), 3)
            md += [f"Second labeller: {len(both)} items labelled by both, agreement {agree}, "
                   f"Cohen's kappa {kappa(both['first'], both['second'])}.", ""]
    (OUT / "precision.md").write_text("\n".join(md), encoding="utf-8")
    print("\n".join(md))


if __name__ == "__main__":
    main()
