"""
Post-hoc analysis of the v11 sealed test (results/final_v11/sealed/SEALED-RESULTS.md). ANALYSIS ONLY: nothing here
changes a model, a threshold or a reported number. Findings go to the report as error analysis / future work.

    python -m eval.v11_sealed_analysis      # -> results/final_v11/sealed/ANALYSIS.md (numbers only)
                                            #    data/processed/v11/sealed/missed_families_v11.csv (real paths, never committed)

Questions:
1. What kind of attack families does each detector miss (shape of the request, not the site's page names)?
2. Are the misses small families (one or two URIs) or large ones?
3. Which families does v11 miss that v10 or the rules catch (and the other way)?
4. LVL2/3 recall split by level.
Shape classes are checked in this order, first match wins.
"""
import os
import re
import sys
from pathlib import Path

import joblib
import pandas as pd

from eval.v11_dev_eval import family, flags

CONV = Path(os.environ.get("V11_ANALYSIS_CONV", "data/processed/v11/sealed"))
OUT = Path(os.environ.get("V11_ANALYSIS_OUT", "results/final_v11/sealed"))
MODELS = {"v10": "models/v10_backup/detector.joblib", "v11": "models/detector_v11.joblib"}

_SQL = re.compile(r"union|select|insert|sleep\(|benchmark|or\s*1\s*=\s*1|'\s*or|--|/\*|information_schema|waitfor", re.I)
_SCRIPT = re.compile(r"<\s*/?\s*(script|img|svg|iframe)|javascript:|onerror|onload|alert\(", re.I)
_CMD = re.compile(r";\s*(ls|id|cat|wget|curl|uname)|\|\s*(ls|id|cat)|`|\$\(", re.I)
_FILE = re.compile(r"etc/passwd|win\.ini|boot\.ini|proc/self|\.\./|\.\.%2f|%2e%2e", re.I)
_EXT = re.compile(r"\.(php\d?|asp|aspx|jsp|cgi|pl|sh|bak|old|sql|env|ini|conf|git|svn|ds_store|xml|zip|tar|gz)(\?|$|/)", re.I)
SHAPES = ["dot-segment / file access", "SQL keywords", "script / HTML", "command", "encoded (percent escapes)",
          "known-file probe (extension)", "odd method", "query without keywords", "plain path"]


def shape(method, path):
    if _FILE.search(path):
        return SHAPES[0]
    if _SQL.search(path):
        return SHAPES[1]
    if _SCRIPT.search(path):
        return SHAPES[2]
    if _CMD.search(path):
        return SHAPES[3]
    if re.search(r"%[0-9A-Fa-f]{2}", path):
        return SHAPES[4]
    if _EXT.search(path.split("?")[0]):
        return SHAPES[5]
    if method not in ("GET", "POST", "HEAD"):
        return SHAPES[6]
    if "?" in path:
        return SHAPES[7]
    return SHAPES[8]


def _load(name):
    df = pd.read_csv(CONV / f"{name}.csv", dtype=str, keep_default_na=False)
    df["count"] = df["count"].astype(int)
    return df


def _md(df):
    cols = list(df.columns)
    rows = ["| " + " | ".join(cols) + " |", "|" + "---|" * len(cols)]
    for _, r in df.iterrows():
        rows.append("| " + " | ".join(f"{v:.3f}" if isinstance(v, float) else str(v) for v in r) + " |")
    return rows


def main():
    att, lvl = _load("attack"), _load("lvl234")
    att["fam"] = [family(m, p) for m, p in zip(att["method"], att["path"])]
    att["shape"] = [shape(m, p) for m, p in zip(att["method"], att["path"])]
    hits = {"rules": flags(att, None, 0).values}
    lvl_hits = {"rules": flags(lvl, None, 0).values}
    for tag, path in MODELS.items():
        m = joblib.load(path)
        hits[tag], lvl_hits[tag] = flags(att, m, 0.7).values, flags(lvl, m, 0.7).values
    for k, v in hits.items():
        att[k] = v
    # family level: share of the family's unique URIs flagged (macro recall averages this over families)
    fam = att.groupby("fam").agg(uris=("path", "size"), raw=("count", "sum"),
                                 shape=("shape", lambda s: s.value_counts().index[0]),
                                 **{k: (k, "mean") for k in hits})
    md = ["# v11 sealed test: post-hoc analysis (analysis only, no model or number changed)", "",
          f"{len(fam)} attack families, {len(att)} unique LVL1 attacks. A family counts as missed when its recall is "
          "below 0.5 (most of its URIs pass). Shape = what the request looks like (dominant class in the family), "
          "first match in this order: " + ", ".join(SHAPES) + ".", ""]

    md += ["## 1. Family recall by request shape (macro over the families of that shape)", ""]
    t = fam.groupby("shape").agg(families=("uris", "size"), **{k: (k, "mean") for k in hits}).reset_index()
    t = t.sort_values("families", ascending=False)
    md += _md(t) + [""]

    md += ["## 2. Missed families (recall < 0.5) by family size", ""]
    bins = pd.cut(fam["uris"], [0, 1, 2, 5, 20, 10**9], labels=["1 URI", "2", "3-5", "6-20", ">20"])
    t = fam.assign(size=bins).groupby("size", observed=False).agg(
        families=("uris", "size"), **{f"missed {k}": (k, lambda s: int((s < 0.5).sum())) for k in hits}).reset_index()
    md += _md(t) + [""]

    md += ["## 3. Who catches what (families, recall >= 0.5 = caught)", ""]
    c = {k: fam[k] >= 0.5 for k in hits}
    pairs = [("v11 caught, v10 missed", c["v11"] & ~c["v10"]), ("v10 caught, v11 missed", c["v10"] & ~c["v11"]),
             ("rules caught, v11 missed", c["rules"] & ~c["v11"]), ("v11 caught, rules missed", c["v11"] & ~c["rules"]),
             ("all three missed", ~c["rules"] & ~c["v10"] & ~c["v11"])]
    md += ["| group | families | of which shape (top 3) |", "|---|---|---|"]
    for name, mask in pairs:
        top = fam[mask]["shape"].value_counts().head(3)
        md.append(f"| {name} | {int(mask.sum())} | " + ", ".join(f"{s} {n}" for s, n in top.items()) + " |")
    md += [""]

    md += ["## 4. LVL2/3 recall by level (secondary set, never trained on)", ""]
    md += ["| level | unique | " + " | ".join(lvl_hits) + " |", "|---|---|" + "---|" * len(lvl_hits)]
    for lv, g in lvl.groupby("level"):
        idx = g.index
        md.append(f"| {lv} | {len(g)} | " + " | ".join(f"{v[idx].mean():.3f}" for v in lvl_hits.values()) + " |")
    lvl_shape = pd.Series([shape(m, p) for m, p in zip(lvl["method"], lvl["path"])]).value_counts().head(5)
    md += ["", "LVL2/3 shapes (top 5): " + ", ".join(f"{s} {n}" for s, n in lvl_shape.items()), ""]

    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "ANALYSIS.md").write_text("\n".join(md) + "\n", encoding="utf-8")
    missed = fam[fam["v11"] < 0.5].sort_values("raw", ascending=False)
    ex = att.groupby("fam")["path"].first()
    missed.assign(example=ex.reindex(missed.index).str[:200]).to_csv(CONV / "missed_families_v11.csv")
    print("\n".join(md))


if __name__ == "__main__":
    sys.exit(main())
