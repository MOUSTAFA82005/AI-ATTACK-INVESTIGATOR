"""
v9 SEALED TEST (PREREGISTRATION v9 section 3, Amendments 1-3, 5, 6). Run ONCE, at tag v9.0-final-test.

    python -m eval.v9_sealed_test convert          # hash check, then sealed files -> data/processed/v9/sealed/*.csv
    python -m eval.v9_sealed_test run --tag v9     # v9 models (this tree)  -> pred_v9_<source>.csv.gz
    (in a worktree of tag v8.0-final-test, with the frozen v8 models in its models/ folder:)
    python "<repo>/eval/v9_sealed_test.py" run --tag v8 --repo "<repo>"
    python -m eval.v9_sealed_test report           # -> results/final_v9/sealed/SEALED-RESULTS.md

Only numbers go to results/. Converted rows and predictions (real lines, IPs) stay in data/processed/ (git-ignored).
"run" imports the pipeline of the CURRENT folder, so the same file runs the v8 code inside the v8 worktree.
Nothing here is tuned: every rule below was written before the sealed files were opened (Amendment 6).
"""
import argparse
import collections
import gzip
import hashlib
import io
import json
import os
import re
import sys
import time
import zipfile
from pathlib import Path

import numpy as np
import pandas as pd

SEALED = Path("data/sealed/v9")
CONV = Path("data/processed/v9/sealed")
OUT = Path("results/final_v9/sealed")
DRY = os.environ.get("V9_DRY")        # code test on FAKE files only (never set at the real run)
if DRY:
    SEALED, CONV, OUT = Path(DRY) / "sealed", Path(DRY) / "conv", Path(DRY) / "out"
SOURCES = ["glastopf", "modsecwp", "zanbil", "indonesia", "srbh", "owasp"]
ML, RULES = "model + sessions", "rules + rule sessions"
SITE_CAP = 200_000            # Amendment 6: the newest 200,000 requests of each Indonesian site
SENSITIVITY_THRESHOLD = 0.8   # Amendment 5: reported as a sensitivity row only
# ModSec-WP class -> attack types that count as right (Amendment 6, fixed before opening the file)
MODSEC_TYPE_OK = {"sqli": {"sqli"}, "xss": {"xss"}, "fileinclusion": {"traversal", "ssrf"},
                  "rce": {"cmdi", "ssti", "log4shell"}}


def _modsec_class(lab):
    l = lab.lower().replace(" ", "").replace("_", "").replace("-", "")
    for key, name in (("brute", "bruteforce"), ("normal", "normal"), ("benign", "normal"), ("sql", "sqli"), ("xss", "xss"),
                      ("crosssite", "xss"), ("inclu", "fileinclusion"), ("lfi", "fileinclusion"),
                      ("rfi", "fileinclusion"), ("rce", "rce"), ("command", "rce"), ("remotecode", "rce")):
        if key in l:
            return name
    return "other:" + lab


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
        m = re.match(r"\s*([0-9A-Fa-f]{64})\s+(.+?)\s*(\(.*)?$", line)
        if m:
            out[m.group(2).strip().replace("\\", "/").split("/")[-1] if "v8_backup" not in m.group(2)
                else "v8_backup/" + m.group(2).strip().replace("\\", "/").split("/")[-1]] = m.group(1).upper()
    return out


def verify_sealed():
    want = _read_hashes("results/final_v9/hashes.txt")
    bad = []
    for name, h in want.items():
        p = SEALED / name
        got = _sha256(p) if p.exists() else "MISSING"
        print(f"  {'ok ' if got == h else 'BAD'} {name}")
        bad += [name] if got != h else []
    models = _read_hashes("results/final_v9/model_hashes.txt")
    for name, h in models.items():
        p = Path("models") / name
        got = _sha256(p) if p.exists() else "MISSING"
        print(f"  {'ok ' if got == h else 'BAD'} models/{name}")
        bad += [name] if got != h else []
    if bad or len(want) != 7:
        raise SystemExit(f"Stopped: hash problem {bad} (sealed files listed: {len(want)}). Nothing was measured.")


def verify_v8_models(repo):
    want = _read_hashes(Path(repo) / "results/final_v9/model_hashes.txt")
    for name in ("detector.joblib", "context.joblib", "attack_type.joblib", "stage.joblib"):
        got = _sha256(Path("models") / name) if (Path("models") / name).exists() else "MISSING"
        if got != want.get("v8_backup/" + name):
            raise SystemExit(f"Stopped: models/{name} here is not the frozen v8 model.")
    print("  v8 models match v8_backup hashes")


# ------------------------------------------------------------------ convert (v9 tree only)
COLS = ["ip", "time", "timestamp", "method", "path", "status", "size", "user_agent", "body"]


def _indonesia_rules(z, org):
    import yaml
    rules = yaml.safe_load(z.read(f"{org}/ground-truth/{org}.yaml"))
    # Amendment 6: a line gets a rule's label when ALL its filter strings occur in the raw line (plain substring).
    return [(str(r["ground_truth_label"]), [str(p) for p in r["filter"]]) for r in rules]


def _label_line(line, rules):
    for lab, pats in rules:
        if all(p in line for p in pats):
            return lab
    return ""


def _member_lines(z, info):
    """Stream the lines of one zip member (one Indonesian file is 2.4 GB: never read it whole)."""
    with z.open(info) as raw:
        f = gzip.GzipFile(fileobj=raw) if info.filename.endswith(".gz") else raw
        for line in io.TextIOWrapper(f, encoding="utf-8", errors="replace", newline=None):
            yield line.rstrip("\r\n")


def _site_key(name):
    base = name.rsplit("/", 1)[-1]
    base = re.sub(r"(access_log|access\.log).*$", "", base)
    return name.rsplit("/", 1)[0] + "/" + base


def _rotation_order(name):
    """Oldest first: dated or numbered rotations, the live file last."""
    base = name.rsplit("/", 1)[-1]
    m = re.search(r"(\d{4})_(\d{2})_(\d{2})(?:\.(\d+))?", base)
    if m:
        return (0, m.group(1) + m.group(2) + m.group(3), int(m.group(4) or 0))
    m = re.search(r"\.log\.(\d+)", base)          # access.log.1 is newer than access.log.2
    if m:
        return (0, str(99999999 - int(m.group(1))), 0)
    return (1, "", 0)


def convert_indonesia():
    from backend.app.log_parser import _parse_combined, parse_log
    parts = []
    for org in ("organization-x", "organization-y"):
        z = zipfile.ZipFile(SEALED / f"{org}.zip")
        rules = _indonesia_rules(z, org)
        files = [i for i in z.infolist() if not i.is_dir() and re.search(r"(access_log|access\.log)", i.filename)
                 and "/lscp/" not in i.filename]
        sites = collections.defaultdict(list)
        for i in files:
            sites[_site_key(i.filename)].append(i)
        for site, infos in sorted(sites.items()):
            keep = collections.deque(maxlen=SITE_CAP)
            for i in sorted(infos, key=lambda i: _rotation_order(i.filename)):
                for line in _member_lines(z, i):
                    if line.strip():
                        keep.append(line)
            lines = list(keep)
            labs = [_label_line(l, rules) for l in lines]
            rows, kept_labs = [], []
            for l, lab in zip(lines, labs):
                r = _parse_combined(l.strip()) or next(iter(parse_log(l)[0]), None)
                if r:
                    rows.append(r); kept_labs.append(lab)
            if not rows:
                continue
            d = pd.DataFrame(rows)[COLS]
            d["source"], d["org"], d["site"] = "indonesia", org, site.split("/")[-1] or site
            d["families"] = kept_labs
            d["label"] = (d["families"] != "").astype(int)
            print(f"  {org} site {len(parts) + 1}: {len(d)} requests", flush=True)
            parts.append(d)
    return pd.concat(parts, ignore_index=True)


_A = re.compile(r"^\[(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2})(?:\.\d+)? ([+-]\d{4})\] \S+ (\S+) ")
_BOUND = re.compile(r"^--([0-9A-Za-z]+)-([A-Z])--\s*$")


def _audit_records(lines):
    rec, sec = {}, None
    for line in lines:
        m = _BOUND.match(line)
        if m:
            sec = m.group(2)
            if sec == "A" and rec:
                yield rec
                rec = {}
            if sec == "Z":
                if rec:
                    yield rec
                rec, sec = {}, None
                continue
            rec.setdefault(sec, [])
            continue
        if sec:
            rec[sec].append(line)
    if rec:
        yield rec


def convert_owasp():
    from eval.v9_convert import _iso, _path
    rows = []
    z = zipfile.ZipFile(SEALED / "owasp.zip")
    for info in sorted((i for i in z.infolist() if not i.is_dir()), key=lambda i: i.filename):
        day = info.filename.split("/")[0]
        for rec in _audit_records(_member_lines(z, info)):
            a = next((l for l in rec.get("A", []) if l.strip()), "")
            m = _A.match(a)
            b = [l for l in rec.get("B", []) if l.strip()]
            if not b:
                continue
            req = b[0].split(" ")
            ua = next((l.split(":", 1)[1].strip() for l in b[1:] if l.lower().startswith("user-agent:")), "")
            f = [l for l in rec.get("F", []) if l.strip()]
            st = re.match(r"HTTP/\S+ (\d{3})", f[0]) if f else None
            size = next((l.split(":", 1)[1].strip() for l in f[1:] if l.lower().startswith("content-length:")), "0")
            t = f"{m.group(1)} {m.group(2)}" if m else ""
            rows.append({"ip": m.group(3) if m else "", "time": t, "timestamp": _iso(t, ["%d/%b/%Y:%H:%M:%S %z"]),
                         "method": req[0], "path": _path(req[1]) if len(req) > 1 else "",
                         "status": int(st.group(1)) if st else 0, "size": int(size) if size.isdigit() else 0,
                         "user_agent": ua, "body": "\n".join(rec.get("C", [])).strip(),
                         "source": "owasp", "day": day, "label": 1, "families": ""})
    return pd.DataFrame(rows)


def convert():
    from eval.v9_convert import convert_glastopf, convert_modsecwp, srbh_chunks
    from backend.app.log_parser import decode, parse_log
    if DRY:
        print("DRY RUN on fake files: no hash check")
    else:
        print("hash check"); verify_sealed()
    CONV.mkdir(parents=True, exist_ok=True)
    t = time.time()
    convert_glastopf(SEALED / "glastopf_sealed.jsonl").to_csv(CONV / "glastopf.csv", index=False)
    d = convert_modsecwp(SEALED / "combined_final_dataset_augmented.xlsx")
    d["families"] = d["families"].map(_modsec_class)
    d.to_csv(CONV / "modsecwp.csv", index=False)
    z, _ = parse_log(decode((SEALED / "zanbil_v9.log").read_bytes()))
    z = pd.DataFrame(z)[COLS].assign(source="zanbil", label=0, families="")
    z.to_csv(CONV / "zanbil.csv", index=False)
    convert_indonesia().to_csv(CONV / "indonesia.csv", index=False)
    for i, c in enumerate(srbh_chunks(SEALED / "srbh_sealed.csv")):
        c.to_csv(CONV / "srbh.csv", index=False, mode="w" if i == 0 else "a", header=i == 0)
    convert_owasp().to_csv(CONV / "owasp.csv", index=False)
    print(f"converted in {time.time() - t:.0f}s -> {CONV}")


# ------------------------------------------------------------------ run (any tree)
KEEP = ["source", "label", "families", "ip", "session", "proba", "model", "rules", ML, RULES, "type_pred"]


def _pipeline(df):
    import eval.final_test as ft
    df = df.copy()
    lab = df["label"].astype(str).isin(["1", "attack"])
    for c in ("method", "path", "body", "user_agent", "ip", "timestamp", "families"):
        df[c] = df[c].fillna("").astype(str)
    for c in ("status", "size"):
        df[c] = pd.to_numeric(df[c], errors="coerce").fillna(0).astype(int)
    df["label"] = np.where(lab, "attack", "normal")
    df["attack_type"] = np.where(lab, "x", "")
    req, _ = ft._pipeline(df)
    return req


def run(tag, data):
    conv, t0 = Path(data), time.time()
    extra = {"modsecwp": [], "indonesia": ["org", "site"], "owasp": ["day"]}
    for src in SOURCES:
        p = conv / f"{src}.csv"
        if not p.exists():
            print("  missing", p); continue
        df = pd.read_csv(p, dtype=str, keep_default_na=False)
        groups = {"srbh": lambda d: d["timestamp"].str[:10], "indonesia": lambda d: d["org"] + "/" + d["site"],
                  "owasp": lambda d: d["day"]}.get(src)
        parts = []
        for key, g in (df.groupby(groups(df), sort=True) if groups else [("all", df)]):
            r = _pipeline(g.reset_index(drop=True))
            r["group"] = key
            for c in extra.get(src, []):
                r[c] = g[c].values if c in g else ""
            if tag == "v9" and src == "modsecwp":
                from ml.attack_type import rule_types
                r["rules_type"] = ""
                f = r["rules"] == 1
                r.loc[f, "rules_type"] = rule_types(r.loc[f, "method"], r.loc[f, "path"], r.loc[f, "body"])
            cols = [c for c in KEEP + ["group", "rules_type"] + extra.get(src, []) if c in r]
            parts.append(r[cols])
            print(f"  {tag} {src} part {len(parts)}: {len(g)} rows ({time.time() - t0:.0f}s)", flush=True)
        pd.concat(parts, ignore_index=True).to_csv(conv / f"pred_{tag}_{src}.csv.gz", index=False)
    print(f"{tag} done in {time.time() - t0:.0f}s")


# ------------------------------------------------------------------ report (numbers only)
def _md(t):
    t = t.astype(object).where(t.notna(), "").astype(str)
    return "\n".join(["| " + " | ".join(t.columns) + " |", "|" + "---|" * len(t.columns)]
                     + ["| " + " | ".join(r) + " |" for r in t.values])


def _load(src):
    out = {}
    for tag in ("v9", "v8"):
        p = CONV / f"pred_{tag}_{src}.csv.gz"
        if p.exists():
            out[tag] = pd.read_csv(p, dtype={"families": str, "type_pred": str, "rules_type": str},
                                   keep_default_na=False)
    return out


def _detectors(P, payload_only=False):
    """(name, boolean Series) for every detector of the preregistration: rules, v8, v9 (+ 0.8 sensitivity)."""
    v9 = P["v9"]
    d = [("payload rules", v9["rules"] == 1)]
    if not payload_only:
        d.append(("rules + rule sessions", v9[RULES] == 1))
    for tag in ("v8", "v9"):
        if tag in P:
            d.append((f"{tag} payload model", P[tag]["model"] == 1))
            if not payload_only:
                d.append((f"{tag} model + sessions", P[tag][ML] == 1))
    d.append(("v9 payload @0.8 (sensitivity)", (v9["proba"] >= SENSITIVITY_THRESHOLD) & (v9["model"] == 1)))
    return d


def report():
    OUT.mkdir(parents=True, exist_ok=True)
    md = ["# v9 sealed test", "", "Run once at tag v9.0-final-test. Rules, frozen v8 and v9 on the same converted rows.", ""]

    P = _load("glastopf")
    if P:
        g = P["v9"]
        rows = [{"detector": n, "requests": len(g), "requests flagged": round(float(p.mean()), 3),
                 "IPs": int(g["ip"].nunique()), "IPs flagged": round(float(p.groupby(g["ip"]).max().mean()), 3)}
                for n, p in _detectors(P)]
        md += ["## 1. Glastopf honeypot, sealed months (headline: share of IPs flagged, Amendment 1)", "", _md(pd.DataFrame(rows)), ""]

    P = _load("modsecwp")
    if P:
        g = P["v9"]
        cls = g["families"]
        rows = []
        for n, p in _detectors(P):
            r = {"detector": n}
            for c in sorted(cls.unique()):
                if c != "normal":
                    r[f"recall {c} (n={int((cls == c).sum())})"] = round(float(p[cls == c].mean()), 3)
            r[f"false alarms on normal (n={int((cls == 'normal').sum())})"] = round(float(p[cls == "normal"].mean()), 4)
            rows.append(r)
        md += ["## 2. ModSec-WP (whole source unseen)", "", _md(pd.DataFrame(rows)), ""]
        trows = []
        for name, frame, col, flag in [("payload rules", g, "rules_type", "rules")] + \
                [(f"{t} model", P[t], "type_pred", "model") for t in ("v8", "v9") if t in P]:
            for c, ok in MODSEC_TYPE_OK.items():
                m = (frame["families"] == c) & (frame[flag] == 1)
                trows.append({"detector": name, "class": c, "flagged": int(m.sum()),
                              "type right": round(float(frame.loc[m, col].isin(ok).mean()), 3) if m.any() else None})
        md += ["### Attack type on flagged requests (right types per class fixed in Amendment 6)", "",
               _md(pd.DataFrame(trows).pivot(index="class", columns="detector", values="type right").reset_index()), ""]

    real, md_extra = [], []
    for src, title in (("zanbil", "zanbil lines 10,000,001-10,200,000"), ("indonesia", "Indonesian sites, benign part")):
        P = _load(src)
        if not P:
            continue
        g = P["v9"]
        normal = g["label"] == "normal"
        for n, p in _detectors(P):
            real.append({"log": title, "detector": n, "normal requests": int(normal.sum()),
                         "flagged (false alarms)": round(float(p[normal].mean()), 5)})
        if src == "indonesia":
            for org in sorted(g["org"].unique()):
                o = normal & (g["org"] == org)
                for n, p in _detectors(P):
                    real.append({"log": f"  {org}", "detector": n, "normal requests": int(o.sum()),
                                 "flagged (false alarms)": round(float(p[o].mean()), 5)})
            att = g["label"] == "attack"
            if att.any():
                ex = []
                for lab in sorted(g.loc[att, "families"].unique()):
                    m = g["families"] == lab
                    ex.append({"label (their YAML rule)": lab, "requests": int(m.sum()),
                               **{n: round(float(p[m].mean()), 3) for n, p in _detectors(P)}})
                md_extra = ["### Indonesian lines matched by their attack rules (extra, not preregistered)", "", _md(pd.DataFrame(ex)), ""]
    if real:
        md += ["## 3. Real normal traffic: share of requests flagged = false-alarm rate", "", _md(pd.DataFrame(real)), ""]
        md += md_extra

    P = _load("srbh")
    if P:
        g = P["v9"]
        normal, att = g["label"] == "normal", g["label"] == "attack"
        rows = [{"detector": n, "normal requests": int(normal.sum()), "flagged": round(float(p[normal].mean()), 5),
                 "CRS attacks": int(att.sum()), "recall vs CRS": round(float(p[att].mean()), 3) if att.any() else None}
                for n, p in _detectors(P, payload_only=True)]
        md += ["## 4. SR-BH sealed days, per request (Amendments 2-3: false alarms; agreement with CRS)", "", _md(pd.DataFrame(rows)), ""]

    P = _load("owasp")
    if P:
        g = P["v9"]
        rows = [{"detector": n, "requests (all WAF-logged)": len(g), "share flagged": round(float(p.mean()), 3)}
                for n, p in _detectors(P)]
        md += ["## 5. ModSecurity 30-day production log (secondary: WAF-logged requests flagged)", "", _md(pd.DataFrame(rows)), ""]

    (OUT / "SEALED-RESULTS.md").write_text("\n".join(md), encoding="utf-8")
    print("\n".join(md))
    print("written", OUT / "SEALED-RESULTS.md")


def main(argv=None):
    ap = argparse.ArgumentParser()
    ap.add_argument("step", choices=["convert", "run", "report"])
    ap.add_argument("--tag", default="v9", choices=["v9", "v8"])
    ap.add_argument("--repo", default=".", help="the v9 repo (for its converted data), when run from the v8 worktree")
    a = ap.parse_args(argv)
    if a.step == "convert":
        convert()
    elif a.step == "run":
        if a.tag == "v8" and not DRY:
            verify_v8_models(a.repo)
        run(a.tag, CONV if DRY else Path(a.repo) / CONV)
    else:
        report()


if __name__ == "__main__":
    # run from another folder (the v8 worktree): import that folder's code, not this file's
    sys.path = [os.getcwd()] + [p for p in sys.path if Path(p).resolve() != Path(__file__).resolve().parent]
    main()
