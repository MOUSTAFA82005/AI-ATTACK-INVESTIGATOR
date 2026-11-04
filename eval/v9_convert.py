"""
v9: convert the external datasets to the pipeline format (PREREGISTRATION v9, section 5 step 2).

Pipeline columns (same as backend/app/log_parser.py rows):
    ip, time, timestamp, method, path, status, size, user_agent, body
Extra columns kept for evaluation only (never features): source, label, families, pattern.

    python eval/v9_convert.py            # converts the DEV parts only -> data/processed/v9/
The same functions are used later, unchanged, on the sealed parts at the final test.
"""
import io
import json
import re
import sys
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

import pandas as pd

COLS = ["ip", "time", "timestamp", "method", "path", "status", "size", "user_agent", "body"]
OUT = Path("data/processed/v9")

# SR-BH CAPEC columns -> our attack families (labels only)
CAPEC_FAMILY = {
    "66 - SQL Injection": "sqli",
    "242 - Code Injection": "code_injection",
    "88 - OS Command Injection": "cmdi",
    "248 - Command Injection": "cmdi",
    "126 - Path Traversal": "traversal",
    "16 - Dictionary-based Password Attack": "bruteforce",
    "310 - Scanning for Vulnerable Software": "scan",
    "272 - Protocol Manipulation": "protocol",
    "153 - Input Data Manipulation": "input_manipulation",
    "274 - HTTP Verb Tampering": "protocol",
    "194 - Fake the Source of Data": "spoofing",
    "34 - HTTP Response Splitting": "protocol",
    "33 - HTTP Request Smuggling": "protocol",
}
# ModSec-WP: columns that are the WAF's own verdict = the answer. Dropped at load (PREREGISTRATION v9 section 2).
MODSEC_LEAK = ("action", "action_phase", "action_message", "full_message_line")


def _iso(s, fmts):
    for f in fmts:
        try:
            t = datetime.strptime(s.strip(), f)
            if t.tzinfo is None:
                t = t.replace(tzinfo=timezone.utc)
            return t.isoformat()
        except (ValueError, AttributeError):
            continue
    return ""


def _path(target):
    if target.startswith(("http://", "https://")):
        u = urlsplit(target)
        return (u.path or "/") + (f"?{u.query}" if u.query else "")
    return target


def _int(s):
    try:
        return int(float(s))
    except (ValueError, TypeError):
        return 0


# ---------------- SR-BH 2020 ----------------
def _srbh_frame(c):
    cap = [k for k in c.columns if k in CAPEC_FAMILY]
    fam = c[cap].eq("1")
    families = fam.apply(lambda r: "|".join(sorted({CAPEC_FAMILY[k] for k in cap if r[k]})), axis=1)
    return pd.DataFrame({
        "ip": c["src_ip"], "time": c["timestamp"],
        "timestamp": c["timestamp"].map(lambda t: _iso(t, ["%d/%b/%Y:%H:%M:%S %z"])),
        "method": c["request_http_method"], "path": c["request_http_request"].map(_path),
        "status": c["response_http_status_code"].map(_int), "size": c["response_content_length"].map(_int),
        "user_agent": c["request_user_agent"], "body": c["request_body"],
        "source": "srbh", "label": (families != "").astype(int), "families": families, "pattern": "",
    })


def srbh_chunks(path, chunksize=50_000):
    """Yield converted SR-BH chunks (the laptop has little RAM)."""
    for c in pd.read_csv(path, dtype=str, keep_default_na=False, chunksize=chunksize, engine="python"):
        yield _srbh_frame(c)


def convert_srbh(path):
    return pd.concat(srbh_chunks(path), ignore_index=True)


# ---------------- Glastopf honeypot (secrepo) ----------------
def _split_raw(raw):
    head, _, body = raw.partition("\r\n\r\n")
    lines = head.split("\r\n")
    parts = lines[0].split(" ") if lines else []
    method = parts[0] if parts else ""
    target = parts[1] if len(parts) > 1 else ""
    ua = ""
    for l in lines[1:]:
        k, _, v = l.partition(":")
        if k.strip().lower() == "user-agent":
            ua = v.strip()
    return method, target, ua, body


def convert_glastopf(path):
    rows = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            p = json.loads(line)
            method, target, ua, body = _split_raw(p.get("request_raw") or "")
            src = p.get("source") or ["", 0]
            rows.append({
                "ip": src[0], "time": p.get("time", ""),
                "timestamp": _iso(p.get("time", ""), ["%Y-%m-%d %H:%M:%S"]),
                "method": method, "path": _path(target or p.get("request_url", "")),
                "status": 0, "size": 0,          # Glastopf does not record status or size
                "user_agent": ua, "body": body,
                "source": "glastopf", "label": 1, "families": "", "pattern": p.get("pattern", ""),
            })
    return pd.DataFrame(rows)


# ---------------- ModSec-WP (xlsx read with the standard library) ----------------
def _xlsx_rows(path):
    ns = "{http://schemas.openxmlformats.org/spreadsheetml/2006/main}"
    import xml.etree.ElementTree as ET
    with zipfile.ZipFile(path) as z:
        shared = []
        if "xl/sharedStrings.xml" in z.namelist():
            for si in ET.fromstring(z.read("xl/sharedStrings.xml")).iter(ns + "si"):
                shared.append("".join(t.text or "" for t in si.iter(ns + "t")))
        with z.open("xl/worksheets/sheet1.xml") as f:
            for _, el in ET.iterparse(f):
                if el.tag != ns + "row":
                    continue
                vals = {}
                for c in el.iter(ns + "c"):
                    col = re.match(r"[A-Z]+", c.get("r")).group(0)
                    t = c.get("t")
                    if t == "inlineStr":
                        v = "".join(x.text or "" for x in c.iter(ns + "t"))
                    else:
                        x = c.find(ns + "v")
                        v = x.text if x is not None else ""
                        if t == "s" and v != "":
                            v = shared[int(v)]
                    vals[col] = v or ""
                el.clear()
                yield vals


def _col_index(letters):
    n = 0
    for ch in letters:
        n = n * 26 + ord(ch) - 64
    return n


def convert_modsecwp(path):
    it = _xlsx_rows(path)
    first = next(it)
    head = [first[k] for k in sorted(first, key=_col_index)]
    letters = sorted(first, key=_col_index)
    rows = []
    for vals in it:
        d = {head[i]: vals.get(l, "") for i, l in enumerate(letters)}
        for k in list(d):
            if k in MODSEC_LEAK or k.startswith("message_"):
                del d[k]
        lab = d.get("label", "").strip().lower()
        rows.append({
            "ip": d.get("remote_address", ""), "time": d.get("event_time", ""),
            "timestamp": _iso(d.get("event_time", ""), ["%Y-%m-%d %H:%M:%S", "%d/%b/%Y:%H:%M:%S %z",
                                                       "%Y-%m-%dT%H:%M:%S", "%Y-%m-%d %H:%M:%S.%f"]),
            "method": d.get("request_line_method", ""), "path": _path(d.get("request_line_url", "")),
            "status": _int(d.get("response_status", "")), "size": 0,   # no size column
            "user_agent": d.get("request_useragent", ""), "body": d.get("request_body", ""),
            "source": "modsecwp", "label": int(lab not in ("normal", "")), "families": lab, "pattern": "",
        })
    return pd.DataFrame(rows)


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    dev = Path("data/raw/external/dev")
    # SR-BH in chunks, appended to one CSV
    out = OUT / "srbh_dev.csv"
    n = att = bad = 0
    fams = pd.Series(dtype=int)
    for i, df in enumerate(srbh_chunks(dev / "srbh_dev.csv")):
        df.to_csv(out, index=False, mode="w" if i == 0 else "a", header=i == 0)
        n += len(df); att += int(df["label"].sum()); bad += int((df["timestamp"] == "").sum())
        fams = fams.add(df.loc[df.label == 1, "families"].str.split("|").explode().value_counts(), fill_value=0)
    print(f"srbh_dev: {n} rows, attacks {att}, normal {n - att}, rows with no parsed time {bad}")
    print(fams.astype(int).sort_values(ascending=False).to_string())
    df = convert_glastopf(dev / "glastopf_dev.jsonl")
    df.to_csv(OUT / "glastopf_dev.csv", index=False)
    print(f"glastopf_dev: {len(df)} rows, IPs {df['ip'].nunique()}, rows with no parsed time {int((df['timestamp'] == '').sum())}")


if __name__ == "__main__":
    sys.exit(main())
