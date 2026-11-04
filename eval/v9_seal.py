"""
v9 sealing (PREREGISTRATION v9, section 2). Run ONCE, from the repo root:
    python eval/v9_seal.py
Cuts the sealed parts of SR-BH and the Glastopf honeypot by date, moves the whole-sealed sources to
data/sealed/v9/, and writes SHA-256 hashes to results/final_v9/hashes.txt.
It prints only dev-side counts; sealed files are never counted or shown.
"""
import csv, hashlib, io, json, shutil, sys, zipfile
from pathlib import Path

EXT = Path("data/raw/external")
SEALED = Path("data/sealed/v9")
DEV = Path("data/raw/external/dev")
OUT = Path("results/final_v9")
SRBH_SEALED_DAYS = ("25/Jul", "26/Jul", "27/Jul", "28/Jul", "29/Jul", "01/Nov")   # dataset covers Jul-Nov 2020 only
HONEYPOT_SPLIT = "2015-04-01"
WHOLE = ["organization-x.zip", "organization-y.zip", "owasp.zip", "combined_final_dataset_augmented.xlsx"]


def sha(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for b in iter(lambda: f.read(1 << 20), b""):
            h.update(b)
    return h.hexdigest().upper()


def split_srbh():
    csv.field_size_limit(10 ** 9)
    src = EXT / "data_capec_multilabel.csv"
    n_dev = n_bad = 0
    with open(src, newline="", encoding="utf-8", errors="replace") as f, \
         open(DEV / "srbh_dev.csv", "w", newline="", encoding="utf-8") as d, \
         open(SEALED / "srbh_sealed.csv", "w", newline="", encoding="utf-8") as s:
        r = csv.reader(f); wd = csv.writer(d); ws = csv.writer(s)
        head = next(r); wd.writerow(head); ws.writerow(head)
        for row in r:
            day = row[0][:6] if row else ""
            if not row or not row[0].strip():
                n_bad += 1                      # rows without a timestamp: dropped from both
            elif day in SRBH_SEALED_DAYS:
                ws.writerow(row)
            else:
                wd.writerow(row); n_dev += 1
    print(f"SR-BH dev rows: {n_dev}   rows without timestamp dropped: {n_bad}")


def split_honeypot():
    n_dev = 0
    with zipfile.ZipFile(EXT / "honeypot.json.zip") as z, \
         open(DEV / "glastopf_dev.jsonl", "w", encoding="utf-8") as d, \
         open(SEALED / "glastopf_sealed.jsonl", "w", encoding="utf-8") as s:
        name = [n for n in z.namelist() if n.endswith(".json")][0]
        with z.open(name) as f:
            for line in io.TextIOWrapper(f, encoding="utf-8", errors="replace"):
                if '"glastopf.events"' not in line:
                    continue
                rec = json.loads(line)
                p = rec.get("payload")
                p = json.loads(p) if isinstance(p, str) else p
                t = str(p.get("time", ""))[:10]
                if t >= HONEYPOT_SPLIT:
                    s.write(json.dumps(p) + "\n")
                else:
                    d.write(json.dumps(p) + "\n"); n_dev += 1
    print(f"Glastopf dev events: {n_dev}")


def main():
    SEALED.mkdir(parents=True, exist_ok=True); DEV.mkdir(parents=True, exist_ok=True); OUT.mkdir(parents=True, exist_ok=True)
    if (OUT / "hashes.txt").exists():
        sys.exit("hashes.txt already exists: sealing was already done, not running again")
    for w in WHOLE:
        if (EXT / w).exists():
            shutil.move(str(EXT / w), str(SEALED / w))
    split_srbh()
    split_honeypot()
    lines = [f"{sha(p)}  {p.name}" for p in sorted(SEALED.iterdir()) if p.is_file()]
    (OUT / "hashes.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


if __name__ == "__main__":
    main()
