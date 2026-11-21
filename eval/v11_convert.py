"""
v11: convert the Biblio-US17 DEV months into CSV files the pipeline reads (results/final_v11/PREREGISTRATION.md).

Reads ONLY data/raw/external/Biblio-US17/Biblio-US17 (Jan 1 - May 31 2017). The sealed part (Jun 1 - Jul 17) was moved
to data/sealed/v11/biblio before this script was written and is never read here. Standard library only.

    python eval/v11_convert.py            # -> data/processed/v11/biblio_dev_{attack,clean,lvl234}.csv

Output columns: split (train = Jan-Apr, holdout = May), day, id, method, path, status, size, label, level, count.
- attack: every LVL1 row of the `attack` set, deduplicated by (split, method, path); count = raw rows it stands for.
- clean:  a uniform random sample of CLEAN_PER_DAY rows per day of the `clean` set (seed 11), not deduplicated.
- fp:     rows of `raw` the signature tools flagged but the authors judged normal (ManualTP = 0), deduplicated like
          attack (Amendment 1: harder normal set for false alarms).
- lvl234: rows of `raw` whose label is attack level 2 or 3 (context dependent, percent encoding), deduplicated like
          attack. Level 4 (DoS) has no payload and is left out. Secondary only, never used for training.
"""
import csv
import random
import sys
from collections import OrderedDict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "data" / "raw" / "external" / "Biblio-US17" / "Biblio-US17"
OUT = ROOT / "data" / "processed" / "v11"
CLEAN_PER_DAY = 5000
SEED = 11
LAST_DEV_DAY = "2017-05-31"
COLS = ["split", "day", "id", "method", "path", "status", "size", "label", "level", "count"]


def days(subdir, ext, src=None):
    """Dev files by default. Only eval/v11_sealed_test.py passes src (the sealed folder), at its single run."""
    for p in sorted(((src or SRC) / subdir).glob(f"biblio-2017-*.{ext}")):
        day = p.name[len("biblio-"):-len(ext) - 1]
        if src is None and day > LAST_DEV_DAY:      # never happens (sealed files moved), but stay safe
            raise SystemExit(f"refusing to read sealed-period file {p}")
        yield day, p


def split_of(day):
    if day > LAST_DEV_DAY:
        return "sealed"
    return "holdout" if day >= "2017-05-01" else "train"


def parse(line):
    """[MM-DD-Fnnnnnn] METHOD URI PROTOCOL" CODE SIZE (tab separated). None for a broken line."""
    parts = line.rstrip("\r\n").split("\t")
    if len(parts) < 6:
        return None
    return {"id": parts[0], "method": parts[1], "path": parts[2], "status": parts[-2], "size": parts[-1]}


def read(path):
    with open(path, encoding="utf-8", errors="replace", newline="") as f:
        for line in f:
            r = parse(line)
            if r:
                yield r


def dedup_rows(subdir, ext, label, keep=None, src=None):
    """keep(day) -> {id: level} limits the rows to those ids; without keep every row is level 1."""
    rows = OrderedDict()
    for day, p in days(subdir, ext, src):
        wanted = keep(day) if keep else None
        for r in read(p):
            if wanted is not None and r["id"] not in wanted:
                continue
            key = (split_of(day), r["method"], r["path"])
            if key in rows:
                rows[key]["count"] += 1
            else:
                rows[key] = {"split": key[0], "day": day, **r, "label": label,
                             "level": wanted[r["id"]] if wanted is not None else 1, "count": 1}
    return list(rows.values())


def sample_clean():
    rng = random.Random(SEED)
    out = []
    for day, p in days("clean", "cl"):
        pool = []
        for i, r in enumerate(read(p)):             # reservoir sample: one pass, fixed memory
            if i < CLEAN_PER_DAY:
                pool.append(r)
            else:
                j = rng.randint(0, i)
                if j < CLEAN_PER_DAY:
                    pool[j] = r
        out += [{"split": split_of(day), "day": day, **r, "label": "normal", "level": 0, "count": 1} for r in pool]
        print("clean", day, len(pool), file=sys.stderr, flush=True)
    return out


def label_levels(fp=False, src=None):
    """id -> attack level 2 or 3, from the label files (ManualTP first, then Phase2TP).
    With fp=True: id -> 0 for the rows the signature tools flagged but the authors judged normal (ManualTP = 0)."""
    levels = {}
    for day, p in days("labels", "lbl", src):
        ids = {}
        with open(p, encoding="utf-8", errors="replace") as f:
            for line in f:
                parts = [x.strip() for x in line.split("\t")]
                if len(parts) < 8:
                    continue
                manual, phase2 = int(parts[5]), int(parts[6])
                if fp:
                    if manual == 0:
                        ids[parts[0]] = 0
                    continue
                lv = manual if manual > 0 else phase2
                if lv in (2, 3):
                    ids[parts[0]] = lv
        levels[day] = ids
    return levels


def write(name, rows, out=None):
    out = out or OUT
    out.mkdir(parents=True, exist_ok=True)
    with open(out / name, "w", encoding="utf-8", newline="") as f:
        w = csv.DictWriter(f, fieldnames=COLS)
        w.writeheader()
        w.writerows(rows)
    print(name, len(rows), file=sys.stderr, flush=True)


def main():
    """Each output is written once; delete a file to make it again."""
    if not (OUT / "biblio_dev_attack.csv").exists():
        write("biblio_dev_attack.csv", dedup_rows("attack", "att", "attack"))
    if not (OUT / "biblio_dev_lvl234.csv").exists():
        levels = label_levels()
        write("biblio_dev_lvl234.csv", dedup_rows("raw", "raw", "attack", keep=lambda d: levels.get(d, {})))
    if not (OUT / "biblio_dev_fp.csv").exists():          # Amendment 1: harder normal set
        fps = label_levels(fp=True)
        rows = dedup_rows("raw", "raw", "normal", keep=lambda d: fps.get(d, {}))
        write("biblio_dev_fp.csv", rows)
    if not (OUT / "biblio_dev_clean.csv").exists():
        write("biblio_dev_clean.csv", sample_clean())


if __name__ == "__main__":
    main()
