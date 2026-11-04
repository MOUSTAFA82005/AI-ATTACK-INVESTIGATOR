"""Convert AIT-LDS v1.1 Apache access logs (training/dev only, PREREGISTRATION v9 Amendment 4).

Input (extracted from AIT-LDS-v1_1.zip, only these 8 files):
    data/raw/external/ait/data/mail.<host>.com/apache2/mail.<host>.com-access.log
    data/raw/external/ait/labels/mail.<host>.com/apache2/mail.<host>.com-access.log
The label file has one line per log line: "<time label>,<line label>". Only the LINE label says
the request itself is part of the attack; the time label also marks normal requests that just
happened during an attack step, so it is kept as a column but never used as truth.

Output: data/processed/v9/ait_<host>.csv with the usual columns plus
    source, host, ait_label, label (attack/normal), attack_type, stage.

Facts found when reading the labels (2026-11-04):
- one attacker chain per host, same order on all 4 hosts: nikto -> hydra -> upload of a web
  shell -> a reverse shell started through the web shell (evil.php?cmd=...). The shell commands
  run over that reverse shell, so they are not in the web log.
- the attacker shares its IP with a normal webmail user on that host (about 6.5k attack lines
  next to 34k-140k normal lines from the same IP), so per-IP sessions mix both.

Usage: python -m eval.v9_convert_ait
"""
import csv
import re
import sys
from datetime import datetime
from pathlib import Path

HOSTS = ["cup", "insect", "onion", "spiral"]
ROOT = Path("data/raw/external/ait")
OUT = Path("data/processed/v9")
COLS = ["ip", "time", "timestamp", "method", "path", "status", "size", "user_agent", "body"]

LINE = re.compile(r'^(\S+) \S+ \S+ \[([^\]]+)\] "(\S+) (.*?)(?: HTTP/[\d.]+)?" (\d{3}) (\S+)(?: "[^"]*" "([^"]*)")?')

# AIT line label -> (our attack type, our stage)
def family(lab):
    if lab == "nikto":
        return "scan", "recon"
    if lab == "hydra":
        return "bruteforce", "intrusion"
    if lab == "upload":
        return "upload", "exploitation"
    if lab.startswith("webshell") or lab == "mail-curl":
        return "webshell", "exploitation"
    return "other", "exploitation"


def convert(host):
    data = ROOT / f"data/mail.{host}.com/apache2/mail.{host}.com-access.log"
    labels = ROOT / f"labels/mail.{host}.com/apache2/mail.{host}.com-access.log"
    out = OUT / f"ait_{host}.csv"
    n = bad = att = 0
    with open(data, encoding="utf-8", errors="replace") as fd, \
         open(labels, encoding="utf-8", errors="replace") as fl, \
         open(out, "w", newline="", encoding="utf-8") as fo:
        w = csv.writer(fo)
        w.writerow(COLS + ["source", "host", "ait_label", "label", "attack_type", "stage"])
        for line, lab in zip(fd, fl):
            time_lab, _, line_lab = lab.strip().partition(",")
            m = LINE.match(line)
            if not m:
                bad += 1
                continue
            ip, t, method, path, status, size, ua = m.groups()
            try:
                ts = datetime.strptime(t, "%d/%b/%Y:%H:%M:%S %z").isoformat()
            except ValueError:
                bad += 1
                continue
            is_att = line_lab not in ("0", "")
            typ, stage = family(line_lab) if is_att else ("", "")
            att += is_att
            n += 1
            w.writerow([ip, t, ts, method, path, int(status), 0 if size == "-" else int(size), ua or "", "",
                        "ait_v1.1", host, f"{time_lab},{line_lab}", "attack" if is_att else "normal", typ, stage])
    print(f"{host}: {n} rows, {att} attacks, {bad} unparsed -> {out}")


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    for h in sys.argv[1:] or HOSTS:
        convert(h)


if __name__ == "__main__":
    main()
