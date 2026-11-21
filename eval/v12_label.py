"""v12 sealed labels: one label per (day, IP), written from READING the raw sealed lines (2026-11-21, after the
freeze at commit 1ddddea, before any system ran on them). No detector, rule baseline or probe list is imported.
The evidence patterns below were written after reading every distinct non-200 / non-GET request in the 15 days."""
import collections, csv, gzip, re, sys
from pathlib import Path

Q = r'"((?:[^"\\]|\\.)*)"'          # a quoted field; nginx writes a quote inside it as \"
LINE = re.compile(r'^(\S+) \S+ \S+ \[[^\]]+\] ' + Q + r' (\d{3}) \S+ ' + Q + ' ' + Q)
# the site (secrepo.com) is static: no PHP/ASP at all (0 such requests answered 200 in the 15 days)
EVIDENCE = [
    ("server-script probe", r"\.(php\d?|asp|aspx|ashx|jsp|cgi)(\?|/|$)"),
    ("secret / config file", r"/\.(env|git|aws|netrc|pypirc|vscode|dev\.vars)|/(sftp-config|secrets|config)\.(json|ya?ml)$|wp-config"),
    ("WordPress probe", r"/wp-(login|json|includes|content|admin)|xmlrpc"),
    ("CMS / exploit endpoint", r"/(plus|phpcms|phpsso_server|seeyon|ispirit|maccms|fckeditor|admin_aspcms|apps/admin|utility|install)(/|$)"
                               r"|/e/(doinfo|downsys)/|/include/taglib|/api/session/properties|ueditor|swfupload|/admin/fileupload"),
    ("payload", r"\\\\think|php://|%27|'|\.\./|<script|union.+select|/etc/passwd"),
]
EVIDENCE = [(n, re.compile(p, re.I)) for n, p in EVIDENCE]
INSTALL_FINDER = re.compile(r"^/(wp|wordpress|old|new|backup|bk|bc|main|home|blog)/?$", re.I)
ADMIN = re.compile(r"^/(admin|login|register|user|contact)(/|$)", re.I)
# the site's own public folders: a downloader that guesses wrong file names there is not scanning for weaknesses
SITE = re.compile(r"^/(self\.logs|datasets|honeypot|maccdc|maccd2012|data|security-data-analysis|access\.log|error\.log|auth\.log|logs?)", re.I)
# Declared search-engine crawlers. One that asks for an exploit-looking PATH (no payload, no POST, no HEAD finder) is
# most likely following a planted spam link (e.g. Baiduspider from Baidu's own 220.181/116.179 ranges asking for
# /plus/result.php); its intent cannot be read from the log -> unsure. AWS hosts claiming Amazonbot are in this group
# too (432 IPs, 140 of them hit exploit paths): it may be a fake agent, but the log cannot prove it.
CRAWLER = re.compile(r"amazonbot|baiduspider|bingbot|googlebot|yandex|petalbot|bytespider|sogou|applebot|duckduckbot", re.I)
PATH_ONLY = {"server-script probe", "CMS / exploit endpoint", "WordPress probe", "secret / config file"}
FLEET_UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/146.0.0.0 Safari/537.36"


def label(reqs):
    why = set()
    for m, path, st, ua in reqs:
        p = path.split("?", 1)[0]
        for n, rx in EVIDENCE:
            if rx.search(path):
                why.add(n)
        if m == "HEAD" and INSTALL_FINDER.search(p):
            why.add("install finder (HEAD)")
        if m == "POST":
            why.add("POST to a static site")
    other = {r[1].split("?", 1)[0] for r in reqs if r[2] >= 400 and not SITE.search(r[1])}
    if len(other) >= 20:
        why.add("scan (>=20 missing paths)")
    admin = {r[1] for r in reqs if ADMIN.search(r[1].split("?", 1)[0]) and r[2] >= 400}
    if why and why <= PATH_ONLY and all(CRAWLER.search(r[3]) for r in reqs):
        return "unsure", ["declared crawler, exploit-looking path only: " + ", ".join(sorted(why))]
    if why or len(admin) >= 2:
        return "attacker", sorted(why | ({"admin/login guessing"} if len(admin) >= 2 else set()))
    if admin:
        return "unsure", ["one admin/login guess"]
    if all(r[3] == FLEET_UA for r in reqs) and all(r[2] == 404 for r in reqs):
        return "unsure", ["Chrome/146 fleet: one wrong file name per IP, spoofed referer (distributed scraper)"]
    return "normal", []


def main(sealed, out):
    rows, bad = [], 0
    for f in sorted(Path(sealed).glob("access.log.*.gz")):
        day = f.name[len("access.log."):-3]
        by_ip = collections.defaultdict(list)
        with gzip.open(f, "rt", errors="replace") as fh:
            for line in fh:
                m = LINE.match(line)
                if not m:
                    bad += 1
                    continue
                parts = m.group(2).split(" ")
                method, path = (parts[0].upper(), parts[1]) if len(parts) >= 2 else ("", parts[0])
                by_ip[m.group(1)].append((method, path, int(m.group(3)), m.group(5)))
        for ip, reqs in by_ip.items():
            lab, why = label(reqs)
            rows.append({"day": day, "ip": ip, "label": lab, "requests": len(reqs), "evidence": "; ".join(why)})
    with open(out, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0]))
        w.writeheader()
        w.writerows(rows)
    c = collections.Counter(r["label"] for r in rows)
    print(dict(c), "unparsed lines:", bad)


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
