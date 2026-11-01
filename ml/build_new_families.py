"""
Build the payload list for the new attack families (improvement 3):
SSRF, XXE, SSTI, NoSQL injection, Log4Shell, LDAP injection and XPath injection.

The payloads come from three public lists, cloned at fixed commits:

    git clone https://github.com/swisskyrepo/PayloadsAllTheThings   (08ea40e, 30 Oct 2026)
    git clone https://github.com/fuzzdb-project/fuzzdb               (5656ab2, 26 Feb 2020)
    git clone https://github.com/danielmiessler/SecLists             (0008f43, 30 Oct 2026; only Fuzzing/)
    git clone https://github.com/Puliczek/CVE-2021-44228-PoC-log4j-bypass-words   (66eaf86, 15 Jan 2022)

    python -m ml.build_new_families <folder with the three clones>

Writes data/raw/new_families.csv: payload_b64, family, source, split. The payload is
stored base64-encoded: antivirus programs (Windows Defender) block a plain file that
holds Log4Shell strings, and pandas then fails with "Invalid argument".

* Fuzz lists ("Intruder" files) are taken whole. Families with no fuzz list (SSRF,
  Log4Shell) take the lines of the code blocks in the PayloadsAllTheThings pages
  that look like that family's input: a URL for SSRF, a ${...} lookup for Log4Shell.
  The Log4Shell bypass list adds every ${...} lookup written in its README.
* XXE lists also hold plain XSS strings; an XXE payload must declare a DOCTYPE, an
  ENTITY or an XInclude (otherwise it is not XXE).
* Payloads are compared after URL-decoding, so "%2A%28" and "*(" count once.
* Fragments with no syntax at all ("!", "*", "42*42", "admin") are dropped: they
  are probes that only make sense next to the server's answer, and the log has no answer body.
* split: every payload is either "train" (70%) or "heldout" (30%), drawn per family with a
  fixed seed. Held-out payloads are different strings, never seen in training, so their
  recall says how well a family is learned, not how well rows are remembered.
"""
import base64
import csv
import random
import re
import sys
from pathlib import Path
from urllib.parse import unquote

from ml.detector import ROOT

OUT = ROOT / "data" / "raw" / "new_families.csv"
FAMILIES = ["ssrf", "xxe", "ssti", "nosql", "log4shell", "ldap", "xpath"]
HELDOUT_SHARE = 0.3
SEED = 42

PAT = "PayloadsAllTheThings"
LISTS = {   # family: [(source, file)], whole files
    "xpath": [("fuzzdb", "attack/xpath/xpath-injection.txt")],     # first: the LDAP lists repeat some of these
    "nosql": [(PAT, "NoSQL Injection/Intruder/NoSQL.txt"), (PAT, "NoSQL Injection/Intruder/MongoDB.txt"),
              ("SecLists", "Fuzzing/Databases/SQLi/NoSQL.txt")],
    "ldap": [(PAT, "LDAP Injection/Intruder/LDAP_FUZZ.txt"), (PAT, "LDAP Injection/Intruder/LDAP_FUZZ_SMALL.txt"),
             ("SecLists", "Fuzzing/LDAP.Fuzzing.txt"), ("fuzzdb", "attack/ldap/ldap-injection.txt")],
    "ssti": [(PAT, "Server Side Template Injection/Intruder/ssti.fuzz"),
             ("SecLists", "Fuzzing/template-engines-expression.txt"),
             ("SecLists", "Fuzzing/template-engines-identification.txt")],
    "xxe": [(PAT, "XXE Injection/Intruders/XXE_Fuzzing.txt"), (PAT, "XXE Injection/Intruders/xml-attacks.txt"),
            ("SecLists", "Fuzzing/XXE-Fuzzing.txt"), ("fuzzdb", "attack/xml/xml-attacks.txt")],
}
PAGES = {   # family: (pages whose code blocks are read, which lines to keep)
    "ssrf": (["Server Side Request Forgery/README.md", "Server Side Request Forgery/SSRF-Cloud-Instances.md",
              "Server Side Request Forgery/SSRF-Advanced-Exploitation.md"],
             re.compile(r"^\s*(https?|gopher|dict|file|ftp|sftp|tftp|ldap|jar|netdoc|php)://\S+$", re.I)),
    "log4shell": (["CVE Exploits/Log4Shell.md"], re.compile(r"^\s*\$\{.+\}\s*$")),
    "ldap": (["LDAP Injection/README.md"], re.compile(r"^\s*user\s*=\s*(?P<p>.+)$")),   # the injected user name
    "xpath": (["XPATH Injection/README.md"], re.compile(r"['\")\]/@*]")),
    "ssti": ([f"Server Side Template Injection/{n}.md" for n in
              ("README", "Python", "Java", "PHP", "Ruby", "JavaScript", "ASP", "Elixir")],
             re.compile(r"\{\{.*\}\}|\$\{.*\}|<%.*%>|#\{.*\}|\{%.*%\}|\*\{.*\}|\[\[.*\]\]")),
    "nosql": (["NoSQL Injection/README.md"],
              re.compile(r"\$(ne|eq|gt|gte|lt|lte|in|nin|regex|where|exists|or|and|nor|not|expr)\b")),
}
_CODE_LINE = re.compile(r"^\s*(import|from|def|class|return|print|#|//|\$ |curl |python|pip |git |"
                        r"sudo |docker |cd |echo |http\.|\w+\s*=\s*['\"(])", re.I)
_LOG4J_WORDS = re.compile(r"\$\{[^`\s]*\}")                     # every ${...} in the bypass-list README
_XXE = re.compile(r"<!doctype|<!entity|xi:include|xinclude", re.I)
_NO_SYNTAX = re.compile(r"^[\w\s.*/+\-%]*$")


def _clean(line):
    s = line.strip()
    if len(s) > 1 and s[0] == s[-1] == '"' and '""' in s:      # a CSV-quoted line (fuzzdb xml list)
        s = s[1:-1].replace('""', '"')
    return s


def _keep(s, family):
    d = unquote(s)
    if family == "xxe" and not _XXE.search(d):
        return False
    return len(d) >= 4 and not d.startswith("#") and not _NO_SYNTAX.match(d)


def _code_lines(path):
    inside, out = False, []
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        if line.strip().startswith("```"):
            inside = not inside
        elif inside:
            out.append(line)
    return out


def collect(base):
    base = Path(base)
    seen, rows = set(), []

    def add(payload, family, source):
        p = _clean(payload)
        if _keep(p, family) and unquote(p) not in seen:
            seen.add(unquote(p))
            rows.append({"payload": p, "family": family, "source": source})

    for family, files in LISTS.items():
        for source, name in files:
            for line in (base / source / name).read_text(encoding="utf-8", errors="ignore").splitlines():
                add(line, family, f"{source}/{name}")
    for family, (pages, wanted) in PAGES.items():
        for name in pages:
            for line in _code_lines(base / PAT / name):
                m = wanted.search(line)
                if m and not _CODE_LINE.match(line):
                    add(m.group("p") if "p" in m.groupdict() else line, family, f"{PAT}/{name}")
    readme = base / "CVE-2021-44228-PoC-log4j-bypass-words" / "README.md"
    for p in _LOG4J_WORDS.findall(readme.read_text(encoding="utf-8", errors="ignore")):
        if "<text>" in p:                                   # a placeholder in the docs, not a payload
            continue
        add(p, "log4shell", "log4j-bypass-words/README.md")
    return rows


def main(base):
    rows = collect(base)
    rng = random.Random(SEED)
    for family in FAMILIES:
        fam = [r for r in rows if r["family"] == family]
        rng.shuffle(fam)
        n_held = round(len(fam) * HELDOUT_SHARE)
        for i, r in enumerate(fam):
            r["split"] = "heldout" if i < n_held else "train"
    rows.sort(key=lambda r: (FAMILIES.index(r["family"]), r["split"], r["payload"]))
    OUT.parent.mkdir(parents=True, exist_ok=True)
    with OUT.open("w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["payload_b64", "family", "source", "split"])
        w.writeheader()
        for r in rows:
            w.writerow({"payload_b64": base64.b64encode(r["payload"].encode()).decode(),
                        **{k: r[k] for k in ("family", "source", "split")}})
    for family in FAMILIES:
        fam = [r for r in rows if r["family"] == family]
        print(f"{family:10s} {len(fam):4d} payloads ({sum(r['split'] == 'heldout' for r in fam)} held out)")
    print("saved", OUT)


if __name__ == "__main__":
    main(sys.argv[1])
