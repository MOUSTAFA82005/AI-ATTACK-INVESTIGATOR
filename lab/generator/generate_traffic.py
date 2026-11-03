"""
generate_traffic.py - traffic generator for the AI Attack Investigator lab.

LAB ONLY. Targets our own isolated lab sites and nothing else:
  juiceshop -> http://127.0.0.1:8080
  dvwa      -> http://127.0.0.1:8081
This script refuses to run if these addresses are changed. If a port is taken
on your machine, use --port (the host always stays 127.0.0.1).

Each simulated session gets its own fake IP (10.1.x.y, to never clash with
manual_examples.py's 10.0.0.x) sent via X-Forwarded-For, so Nginx logs a
distinct client IP per session.

Sessions run CONCURRENTLY (see --workers) so a full run stays fast enough
to run live. This means request timestamps across different sessions
interleave, same as a real server under real traffic - each session's own
requests are still sent in order.

Outputs (all under data/, which is gitignored - never commit generated
data or logs):
  data/labels/sessions_<tag>.csv      - one row per session
  data/labels/requests_<tag>.csv      - one row per HTTP request actually sent
                                         (now includes a "site" column)
  data/raw/<site>_generated_<tag>.log - the NEW access.log lines produced
                                         by this run (captured by size)

Usage:
    python lab/generator/generate_traffic.py --sessions 300 --seed 3 --out-tag run3
    python lab/generator/generate_traffic.py --site dvwa --sessions 50 --seed 99 --out-tag dvwa_check
    python lab/generator/generate_traffic.py --sessions 300 --seed 7 --campaigns 60 --out-tag camp7
    python lab/generator/generate_traffic.py --families all --sessions 400 --seed 6 --campaigns 60 --out-tag run6

Campaigns (--campaigns N): N of the attacker sessions go through several
steps in a row from the same IP (for example scan > enum > sqli), like a
real intrusion. Used for the next-step model. The steps are picked from
CAMPAIGN_START / CAMPAIGN_NEXT below, and each step reuses the normal
session function of that attack. With the default 0 a run is the same as before.

New attack families (--families all, generator v4): SSRF, XXE, SSTI, NoSQL injection,
Log4Shell, LDAP injection and XPath injection join the attacker sessions on both
sites. Their payloads are in payloads/v4_<family>.b64 (base64, one per line), built by
build_v4_payloads.py from public sources the detector was NOT trained on. They are
stored base64 because Windows Defender blocks plain files holding Log4Shell strings;
for the same reason Log4Shell payloads are only sent URL-encoded (query string or
form body), never raw in a JSON body or a header, so the access log never holds a raw
JNDI lookup string. (This file itself never spells one out either, for the same reason.) With the default --families old a run is the same as before.
Campaigns use the old families only.
"""
import base64
import argparse
import csv
import random
import re
import string
import threading
import time
import urllib.parse
from collections import Counter
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from pathlib import Path

import requests

# ---------- lab sites (hard-coded, never change these) ----------
ALLOWED_BASES = {
    "juiceshop": "http://127.0.0.1:8080",
    "dvwa": "http://127.0.0.1:8081",
    "mutillidae": "http://127.0.0.1:8084",
    "bwapp": "http://127.0.0.1:8085",
    "dvna": "http://127.0.0.1:8086",
    "vampi": "http://127.0.0.1:8087",
    "dvga": "http://127.0.0.1:8088",
}
BASE_SITES = dict(ALLOWED_BASES)
if BASE_SITES != ALLOWED_BASES:
    raise SystemExit("Refusing to run: BASE_SITES must stay the lab addresses.")
BASE = BASE_SITES["juiceshop"]  # kept for the existing Juice Shop functions, unchanged

LAB_HOST = "http://127.0.0.1"

# ---------- campaigns: which step comes next (probabilities, written by us) ----------
CAMPAIGN_START = {"scan": 0.6, "enum": 0.2, "bruteforce": 0.2}
CAMPAIGN_NEXT = {
    "scan":       {"enum": 0.25, "bruteforce": 0.25, "sqli": 0.2, "traversal": 0.15, "xss": 0.1, "cmdi": 0.05},
    "enum":       {"sqli": 0.35, "bruteforce": 0.25, "xss": 0.2, "traversal": 0.1, "cmdi": 0.1},
    "bruteforce": {"sqli": 0.3, "enum": 0.3, "xss": 0.2, "cmdi": 0.1, "traversal": 0.1},
    "sqli":       {"xss": 0.3, "cmdi": 0.25, "traversal": 0.25, "enum": 0.2},
    "xss":        {"sqli": 0.4, "cmdi": 0.3, "traversal": 0.3},
    "traversal":  {"cmdi": 0.4, "sqli": 0.3, "xss": 0.3},
    "cmdi":       {"traversal": 0.4, "sqli": 0.3, "xss": 0.3},
}
CAMPAIGN_STEPS = (3, 5)   # min and max number of steps

ROOT = Path(__file__).resolve().parents[2]
PAYLOAD_DIR = Path(__file__).resolve().parent / "payloads"


def _label_path(kind, tag, site):
    # Juice Shop keeps the old names (requests_run3.csv); other sites add their name
    # (requests_dvwa_run4.csv), so two sites with the same --out-tag never overwrite each other.
    parts = [kind] + ([site] if site != "juiceshop" else []) + ([tag] if tag else [])
    return ROOT / "data" / "labels" / ("_".join(parts) + ".csv")


def sessions_path(tag, site="juiceshop"):
    return _label_path("sessions", tag, site)


def requests_path(tag, site="juiceshop"):
    return _label_path("requests", tag, site)


def generated_log_path(site, tag):
    suffix = f"_{tag}" if tag else ""
    return ROOT / "data" / "raw" / f"{site}_generated{suffix}.log"


BROWSER_UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/155.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:132.0) Gecko/20100101 Firefox/132.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 "
    "(KHTML, like Gecko) Version/17.5 Safari/605.1.15",
]
ATTACK_UAS = {
    "sqli": "sqlmap/1.8.11#stable (http://sqlmap.org)",
    "traversal": "Mozilla/5.0 (compatible; dirbuster)",
    "bruteforce": "Mozilla/5.0 (Hydra)",
    "xss": None,  # XSS travels inside a normal-looking browser request
    "cmdi": "commix/4.2 (https://commixproject.com)",
    "scan": "Mozilla/5.0 (compatible; dirbuster)",
}

STATIC_FILES = [
    "/assets/public/images/favicon_js.ico",
    "/socket.io/?EIO=4&transport=polling",
    "/main.js",
    "/styles.css",
]

PRODUCT_TERMS = [
    "apple", "juice", "smoothie", "banana", "lemon", "tea", "coffee", "milk",
    "orange", "mango", "grape", "berry", "melon", "ginger", "mint", "honey",
    "carrot", "beet", "cherry", "peach", "pear", "kiwi", "lime", "basil",
    "cucumber", "spinach", "kale", "pineapple", "coconut", "pomegranate",
    "raspberry", "blueberry", "watermelon", "papaya", "fig", "date",
    "cinnamon", "vanilla", "cocoa", "almond",
]
FEEDBACK_COMMENTS = [
    "Great store, found everything I needed!",
    "O'Brien's favorite shop, highly recommend.",
    '"Tom & Jerry" would love this place.',
    "50% off?! Amazing deal, thanks!",
    "Delivery was fast & packaging was neat.",
    "Isn't this the best juice bar around?",
    "Can't complain - solid service.",
    "Rated 5/5, won't hesitate to buy again.",
    "Price point (a bit high) but worth it.",
    "Ordered 3x, all arrived fine.",
    "My kids' favorite smoothie spot!",
    "Customer service answered @9pm, impressive.",
    "Website's a bit slow on mobile, otherwise good.",
    "Love the 'fresh daily' promise - kept it!",
    "D'oh, forgot my coupon, still happy though.",
    "A+ products, B- website speed.",
    "Nothing beats a 100% natural smoothie.",
    "Review #42: still my go-to store.",
    "Great value; $5 for a smoothie is fair.",
    "Packaging said 'fragile' & it was respected.",
    "Would've given 5 stars, minus 1 for shipping delay.",
    "Easy to use site, no complaints here.",
    "Juice tasted off; email'd support already.",
    "This is a test, don't mind me - still love it.",
    "Products arrived in <48h, impressive!",
    "Mix of fruits = perfect breakfast combo.",
    "Nice touch with the 'thank you' card.",
    "Ordering again next week, 100%.",
    "Staff's friendly & quick to help.",
    "Best juice shop, hands down (and I've tried many).",
]
HARD_NORMAL_PHRASES = [
    "select your size before checkout",
    "drop off at 5pm please",
    "union station juice bar",
    "I <3 this smoothie",
    "best script ever for a recipe",
    "order by price please",
    "1=1 deal: buy one get one",
    "please delete my old address",
    "insert a note: gift wrap please",
    "update my delivery time to 6pm",
    "drop by the store anytime",
    "select all that apply: fruit, veg",
    "union of flavors, truly unique",
    "script for a healthy smoothie below",
    "order by size: small, medium, large",
    "my script for success: eat well",
    "please update the order status",
    "where is my order? #12345",
    "select 'large' as my cup size",
    "insert coin for the vending machine joke",
    "drop everything, this juice is amazing",
    "union break room loved this brand",
    "delete this review if duplicated",
    "1=1 always true, 5 stars always deserved",
    "select 2 of these for a discount",
    "having trouble with my order",
    "group by flavor when restocking?",
    "order confirmed, thanks a lot",
    "script kiddie joke aside, great app",
    "please select a delivery slot",
]
# Real-looking names with punctuation (apostrophes, hyphens), used as
# innocent input on DVWA's vulnerability pages. These are the hardest
# "normal" cases: they look odd to a naive keyword filter but are
# ordinary human names.
HARD_NORMAL_NAMES = [
    "O'Brien", "Anne-Marie", "Jean-Luc", "D'Angelo", "Mary-Jane",
    "Al-Amin", "Ng'ang'a", "O'Connor", "Van Der Berg", "St. Clair",
    "Mc'Donald", "L'Hommedieu", "De La Cruz", "Al-Rashid", "O'Malley",
]

_ip_counter = [1]
_ip_lock = threading.Lock()


def next_ip():
    """10.1.x.y, x grows past 255 sessions. Never clashes with 10.0.0.x.
    Thread-safe, since sessions run concurrently."""
    with _ip_lock:
        n = _ip_counter[0]
        x, y = divmod(n, 255)
        _ip_counter[0] += 1
    return f"10.1.{x}.{y + 1}"


def load_payloads(name):
    path = PAYLOAD_DIR / name
    lines = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            lines.append(line)
    return lines


SQLI_PAYLOADS = load_payloads("sqli.txt") + load_payloads("sqli_extra.txt")
XSS_PAYLOADS = load_payloads("xss.txt") + load_payloads("xss_extra.txt")
TRAVERSAL_PAYLOADS = load_payloads("traversal.txt")
CMDI_PAYLOADS = load_payloads("cmdi.txt")
SCAN_PATHS = load_payloads("scan_paths.txt")

NEW_FAMILIES = ["ssrf", "xxe", "ssti", "nosql", "log4shell", "ldap", "xpath"]


def load_b64_payloads(name):
    """payloads/<name>: one base64-encoded payload per line (see build_v4_payloads.py)."""
    path = PAYLOAD_DIR / name
    return [base64.b64decode(line).decode("utf-8")
            for line in path.read_text(encoding="ascii").split() if line]


NEW_PAYLOADS = {}   # family -> payloads, filled by main() only with --families all


_TIME_WORDS = re.compile(r"sleep|benchmark|waitfor|pg_sleep|ping\s+-[cn]|timeout", re.I)


def payload_variant(attack_type, payload, target=""):
    """
    Sub-type label of a payload attack, from the raw payload (before vary()) and the field it
    is sent in. Only labels; it uses no randomness, so traffic for a seed stays the same.
      sqli:      blind (time-based) / login (sent in a login form) / query
      xss:       stored (saved and shown to others: feedback, registration) / reflected
      traversal: encoded (double-encoded or encoded dots, to slip past filters) / plain
      cmdi:      blind (time-based) / os
    """
    timed = bool(_TIME_WORDS.search(payload))
    if attack_type == "sqli":
        return "blind" if timed else "login" if target == "login_email" else "query"
    if attack_type == "xss":
        return "stored" if target in ("feedback_comment", "register_email") else "reflected"
    if attack_type == "traversal":
        return "encoded" if re.search(r"%25|%2e", payload, re.I) else "plain"
    if attack_type == "cmdi":
        return "blind" if timed else "os"
    return new_family_variant(attack_type, payload)


def new_family_variant(attack_type, payload):
    """Sub-type of a new-family payload (labels only, no randomness)."""
    low = payload.lower()
    if attack_type == "ssrf":
        if re.search(r"169\.254\.169\.254|metadata|100\.100\.100\.200", low):
            return "cloud"
        return "internal" if low.startswith(("http://", "https://")) else "scheme"
    if attack_type == "xxe":
        if "xinclude" in low or "xi:include" in low:
            return "xinclude"
        if re.search(r'"https?://', low):
            return "oob"
        return "dos" if "system" not in low and "public" not in low else "file"
    if attack_type == "ssti":
        return "exec" if re.search(r"popen|exec|runtime|system|import|process|getenv|getcwd|`", low) else "probe"
    if attack_type == "nosql":
        return "js" if re.search(r"\$where|return|sleep|this\.|db\.|\|\||&&", low) else "operator"
    if attack_type == "log4shell":
        return "plain" if ("$" + "{jndi:") in low else "obfuscated"
    return ""


def vary(payload):
    """Apply a random surface variation to an attack payload."""
    choice = random.choices(
        ["plain", "url_encode", "mixed_case", "spaces", "obfuscate"],
        weights=[20, 20, 20, 10, 30],
    )[0]
    if choice == "url_encode":
        return urllib.parse.quote(payload, safe="")
    if choice == "mixed_case":
        return "".join(c.upper() if random.random() < 0.5 else c.lower() for c in payload)
    if choice == "spaces":
        return "  " + payload + "  "
    if choice == "obfuscate":
        return _obfuscate(payload)
    return payload


_SPLITTABLE_WORDS = ["union", "select", "insert", "update", "delete", "drop",
                      "where", "order", "having", "script", "alert", "onerror"]
_ALT_WHITESPACE = ["\t", "%09", "\n", "%0a", "/**/"]


def _obfuscate(payload):
    """Mangle a payload: split keywords with SQL comments, swap whitespace
    for alternative forms, and concatenate pieces of the string."""
    text = payload
    for word in random.sample(_SPLITTABLE_WORDS, k=len(_SPLITTABLE_WORDS)):
        idx = text.lower().find(word)
        if idx != -1:
            mid = len(word) // 2
            text = text[:idx] + word[:mid] + "/**/" + word[mid:] + text[idx + len(word):]
            break
    alt_ws = random.choice(_ALT_WHITESPACE)
    text = text.replace(" ", alt_ws)
    if random.random() < 0.4 and "'" not in text:
        parts = [text[:len(text) // 2], text[len(text) // 2:]]
        text = "'" + parts[0] + "'+'" + parts[1] + "'"
    return text


# Inside a campaign every step reuses the same HTTP session (cookies, so one
# login), like one attacker working in one browser or tool. Per thread, because
# sessions run concurrently.
_campaign = threading.local()


def session_http(ip, user_agent=None):
    shared = getattr(_campaign, "session", None)
    if shared is not None:
        shared.headers["User-Agent"] = user_agent or shared.headers["User-Agent"]
        return shared
    s = requests.Session()
    s.headers.update({
        "X-Forwarded-For": ip,
        "User-Agent": user_agent or random.choice(BROWSER_UAS),
    })
    return s


def fake_email():
    return "u" + "".join(random.choices(string.digits, k=8)) + "@example-lab.test"


def fake_password():
    return "".join(random.choices(string.ascii_letters + string.digits, k=10))


def pause():
    """Default delay between requests. Kept short so a full run fits in
    the ~10 minute budget even with hundreds of sessions."""
    time.sleep(random.uniform(0.15, 0.5))


def quick_pause():
    """Shorter delay for scanner-style sessions (real scanners are fast)."""
    time.sleep(random.uniform(0.05, 0.2))


def now_iso():
    return datetime.now(timezone.utc).isoformat()


# ---------- true attack stage, read from the server's full answer ----------
# The access log only shows status and size. The generator sees the whole answer,
# so it can say whether an attack really worked. This is the ground truth the
# stage model (ml/stage.py) learns from; the model itself only sees the log.
#   recon        looking around (scans, IDs that are not there)
#   intrusion    trying to get in, and it did not work
#   exploitation it worked (the payload's effect is in the answer, or a guessed login succeeded)
#   data_theft   records were read (an enumerated ID that exists and came back with data)
_LEAK_MARKERS = ("root:x:0:0", "daemon:x:", "uid=", "[boot loader]", "[extensions]",
                 "bytes from", "PING ", "Linux version")
_HASH_RE = re.compile(r"\b[a-f0-9]{32}\b")


def _request_values(resp):
    url = urllib.parse.unquote_plus(resp.request.url or "")
    body = resp.request.body or ""
    if isinstance(body, bytes):
        body = body.decode("utf-8", "replace")
    return url + "\n" + urllib.parse.unquote_plus(body)


def _site_of(resp):
    port = urllib.parse.urlsplit(resp.request.url).port
    return next((site for site, p in EXTRA_PORTS.items() if p == port), None) if "EXTRA_PORTS" in globals() else None


def _payload_worked(resp, attack_type):
    text = resp.text if resp.content and len(resp.content) < 2_000_000 else ""
    if not (200 <= resp.status_code < 300) or not text:
        return False
    sent = _request_values(resp)
    if any(m in text and m not in sent for m in _LEAK_MARKERS):
        return True                                    # a file or command output came back
    site = _site_of(resp)
    if attack_type == "sqli" and site:
        return SITE_SPECS[site]["sqli_worked"](text)
    if attack_type == "ssti" and site == "dvna":
        return "49" in text and "7*7" in sent
    if attack_type == "sqli":
        return ('"authentication"' in text                       # login bypass: a token came back
                or text.count("First name:") >= 2                # DVWA: more than the one asked row
                or len(set(_HASH_RE.findall(text)) - set(_HASH_RE.findall(sent))) >= 2)   # password hashes
    if attack_type == "xss" and "json" in resp.headers.get("Content-Type", ""):
        return False                  # an API answer is data, not a page: no browser runs it
    if attack_type == "xss":
        # the script part came back unchanged (reflected or stored), so a browser would run it
        parts = re.findall(r"<\s*(?:script|img|svg|iframe|body)[^>]*>|on\w+\s*=|javascript:", sent, re.I)
        return any(p in text for p in parts)
    if attack_type == "ssti":
        return "49" in text and "7*7" in sent and "7*7" not in text
    return False


def true_stage(resp, label, attack_type):
    if label != "attack":
        return ""
    if attack_type == "scan":
        return "recon"
    ok = 200 <= resp.status_code < 300
    text = resp.text if ok and resp.content and len(resp.content) < 2_000_000 else ""
    site = _site_of(resp)
    if attack_type == "enum" and site:
        return "data_theft" if ok and SITE_SPECS[site]["enum_found"](text) else "recon"
    if attack_type == "bruteforce" and site:
        return "exploitation" if SITE_SPECS[site]["login_won"](resp) else "intrusion"
    if attack_type == "enum":
        got = ok and ("First name:" in text or re.search(r'"data"\s*:\s*[\[{]', text) is not None)
        return "data_theft" if got else "recon"
    if attack_type == "bruteforce":
        won = ok and ('"authentication"' in text or "Welcome to the password protected area" in text)
        return "exploitation" if won else "intrusion"
    return "exploitation" if _payload_worked(resp, attack_type) else "intrusion"


# ---------- per-request logging (thread-safe: sessions run concurrently) ----------
class RequestLog:
    def __init__(self):
        self.rows = []
        self.status_counts = Counter()
        self.attack_counts = Counter()  # (attack_type, variant, site) -> count
        self._lock = threading.Lock()

    def record(self, ip, method, path, label, attack_type, variant, site, stage=""):
        with self._lock:
            self.rows.append([now_iso(), ip, method, path, label, attack_type, variant, site, stage])
            if label == "attack":
                self.attack_counts[(attack_type, variant, site)] += 1

    def log_response(self, resp, ip, label, attack_type, variant, site):
        with self._lock:
            self.status_counts[resp.status_code] += 1
        path = urllib.parse.urlsplit(resp.request.url).path
        stage = true_stage(resp, label, attack_type)
        self.record(ip, resp.request.method, path, label, attack_type, variant, site, stage)

    def log_error(self):
        with self._lock:
            self.status_counts["error"] += 1

    def write(self, path):
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["time", "ip", "method", "path", "label", "attack_type", "variant", "site", "stage"])
            w.writerows(self.rows)


def send(reqlog, s, ip, method, url, label, attack_type, variant="", site="juiceshop", **kwargs):
    """... Redirects are NOT followed automatically: each hop must be its
    own send() call, so every request we make maps to exactly one log
    line and is labelled with its own real method/path (e.g. the login
    POST itself, not the page it redirects to)."""
    kwargs.setdefault("allow_redirects", False)
    for attempt in (1, 2):
        try:
            resp = s.request(method, url, timeout=10, **kwargs)
            reqlog.log_response(resp, ip, label, attack_type, variant, site)
            return resp
        except requests.RequestException as e:
            if attempt == 2:
                print(f"  request failed: {method} {url} -> {e}")
                reqlog.log_error()
                return None
            time.sleep(2)
    return None


# ============================================================
# Juice Shop sessions (unchanged from before)
# ============================================================
def run_normal_session(ip, reqlog):
    s = session_http(ip)
    start = now_iso()
    L = ("normal", "")

    send(reqlog, s, ip, "GET", BASE + "/", *L)
    for f in random.sample(STATIC_FILES, k=random.randint(2, len(STATIC_FILES))):
        send(reqlog, s, ip, "GET", BASE + f, *L)
        pause()

    if random.random() < 0.15:
        send(reqlog, s, ip, "GET", BASE + f"/api/Products/{random.randint(9000, 9999)}", *L)
        pause()

    for term in random.sample(PRODUCT_TERMS, k=random.randint(1, 3)):
        if random.random() < 0.2:
            term = random.choice(HARD_NORMAL_PHRASES)
        send(reqlog, s, ip, "GET", BASE + "/rest/products/search", *L, params={"q": term})
        pause()
        pid = random.randint(1, 20)
        send(reqlog, s, ip, "GET", BASE + f"/api/Products/{pid}", *L)
        pause()
        send(reqlog, s, ip, "GET", BASE + f"/rest/products/{pid}/reviews", *L)
        pause()

    email, password = fake_email(), "P@ss" + str(random.randint(1000, 9999))
    send(reqlog, s, ip, "POST", BASE + "/api/Users/", *L, json={
        "email": email, "password": password, "passwordRepeat": password,
        "securityQuestion": {"id": 1}, "securityAnswer": "lab",
    })
    pause()

    if random.random() < 0.15:
        for _ in range(random.randint(1, 2)):
            send(reqlog, s, ip, "POST", BASE + "/rest/user/login", *L,
                 json={"email": email, "password": password + "x"})
            pause()

    token, bid = None, None
    r = send(reqlog, s, ip, "POST", BASE + "/rest/user/login", *L,
             json={"email": email, "password": password})
    if r is not None and r.status_code == 200:
        try:
            data = r.json()["authentication"]
            token = data.get("token")
            bid = data.get("bid")
        except (ValueError, KeyError):
            pass
    if token:
        s.headers["Authorization"] = f"Bearer {token}"
    pause()

    if bid is not None:
        send(reqlog, s, ip, "GET", BASE + f"/rest/basket/{bid}", *L)
        pause()
    send(reqlog, s, ip, "POST", BASE + "/api/BasketItems/", *L,
         json={"ProductId": random.randint(1, 20), "quantity": random.randint(1, 3)})
    pause()
    comment = random.choice(HARD_NORMAL_PHRASES) if random.random() < 0.2 else random.choice(FEEDBACK_COMMENTS)
    send(reqlog, s, ip, "POST", BASE + "/api/Feedbacks/", *L,
         json={"comment": comment, "rating": random.randint(3, 5)})

    return start, now_iso()


def send_payload_everywhere(reqlog, s, ip, attack_type, payload):
    p = vary(payload)
    target = random.choice(["search", "login_email", "register_email",
                             "feedback_comment", "basket_qty"])
    v = payload_variant(attack_type, payload, target)
    if target == "search":
        send(reqlog, s, ip, "GET", BASE + "/rest/products/search",
             "attack", attack_type, v, params={"q": p})
    elif target == "login_email":
        send(reqlog, s, ip, "POST", BASE + "/rest/user/login",
             "attack", attack_type, v, json={"email": p, "password": "x"})
    elif target == "register_email":
        send(reqlog, s, ip, "POST", BASE + "/api/Users/",
             "attack", attack_type, v, json={
                 "email": p, "password": "x", "passwordRepeat": "x",
                 "securityQuestion": {"id": 1}, "securityAnswer": "x"})
    elif target == "feedback_comment":
        send(reqlog, s, ip, "POST", BASE + "/api/Feedbacks/",
             "attack", attack_type, v, json={"comment": p, "rating": 1})
    elif target == "basket_qty":
        send(reqlog, s, ip, "POST", BASE + "/api/BasketItems/",
             "attack", attack_type, v, json={"ProductId": 1, "quantity": p})


def run_sqli_session(ip, reqlog):
    s = session_http(ip, ATTACK_UAS["sqli"])
    start = now_iso()
    cover_term = random.choice(HARD_NORMAL_PHRASES) if random.random() < 0.2 else random.choice(PRODUCT_TERMS)
    send(reqlog, s, ip, "GET", BASE + "/rest/products/search", "normal", "",
         params={"q": cover_term})
    pause()
    for payload in random.sample(SQLI_PAYLOADS, k=random.randint(4, 8)):
        send_payload_everywhere(reqlog, s, ip, "sqli", payload)
        pause()
    return start, now_iso()


def run_xss_session(ip, reqlog):
    s = session_http(ip, random.choice(BROWSER_UAS))
    start = now_iso()
    cover_term = random.choice(HARD_NORMAL_PHRASES) if random.random() < 0.2 else random.choice(PRODUCT_TERMS)
    send(reqlog, s, ip, "GET", BASE + "/rest/products/search", "normal", "",
         params={"q": cover_term})
    pause()
    for payload in random.sample(XSS_PAYLOADS, k=random.randint(4, 8)):
        send_payload_everywhere(reqlog, s, ip, "xss", payload)
        pause()
    return start, now_iso()


def run_traversal_session(ip, reqlog):
    s = session_http(ip, ATTACK_UAS["traversal"])
    start = now_iso()
    for payload in random.sample(TRAVERSAL_PAYLOADS, k=random.randint(4, 7)):
        send(reqlog, s, ip, "GET", BASE + "/ftp/" + payload, "attack", "traversal",
             payload_variant("traversal", payload))
        pause()
    send(reqlog, s, ip, "GET", BASE + "/rest/products/search", "normal", "",
         params={"q": random.choice(PRODUCT_TERMS)})
    return start, now_iso()


def run_cmdi_session(ip, reqlog):
    s = session_http(ip, random.choice(BROWSER_UAS))
    start = now_iso()
    cover_term = random.choice(HARD_NORMAL_PHRASES) if random.random() < 0.2 else random.choice(PRODUCT_TERMS)
    send(reqlog, s, ip, "GET", BASE + "/rest/products/search", "normal", "",
         params={"q": cover_term})
    pause()
    for payload in random.sample(CMDI_PAYLOADS, k=min(len(CMDI_PAYLOADS), random.randint(4, 8))):
        p = vary(payload)
        target = random.choice(["search", "feedback_comment"])
        v = payload_variant("cmdi", payload)
        if target == "search":
            send(reqlog, s, ip, "GET", BASE + "/rest/products/search",
                 "attack", "cmdi", v, params={"q": p})
        else:
            send(reqlog, s, ip, "POST", BASE + "/api/Feedbacks/",
                 "attack", "cmdi", v, json={"comment": p, "rating": 1})
        pause()
    return start, now_iso()


def run_bruteforce_session(ip, reqlog):
    variant = random.choices(["fast", "slow", "spray"], weights=[50, 25, 25])[0]
    s = session_http(ip, ATTACK_UAS["bruteforce"])
    start = now_iso()

    if variant in ("fast", "slow"):
        target_email = "admin@juice-sh.op"
        n_attempts = random.randint(6, 12) if variant == "fast" else random.randint(3, 5)
        for _ in range(n_attempts):
            send(reqlog, s, ip, "POST", BASE + "/rest/user/login", "attack", "bruteforce",
                 variant, json={"email": target_email, "password": fake_password()})
            if variant == "slow":
                time.sleep(random.uniform(5, 20))
            else:
                pause()
        if random.random() < 0.5:
            send(reqlog, s, ip, "POST", BASE + "/rest/user/login", "attack", "bruteforce",
                 variant, json={"email": target_email, "password": fake_password()})
    else:
        victims = [fake_email() for _ in range(random.randint(8, 15))]
        passwords = [fake_password() for _ in range(random.randint(1, 2))]
        for victim in victims:
            send(reqlog, s, ip, "POST", BASE + "/rest/user/login", "attack", "bruteforce",
                 variant, json={"email": victim, "password": random.choice(passwords)})
            pause()

    return start, now_iso()


def run_scan_session(ip, reqlog):
    s = session_http(ip, ATTACK_UAS["scan"])
    start = now_iso()
    paths = random.sample(SCAN_PATHS, k=min(len(SCAN_PATHS), random.randint(15, 25)))
    for path in paths:
        send(reqlog, s, ip, "GET", BASE + "/" + path.lstrip("/"), "attack", "scan")
        quick_pause()
    return start, now_iso()


def run_enum_session(ip, reqlog):
    s = session_http(ip, random.choice(BROWSER_UAS))
    start = now_iso()
    email, password = fake_email(), fake_password()
    send(reqlog, s, ip, "POST", BASE + "/api/Users/", "normal", "", json={
        "email": email, "password": password, "passwordRepeat": password,
        "securityQuestion": {"id": 1}, "securityAnswer": "lab",
    })
    pause()
    token = None
    r = send(reqlog, s, ip, "POST", BASE + "/rest/user/login", "normal", "",
             json={"email": email, "password": password})
    if r is not None and r.status_code == 200:
        try:
            token = r.json()["authentication"].get("token")
        except (ValueError, KeyError):
            pass
    if token:
        s.headers["Authorization"] = f"Bearer {token}"
    pause()

    n = random.randint(15, 30)
    ids = list(range(1, n + 1)) if random.random() < 0.5 else random.sample(range(1, 500), k=n)
    target = random.choice(["basket_items", "basket"])
    for i in ids:
        if target == "basket_items":
            send(reqlog, s, ip, "GET", BASE + f"/api/BasketItems/{i}", "attack", "enum")
        else:
            send(reqlog, s, ip, "GET", BASE + f"/rest/basket/{i}", "attack", "enum")
        quick_pause()
    return start, now_iso()


def _pick(probs):
    return random.choices(list(probs), weights=list(probs.values()))[0]


def campaign_steps():
    """3 to 5 steps; the table never sends a step to itself, so no step repeats right away."""
    steps = [_pick(CAMPAIGN_START)]
    for _ in range(random.randint(*CAMPAIGN_STEPS) - 1):
        steps.append(_pick(CAMPAIGN_NEXT[steps[-1]]))
    return steps


def run_campaign(ip, reqlog, steps, runners):
    """One attacker, several attacks in a row from the same IP and the same HTTP
    session (one login). Each request keeps the label of its own step; the
    session row says campaign and lists the steps."""
    start = None
    _campaign.session = requests.Session()
    _campaign.session.headers.update({"X-Forwarded-For": ip, "User-Agent": random.choice(BROWSER_UAS)})
    try:
        for i, step in enumerate(steps):
            run_step = runners.get(step) or runners["scan"]     # a site with no ID page: no enum step
            s_start, end = run_step(ip, reqlog)
            start = start or s_start
            if i < len(steps) - 1:
                pause()
    finally:
        _campaign.session = None
    return start, end


ATTACK_RUNNERS = {
    "sqli": run_sqli_session,
    "xss": run_xss_session,
    "traversal": run_traversal_session,
    "bruteforce": run_bruteforce_session,
    "cmdi": run_cmdi_session,
    "scan": run_scan_session,
    "enum": run_enum_session,
}


# ============================================================
# DVWA sessions (new)
# ============================================================
DVWA_ACCOUNTS = [
    ("admin", "password"),
    ("gordonb", "abc123"),
    ("1337", "charley"),
    ("pablo", "letmein"),
    ("smithy", "password"),
]
CSRF_RE = re.compile(r"name=['\"]user_token['\"]\s+value=['\"]([a-f0-9]+)['\"]")

DVWA_STATIC_PAGES = ["/index.php", "/about.php", "/instructions.php", "/security.php"]
DVWA_VULN_PAGES = {
    "sqli": ("/vulnerabilities/sqli/", "id"),
    "xss": ("/vulnerabilities/xss_r/", "name"),
    "traversal": ("/vulnerabilities/fi/", "page"),
}


def get_csrf_token(html):
    if not html:
        return None
    m = CSRF_RE.search(html)
    return m.group(1) if m else None


def dvwa_login_session(reqlog, ip, s):
    """GET the login page to read the CSRF token, then POST credentials
    for a randomly chosen DVWA account (one of the 5 built-in fake
    accounts). A real person sometimes mistypes their own password once
    or twice first."""
    base = BASE_SITES["dvwa"]
    if getattr(s, "dvwa_user", None):          # already logged in (campaign)
        return s.dvwa_user
    username, password = random.choice(DVWA_ACCOUNTS)

    r = send(reqlog, s, ip, "GET", base + "/login.php", "normal", "", site="dvwa")
    token = get_csrf_token(r.text) if r is not None else None

    if random.random() < 0.15:
        for _ in range(random.randint(1, 2)):
            send(reqlog, s, ip, "POST", base + "/login.php", "normal", "", site="dvwa",
                 data={"username": username, "password": password + "x",
                       "Login": "Login", "user_token": token or ""})
            pause()
            r2 = send(reqlog, s, ip, "GET", base + "/login.php", "normal", "", site="dvwa")
            token = get_csrf_token(r2.text) if r2 is not None else token

    send(reqlog, s, ip, "POST", base + "/login.php", "normal", "", site="dvwa",
         data={"username": username, "password": password,
               "Login": "Login", "user_token": token or ""})
    s.dvwa_user = username
    return username


def dvwa_set_security_low(reqlog, ip, s):
    """Set DVWA's security level to low, so vulnerability pages respond
    the same way every session."""
    base = BASE_SITES["dvwa"]
    if getattr(s, "dvwa_low", False):          # already set (campaign)
        return
    r = send(reqlog, s, ip, "GET", base + "/security.php", "normal", "", site="dvwa")
    token = get_csrf_token(r.text) if r is not None else None
    send(reqlog, s, ip, "POST", base + "/security.php", "normal", "", site="dvwa",
         data={"security": "low", "seclev_submit": "Submit", "user_token": token or ""})
    s.dvwa_low = True


def run_normal_session_dvwa(ip, reqlog):
    base = BASE_SITES["dvwa"]
    s = session_http(ip)
    start = now_iso()
    dvwa_login_session(reqlog, ip, s)
    pause()
    dvwa_set_security_low(reqlog, ip, s)
    pause()

    for page in random.sample(DVWA_STATIC_PAGES, k=random.randint(2, 3)):
        send(reqlog, s, ip, "GET", base + page, "normal", "", site="dvwa")
        pause()

    if random.random() < 0.15:
        missing = random.choice(["old_page.php", "report.php", "export.php"])
        send(reqlog, s, ip, "GET", base + "/" + missing, "normal", "", site="dvwa")
        pause()

    # visit vulnerability pages with innocent input - the hardest "normal"
    # case, since the page itself is attack-prone but the value isn't.
    for _ in range(random.randint(2, 4)):
        kind = random.choice(list(DVWA_VULN_PAGES.keys()))
        page, param = DVWA_VULN_PAGES[kind]
        roll = random.random()
        if roll < 0.4:
            value = str(random.randint(1, 20))
        elif roll < 0.75:
            value = random.choice(HARD_NORMAL_NAMES)
        else:
            value = random.choice(HARD_NORMAL_PHRASES)
        params = {param: value}
        if kind in ("sqli", "xss"):
            params["Submit"] = "Submit"
        send(reqlog, s, ip, "GET", base + page, "normal", "", site="dvwa", params=params)
        pause()

    return start, now_iso()


def run_sqli_session_dvwa(ip, reqlog):
    base = BASE_SITES["dvwa"]
    s = session_http(ip, ATTACK_UAS["sqli"])
    start = now_iso()
    dvwa_login_session(reqlog, ip, s)
    pause()
    dvwa_set_security_low(reqlog, ip, s)
    pause()
    cover = random.choice(HARD_NORMAL_NAMES) if random.random() < 0.3 else str(random.randint(1, 20))
    send(reqlog, s, ip, "GET", base + "/vulnerabilities/sqli/", "normal", "", site="dvwa",
         params={"id": cover, "Submit": "Submit"})
    pause()
    for payload in random.sample(SQLI_PAYLOADS, k=random.randint(4, 8)):
        p = vary(payload)
        send(reqlog, s, ip, "GET", base + "/vulnerabilities/sqli/", "attack", "sqli",
             payload_variant("sqli", payload, "query"), site="dvwa",
             params={"id": p, "Submit": "Submit"})
        pause()
    return start, now_iso()


def run_xss_session_dvwa(ip, reqlog):
    base = BASE_SITES["dvwa"]
    s = session_http(ip, random.choice(BROWSER_UAS))
    start = now_iso()
    dvwa_login_session(reqlog, ip, s)
    pause()
    dvwa_set_security_low(reqlog, ip, s)
    pause()
    cover = random.choice(HARD_NORMAL_NAMES) if random.random() < 0.3 else random.choice(PRODUCT_TERMS)
    send(reqlog, s, ip, "GET", base + "/vulnerabilities/xss_r/", "normal", "", site="dvwa",
         params={"name": cover, "Submit": "Submit"})
    pause()
    for payload in random.sample(XSS_PAYLOADS, k=random.randint(4, 8)):
        p = vary(payload)
        send(reqlog, s, ip, "GET", base + "/vulnerabilities/xss_r/", "attack", "xss",
             payload_variant("xss", payload, "search"), site="dvwa",
             params={"name": p})
        pause()
    return start, now_iso()


def run_traversal_session_dvwa(ip, reqlog):
    base = BASE_SITES["dvwa"]
    s = session_http(ip, ATTACK_UAS["traversal"])
    start = now_iso()
    dvwa_login_session(reqlog, ip, s)
    pause()
    dvwa_set_security_low(reqlog, ip, s)
    pause()
    for payload in random.sample(TRAVERSAL_PAYLOADS, k=random.randint(4, 7)):
        send(reqlog, s, ip, "GET", base + "/vulnerabilities/fi/", "attack", "traversal",
             payload_variant("traversal", payload), site="dvwa",
             params={"page": payload})
        pause()
    send(reqlog, s, ip, "GET", base + "/vulnerabilities/fi/", "normal", "", site="dvwa",
         params={"page": "include.php"})
    return start, now_iso()


def run_cmdi_session_dvwa(ip, reqlog):
    """exec/ is a POST form with a CSRF token, so we GET the page for a
    fresh token before every submission."""
    base = BASE_SITES["dvwa"]
    s = session_http(ip, random.choice(BROWSER_UAS))
    start = now_iso()
    dvwa_login_session(reqlog, ip, s)
    pause()
    dvwa_set_security_low(reqlog, ip, s)
    pause()
    for payload in random.sample(CMDI_PAYLOADS, k=min(len(CMDI_PAYLOADS), random.randint(4, 8))):
        r = send(reqlog, s, ip, "GET", base + "/vulnerabilities/exec/", "normal", "", site="dvwa")
        token = get_csrf_token(r.text) if r is not None else None
        p = vary(payload)
        send(reqlog, s, ip, "POST", base + "/vulnerabilities/exec/", "attack", "cmdi",
             payload_variant("cmdi", payload), site="dvwa",
             data={"ip": "127.0.0.1" + p, "Submit": "Submit", "user_token": token or ""})
        pause()
    return start, now_iso()


def run_bruteforce_session_dvwa(ip, reqlog):
    """brute/ requires being logged in (any of the 5 accounts), then the
    attack targets 'admin' (fast/slow) or sprays across several of the 5
    known fake accounts (spray)."""
    base = BASE_SITES["dvwa"]
    variant = random.choices(["fast", "slow", "spray"], weights=[50, 25, 25])[0]
    s = session_http(ip, ATTACK_UAS["bruteforce"])
    start = now_iso()
    dvwa_login_session(reqlog, ip, s)
    pause()
    dvwa_set_security_low(reqlog, ip, s)
    pause()

    if variant in ("fast", "slow"):
        n = random.randint(6, 12) if variant == "fast" else random.randint(3, 5)
        for _ in range(n):
            send(reqlog, s, ip, "GET", base + "/vulnerabilities/brute/", "attack", "bruteforce",
                 variant, site="dvwa",
                 params={"username": "admin", "password": fake_password(), "Login": "Login"})
            if variant == "slow":
                time.sleep(random.uniform(5, 20))
            else:
                pause()
    else:
        victims = random.sample([a for a, _ in DVWA_ACCOUNTS], k=min(5, random.randint(2, 5)))
        passwords = [fake_password() for _ in range(random.randint(1, 2))]
        for victim in victims:
            for _ in range(random.randint(2, 4)):
                send(reqlog, s, ip, "GET", base + "/vulnerabilities/brute/", "attack", "bruteforce",
                     variant, site="dvwa",
                     params={"username": victim, "password": random.choice(passwords), "Login": "Login"})
                pause()

    return start, now_iso()


def run_scan_session_dvwa(ip, reqlog):
    base = BASE_SITES["dvwa"]
    s = session_http(ip, ATTACK_UAS["scan"])
    start = now_iso()
    paths = random.sample(SCAN_PATHS, k=min(len(SCAN_PATHS), random.randint(15, 25)))
    for path in paths:
        send(reqlog, s, ip, "GET", base + "/" + path.lstrip("/"), "attack", "scan", site="dvwa")
        quick_pause()
    return start, now_iso()


def run_enum_session_dvwa(ip, reqlog):
    base = BASE_SITES["dvwa"]
    s = session_http(ip, random.choice(BROWSER_UAS))
    start = now_iso()
    dvwa_login_session(reqlog, ip, s)
    pause()
    dvwa_set_security_low(reqlog, ip, s)
    pause()
    n = random.randint(15, 30)
    ids = list(range(1, n + 1)) if random.random() < 0.5 else random.sample(range(1, 500), k=n)
    for i in ids:
        send(reqlog, s, ip, "GET", base + "/vulnerabilities/sqli/", "attack", "enum", site="dvwa",
             params={"id": i, "Submit": "Submit"})
        quick_pause()
    return start, now_iso()


ATTACK_RUNNERS_DVWA = {
    "sqli": run_sqli_session_dvwa,
    "xss": run_xss_session_dvwa,
    "traversal": run_traversal_session_dvwa,
    "bruteforce": run_bruteforce_session_dvwa,
    "cmdi": run_cmdi_session_dvwa,
    "scan": run_scan_session_dvwa,
    "enum": run_enum_session_dvwa,
}


# ============================================================
# New attack families (generator v4, --families all)
# ============================================================
# Where each family is sent. Juice Shop has real endpoints for some of them
# (profile image URL = SSRF, profile username = SSTI, product reviews = NoSQL,
# file upload = XXE); the others are probes against ordinary inputs, the way a
# scanner tries every field.
NEW_TARGETS_JS = {
    "ssrf": ["profile_image_url", "redirect_to", "search"],
    "xxe": ["xml_upload", "xml_feedback", "xml_login"],
    "ssti": ["profile_username", "search", "feedback_comment"],
    "nosql": ["reviews_patch", "login_json", "search", "reviews_path"],
    "log4shell": ["search", "redirect_to", "profile_image_url"],   # URL-encoded places only
    "ldap": ["login_email", "search", "feedback_comment"],
    "xpath": ["login_email", "search", "feedback_comment"],
}
NEW_TARGETS_DVWA = {
    "ssrf": ["fi_page", "xss_r_name"],
    "xxe": ["xml_xss_s", "xml_sqli", "xml_exec"],
    "ssti": ["xss_r_name", "sqli_id"],
    "nosql": ["brute_params", "brute_json", "sqli_id"],
    "log4shell": ["sqli_id", "xss_r_name", "brute_username"],      # all GET query strings
    "ldap": ["brute_username", "sqli_id"],
    "xpath": ["brute_username", "sqli_id"],
}
XML_HEADERS = {"Content-Type": "application/xml"}


def vary_new(family, payload):
    """Surface variation for the new families. The old vary() splits SQL words and
    swaps spaces, which would break these payloads, so here a payload is either sent
    as it is or URL-encoded once more. Log4Shell payloads already carry their own
    obfuscation, and are sent as they are."""
    if family == "log4shell" or random.random() < 0.7:
        return payload
    return urllib.parse.quote(payload, safe="")


def _is_doc(payload):
    return payload.lstrip().startswith(("{", "<"))


def _nosql_params(payload):
    return "[$" in payload and "=" in payload


def send_new_payload_js(reqlog, s, ip, family, payload):
    v = new_family_variant(family, payload)
    targets = NEW_TARGETS_JS[family]
    if family == "nosql":   # a document goes in a JSON body, "a[$ne]=1&b[$ne]=1" is the query string
        targets = ([t for t in targets if t in ("reviews_patch", "login_json")] if _is_doc(payload) else
                   ["search_params"] if _nosql_params(payload) else
                   [t for t in targets if t in ("search", "reviews_path")])
    target = random.choice(targets)
    a = ("attack", family, v)
    if family == "xxe":
        url = {"xml_upload": "/file-upload", "xml_feedback": "/api/Feedbacks/",
               "xml_login": "/rest/user/login"}[target]
        send(reqlog, s, ip, "POST", BASE + url, *a, data=payload.encode(), headers=XML_HEADERS)
        return
    if target == "reviews_patch":
        send(reqlog, s, ip, "PATCH", BASE + "/rest/products/reviews", *a,
             data=payload.encode(), headers={"Content-Type": "application/json"})
    elif target == "login_json":
        send(reqlog, s, ip, "POST", BASE + "/rest/user/login", *a,
             data=payload.encode(), headers={"Content-Type": "application/json"})
    elif target == "search_params":
        send(reqlog, s, ip, "GET", BASE + "/rest/products/search?" + payload.replace(" ", "%20"), *a)
        return
    p = vary_new(family, payload)
    if target == "search":
        send(reqlog, s, ip, "GET", BASE + "/rest/products/search", *a, params={"q": p})
    elif target == "reviews_path":
        send(reqlog, s, ip, "GET", BASE + "/rest/products/" + urllib.parse.quote(p, safe="") + "/reviews", *a)
    elif target == "redirect_to":
        send(reqlog, s, ip, "GET", BASE + "/redirect", *a, params={"to": p})
    elif target == "profile_image_url":
        send(reqlog, s, ip, "POST", BASE + "/profile/image/url", *a, data={"imageUrl": p})
    elif target == "profile_username":
        send(reqlog, s, ip, "POST", BASE + "/profile", *a, data={"username": p})
    elif target == "login_email":
        send(reqlog, s, ip, "POST", BASE + "/rest/user/login", *a, json={"email": p, "password": "x"})
    elif target == "feedback_comment":
        send(reqlog, s, ip, "POST", BASE + "/api/Feedbacks/", *a, json={"comment": p, "rating": 1})


def send_new_payload_dvwa(reqlog, s, ip, family, payload):
    base = BASE_SITES["dvwa"]
    v = new_family_variant(family, payload)
    targets = NEW_TARGETS_DVWA[family]
    if family == "nosql":
        targets = (["brute_json"] if _is_doc(payload) else
                   ["brute_params"] if _nosql_params(payload) else ["sqli_id"])
    target = random.choice(targets)
    a = ("attack", family, v)
    kw = {"site": "dvwa"}
    if family == "xxe":
        url = {"xml_xss_s": "/vulnerabilities/xss_s/", "xml_sqli": "/vulnerabilities/sqli/",
               "xml_exec": "/vulnerabilities/exec/"}[target]
        send(reqlog, s, ip, "POST", base + url, *a, data=payload.encode(), headers=XML_HEADERS, **kw)
        return
    if target == "brute_json":
        send(reqlog, s, ip, "POST", base + "/vulnerabilities/brute/", *a,
             data=payload.encode(), headers={"Content-Type": "application/json"}, **kw)
        return
    if target == "brute_params":
        send(reqlog, s, ip, "GET", base + "/vulnerabilities/brute/?" + payload.replace(" ", "%20") + "&Login=Login",
             *a, **kw)
        return
    p = vary_new(family, payload)
    if target == "sqli_id":
        send(reqlog, s, ip, "GET", base + "/vulnerabilities/sqli/", *a, params={"id": p, "Submit": "Submit"}, **kw)
    elif target == "xss_r_name":
        send(reqlog, s, ip, "GET", base + "/vulnerabilities/xss_r/", *a, params={"name": p}, **kw)
    elif target == "fi_page":
        send(reqlog, s, ip, "GET", base + "/vulnerabilities/fi/", *a, params={"page": p}, **kw)
    elif target == "brute_username":
        send(reqlog, s, ip, "GET", base + "/vulnerabilities/brute/", *a,
             params={"username": p, "password": fake_password(), "Login": "Login"}, **kw)


def make_new_family_runner(family, site):
    """One attacker trying 4 to 8 payloads of one new family, after one normal-looking request."""
    def run(ip, reqlog):
        s = session_http(ip, random.choice(BROWSER_UAS))
        start = now_iso()
        payloads = NEW_PAYLOADS[family]
        picked = random.sample(payloads, k=min(len(payloads), random.randint(4, 8)))
        if site == "juiceshop":
            send(reqlog, s, ip, "GET", BASE + "/rest/products/search", "normal", "",
                 params={"q": random.choice(PRODUCT_TERMS)})
            pause()
            for payload in picked:
                send_new_payload_js(reqlog, s, ip, family, payload)
                pause()
        else:
            base = BASE_SITES["dvwa"]
            dvwa_login_session(reqlog, ip, s)
            pause()
            dvwa_set_security_low(reqlog, ip, s)
            pause()
            send(reqlog, s, ip, "GET", base + "/vulnerabilities/sqli/", "normal", "", site="dvwa",
                 params={"id": str(random.randint(1, 20)), "Submit": "Submit"})
            pause()
            for payload in picked:
                send_new_payload_dvwa(reqlog, s, ip, family, payload)
                pause()
        return start, now_iso()
    run.__name__ = f"run_{family}_session_{site}"
    return run


def add_new_family_runners():
    """--families all: load the v4 payloads and add one runner per new family on both sites."""
    for family in NEW_FAMILIES:
        NEW_PAYLOADS[family] = load_b64_payloads(f"v4_{family}.b64")
        ATTACK_RUNNERS[family] = make_new_family_runner(family, "juiceshop")
        ATTACK_RUNNERS_DVWA[family] = make_new_family_runner(family, "dvwa")


# ============================================================
# Extra sites (generator v6): bWAPP, Mutillidae, DVNA
# ============================================================
# Three more vulnerable apps, so the models can be tested on a site they never
# saw (leave one site out). Each site is described by a spec: how a user logs in,
# which pages a visitor opens, and which inputs exist; the same runners then send
# normal visits and every kind of attack to any site. Lab addresses only.
# Success markers (true_stage) come from looking at each app's real answers.
def _rows(text, tag="<tr"):
    return text.count(tag)


SITE_SPECS = {
    "bwapp": {
        "login": ("POST", "/login.php", lambda acc: {"login": acc[0], "password": acc[1],
                                                   "security_level": "0", "form": "submit"}),
        "accounts": [("bee", "bug")],
        "pages": ["/portal.php", "/info.php", "/training.php", "/credits.php", "/aim.php", "/user_extra.php"],
        "missing": ["/old_portal.php", "/report.php", "/movies.php"],
        "inputs": {
            "movie_search": ("GET", "/sqli_1.php", "title", {"action": "search"}, "words"),
            "names": ("GET", "/xss_get.php", "firstname", {"lastname": "Smith", "form": "submit"}, "names"),
            "language": ("GET", "/rlfi.php", "language", {"action": "go"}, ["lang_en.php", "lang_fr.php", "lang_nl.php"]),
            "dns": ("POST", "/commandi.php", "target", {"form": "submit"}, "hosts"),
        },
        "attack_inputs": {"sqli": ["movie_search"], "xss": ["names", "movie_search"], "traversal": ["language"],
                          "cmdi": ["dns"], "new": ["movie_search", "names", "dns"]},
        "bruteforce": ("POST", "/login.php", "login", "password", {"security_level": "0", "form": "submit"},
                       ["bee", "A.I.M.", "admin"]),
        "enum": ("GET", "/sqli_2.php", "movie", {"action": "go"}),
        "sqli_worked": lambda t: _rows(t) >= 12 or re.search(r"\b[a-f0-9]{40}\b", t) is not None,
        "enum_found": lambda t: re.search(r"<td>[A-Z][^<]{2,}</td>", t) is not None,
        "login_won": lambda r: r.status_code in (301, 302) and "portal.php" in r.headers.get("Location", ""),
    },
    "mutillidae": {
        "login": ("POST", "/index.php?page=login.php",
                  lambda acc: {"username": acc[0], "password": acc[1], "login-php-submit-button": "Login"}),
        "accounts": [("admin", "adminpass"), ("adrian", "somepassword"), ("john", "monkey"),
                     ("jeremy", "password"), ("bryce", "password")],
        "pages": ["/index.php?page=home.php", "/index.php?page=browser-info.php", "/index.php?page=user-poll.php",
                  "/index.php?page=text-file-viewer.php", "/index.php?page=add-to-your-blog.php",
                  "/index.php?page=site-footer-xss-discussion.php"],
        "missing": ["/old.php", "/index.php?page=report.php", "/backup/"],
        "inputs": {
            "user_info": ("GET", "/index.php", "username", {"page": "user-info.php", "password": "{password}",
                                                          "user-info-php-submit-button": "View Account Details"}, "names"),
            "dns": ("POST", "/index.php?page=dns-lookup.php", "target_host",
                    {"dns-lookup-php-submit-button": "Lookup DNS"}, "hosts"),
            "page": ("GET", "/index.php", "page", {}, ["home.php", "browser-info.php", "user-poll.php",
                                                      "text-file-viewer.php", "dns-lookup.php"]),
        },
        "attack_inputs": {"sqli": ["user_info"], "xss": ["dns", "user_info"], "traversal": ["page"],
                          "cmdi": ["dns"], "new": ["user_info", "dns"]},
        "bruteforce": ("POST", "/index.php?page=login.php", "username", "password",
                       {"login-php-submit-button": "Login"}, ["admin", "adrian", "john", "jeremy"]),
        "enum": None,
        "sqli_worked": lambda t: any(int(n) >= 2 for n in re.findall(r"(\d+) records found", t)),
        "login_won": lambda r: r.status_code in (301, 302),
    },
    "dvna": {
        "register": True,
        "login": ("POST", "/login", lambda acc: {"username": acc[0], "password": acc[1]}),
        "accounts": [],
        "pages": ["/learn", "/app/products", "/app/usersearch", "/app/ping", "/app/calc",
                  "/learn/vulnerability/a1_injection", "/learn/vulnerability/a7_xss"],
        "missing": ["/app/orders", "/app/report", "/old"],
        "inputs": {
            "usersearch": ("POST", "/app/usersearch", "login", {}, "names"),
            "products": ("POST", "/app/products", "name", {}, "words"),
            "ping": ("POST", "/app/ping", "address", {}, "hosts"),
            "redirect": ("GET", "/app/redirect", "url", {}, ["/learn", "/app/products", "/app/ping"]),
        },
        "attack_inputs": {"sqli": ["usersearch"], "xss": ["products", "usersearch"], "traversal": ["redirect"],
                          "cmdi": ["ping"], "new": ["products", "usersearch", "ping"]},
        "bruteforce": ("POST", "/login", "username", "password", {}, None),
        "enum": None,
        "sqli_worked": lambda t: "Search Result" in t,
        "login_won": lambda r: r.status_code in (301, 302) and "/learn" in r.headers.get("Location", ""),
    },
    # ---- API sites: every request is JSON (REST) or one GraphQL endpoint ----
    # Input kinds beyond GET/POST forms: "JSON" (POST, JSON body), "PATH" (GET, the value
    # is a path segment: path has {v}), "GQL" (POST /graphql, the value goes into a string
    # argument of the query template in place of {v}).
    "vampi": {
        "login": ("JSON", "/users/v1/login", lambda acc: {"username": acc[0], "password": acc[1]}),
        "accounts": [("name1", "pass1"), ("name2", "pass2")],
        "pages": ["/", "/users/v1", "/books/v1"],
        "missing": ["/api/v2/users", "/admin", "/users/v2"],
        "inputs": {
            "user": ("PATH", "/users/v1/{v}", None, {}, ["name1", "name2", "admin"]),
            "book": ("PATH", "/books/v1/{v}", None, {}, "books"),
            "add_book": ("JSON", "/books/v1", "book_title", {"secret": "my notes"}, "books"),
            "register": ("JSON", "/users/v1/register", "username", {"password": "{password}", "email": "lab@example-lab.test"}, "names"),
        },
        "attack_inputs": {"sqli": ["user"], "xss": ["add_book", "register"], "traversal": ["book"],
                          "cmdi": ["user", "add_book"], "new": ["add_book", "register", "user"]},
        "bruteforce": ("JSON", "/users/v1/login", "username", "password", {}, ["admin", "name1", "name2"]),
        "enum": ("PATH", "/books/v1/bookTitle{v}", None, {}),
        "sqli_worked": lambda t: '"email"' in t,
        "enum_found": lambda t: '"secret"' in t,
        "login_won": lambda r: "auth_token" in r.text,
    },
    "dvga": {
        "login": ("GQL", "/graphql", lambda acc: 'mutation { login(username:"%s", password:"%s") { accessToken } }' % acc),
        "accounts": [("admin", "changeme"), ("operator", "password123")],
        "pages": ["/", "/public_pastes", "/about"],
        "missing": ["/admin", "/graphiql", "/api"],
        "inputs": {
            "search": ("GQL", "/graphql", 'query { pastes(filter:"{v}") { id title content } }', {}, "words"),
            "create": ("GQL", "/graphql", 'mutation { createPaste(title:"Note", content:"{v}", public:true) { paste { id } } }', {}, "names"),
            "import": ("GQL", "/graphql", 'mutation { importPaste(host:"127.0.0.1", port:80, path:"{v}", scheme:"http") { result } }', {}, ["/", "/about", "/public_pastes"]),
            "owner": ("GQL", "/graphql", 'query { pastes(filter:"{v}") { id owner { name } } }', {}, "names"),
        },
        "attack_inputs": {"sqli": ["search", "owner"], "xss": ["create"], "traversal": ["import"],
                          "cmdi": ["import"], "new": ["search", "create", "import"]},
        "bruteforce": ("GQL", "/graphql", None, None, 'mutation { login(username:"{u}", password:"{p}") { accessToken } }', ["admin", "operator"]),
        "enum": ("GQL", "/graphql", 'query { paste(id: {v}) { id title content } }', {}),
        "sqli_worked": lambda t: t.count('"id"') >= 6,
        "enum_found": lambda t: '"paste":{' in t.replace(" ", ""),
        "login_won": lambda r: '"accessToken":"' in r.text.replace(" ", ""),
    },
}
EXTRA_SITES = list(SITE_SPECS)
ATTACK_PREFIX = {"mutillidae": {"dns": "127.0.0.1"}, "dvna": {"ping": "127.0.0.1"}, "dvga": {"import": "/"}}
EXTRA_PORTS = {"mutillidae": 8084, "bwapp": 8085, "dvna": 8086, "vampi": 8087, "dvga": 8088}
VAMPI_BOOKS = ["bookTitle" + str(n) for n in range(1, 100)]


def _gql_string(value):
    """A value inside a GraphQL string argument, escaped as a client library would."""
    return str(value).replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")


def _api_request(method, path, param, extra, value):
    """(HTTP method, path, requests kwargs) for one input of any kind."""
    if method == "PATH":
        return "GET", path.replace("{v}", urllib.parse.quote(str(value), safe="")), {}
    if method == "GQL":
        return "POST", path, {"json": {"query": param.replace("{v}", _gql_string(value))}}
    fields = dict(extra)
    if param:
        fields[param] = value
    if method == "JSON":
        return "POST", path, {"json": fields}
    return method, path, ({"params": fields} if method == "GET" else {"data": fields})


def _keep_token(s, resp):
    """API login: later requests carry the token, as the site's own client does."""
    try:
        data = resp.json()
    except Exception:
        return
    token = data.get("auth_token") or ((data.get("data") or {}).get("login") or {}).get("accessToken")
    if token:
        s.headers["Authorization"] = "Bearer " + token
NORMAL_HOSTS = ["127.0.0.1", "localhost", "example.com", "lab.local", "8.8.8.8", "intranet"]
_extra_site = threading.local()          # which extra site the current thread works on


def _spec_value(kind):
    if isinstance(kind, list):
        return random.choice(kind)
    roll = random.random()
    if kind == "hosts":
        return random.choice(NORMAL_HOSTS)
    if kind == "books":
        return random.choice(VAMPI_BOOKS[:60])
    if kind == "names":
        return random.choice(HARD_NORMAL_NAMES) if roll < 0.8 else random.choice(HARD_NORMAL_PHRASES)
    return random.choice(PRODUCT_TERMS) if roll < 0.7 else random.choice(HARD_NORMAL_PHRASES)


def _spec_send(reqlog, s, ip, site, name, value, label, attack_type, variant="", account=None):
    spec = SITE_SPECS[site]
    method, path, param, extra, _ = spec["inputs"][name]
    fields = {k: v.replace("{password}", (account or ("x", fake_password()))[1]) for k, v in extra.items()}
    # A shell input (DNS lookup, ping) gets a real host before the payload, as a real
    # attacker sends it: an empty host makes the tool wait for input and the request hangs.
    if label == "attack" and name in ATTACK_PREFIX.get(site, {}):
        value = ATTACK_PREFIX[site][name] + value
    if method in ("JSON", "PATH", "GQL"):
        http, p, kw = _api_request(method, path, param, fields, value)
        return send(reqlog, s, ip, http, BASE_SITES[site] + p, label, attack_type, variant, site=site, **kw)
    fields[param] = value
    url = BASE_SITES[site] + path
    kw = {"params": fields} if method == "GET" else {"data": fields}
    return send(reqlog, s, ip, method, url, label, attack_type, variant, site=site, **kw)


def _spec_login(reqlog, s, ip, site):
    """Log in as an ordinary user (DVNA: register a new fake account first). Returns the account."""
    spec = SITE_SPECS[site]
    base = BASE_SITES[site]
    if getattr(s, "spec_account", None):        # already logged in (campaign: one login for all steps)
        return s.spec_account
    if spec.get("register"):
        user = "u" + "".join(random.choices(string.digits, k=7))
        acc = (user, fake_password())
        send(reqlog, s, ip, "POST", base + "/register", "normal", "", site=site,
             data={"name": "Lab " + user, "username": acc[0], "email": user + "@example-lab.test",
                   "password": acc[1], "cpassword": acc[1]})
        pause()
    else:
        acc = random.choice(spec["accounts"])
    method, path, fields = spec["login"]
    if method == "GQL":
        r = send(reqlog, s, ip, "POST", base + path, "normal", "", site=site, json={"query": fields(acc)})
    elif method == "JSON":
        r = send(reqlog, s, ip, "POST", base + path, "normal", "", site=site, json=fields(acc))
    else:
        r = send(reqlog, s, ip, method, base + path, "normal", "", site=site, data=fields(acc))
    if r is not None:
        _keep_token(s, r)
    s.spec_account = acc
    return acc


def _enum_request(spec, i):
    method, path, param, extra = spec["enum"]
    if method in ("PATH", "GQL"):
        return _api_request(method, path, param, extra, i)
    return method, path, {"params": {param: i, **extra}}


def _make_extra_normal(site):
    def run(ip, reqlog):
        spec = SITE_SPECS[site]
        s = session_http(ip)
        start = now_iso()
        acc = _spec_login(reqlog, s, ip, site)
        pause()
        for page in random.sample(spec["pages"], k=min(len(spec["pages"]), random.randint(2, 4))):
            send(reqlog, s, ip, "GET", BASE_SITES[site] + page, "normal", "", site=site)
            pause()
        if random.random() < 0.15:
            send(reqlog, s, ip, "GET", BASE_SITES[site] + random.choice(spec["missing"]), "normal", "", site=site)
            pause()
        for _ in range(random.randint(2, 4)):
            name = random.choice(list(spec["inputs"]))
            value = _spec_value(spec["inputs"][name][4])
            if name == "user_info":
                value = acc[0]
            _spec_send(reqlog, s, ip, site, name, value, "normal", "", account=acc)
            pause()
        if spec["enum"] and random.random() < 0.5:
            for i in random.sample(range(1, 11), k=random.randint(1, 3)):
                http, p, kw = _enum_request(spec, i)
                send(reqlog, s, ip, http, BASE_SITES[site] + p, "normal", "", site=site, **kw)
                pause()
        return start, now_iso()
    return run


def _make_extra_payload_runner(site, attack_type, payloads_of):
    def run(ip, reqlog):
        spec = SITE_SPECS[site]
        s = session_http(ip, ATTACK_UAS.get(attack_type) or random.choice(BROWSER_UAS))
        start = now_iso()
        acc = _spec_login(reqlog, s, ip, site)
        pause()
        targets = spec["attack_inputs"].get(attack_type) or spec["attack_inputs"]["new"]
        cover = random.choice(targets)
        _spec_send(reqlog, s, ip, site, cover, _spec_value(spec["inputs"][cover][4]), "normal", "", account=acc)
        pause()
        payloads = payloads_of()
        for payload in random.sample(payloads, k=min(len(payloads), random.randint(4, 8))):
            if attack_type in NEW_FAMILIES:
                p, v = vary_new(attack_type, payload), new_family_variant(attack_type, payload)
            elif attack_type == "traversal":
                p, v = payload, payload_variant("traversal", payload)
            else:
                p, v = vary(payload), payload_variant(attack_type, payload)
            _spec_send(reqlog, s, ip, site, random.choice(targets), p, "attack", attack_type, v, account=acc)
            pause()
        return start, now_iso()
    return run


def _make_extra_bruteforce(site):
    def run(ip, reqlog):
        spec = SITE_SPECS[site]
        method, path, ufield, pfield, extra, users = spec["bruteforce"]

        def attempt(user, password):
            if method == "GQL":
                q = extra.replace("{u}", _gql_string(user)).replace("{p}", _gql_string(password))
                return {"json": {"query": q}}
            if method == "JSON":
                return {"json": {ufield: user, pfield: password}}
            return {"data": {ufield: user, pfield: password, **extra}}
        http = "POST" if method in ("JSON", "GQL") else method
        variant = random.choices(["fast", "slow", "spray"], weights=[50, 25, 25])[0]
        s = session_http(ip, ATTACK_UAS["bruteforce"])
        start = now_iso()
        users = users or ["admin", "labuser", "root", "test"]
        url = BASE_SITES[site] + path
        if variant in ("fast", "slow"):
            target = users[0]
            for _ in range(random.randint(6, 12) if variant == "fast" else random.randint(3, 5)):
                send(reqlog, s, ip, http, url, "attack", "bruteforce", variant, site=site,
                     **attempt(target, fake_password()))
                time.sleep(random.uniform(5, 20)) if variant == "slow" else pause()
        else:
            passwords = [fake_password() for _ in range(random.randint(1, 2))]
            for victim in random.sample(users, k=min(len(users), random.randint(2, 4))):
                for _ in range(random.randint(2, 4)):
                    send(reqlog, s, ip, http, url, "attack", "bruteforce", variant, site=site,
                         **attempt(victim, random.choice(passwords)))
                    pause()
        return start, now_iso()
    return run


def _make_extra_scan(site):
    def run(ip, reqlog):
        s = session_http(ip, ATTACK_UAS["scan"])
        start = now_iso()
        for path in random.sample(SCAN_PATHS, k=min(len(SCAN_PATHS), random.randint(15, 25))):
            send(reqlog, s, ip, "GET", BASE_SITES[site] + "/" + path.lstrip("/"), "attack", "scan", site=site)
            quick_pause()
        return start, now_iso()
    return run


def _make_extra_enum(site):
    def run(ip, reqlog):
        method, path, param, extra = SITE_SPECS[site]["enum"]
        s = session_http(ip, random.choice(BROWSER_UAS))
        start = now_iso()
        _spec_login(reqlog, s, ip, site)
        pause()
        n = random.randint(15, 30)
        ids = list(range(1, n + 1)) if random.random() < 0.5 else random.sample(range(1, 500), k=n)
        for i in ids:
            http, p, kw = _enum_request(SITE_SPECS[site], i)
            send(reqlog, s, ip, http, BASE_SITES[site] + p, "attack", "enum", site=site, **kw)
            quick_pause()
        return start, now_iso()
    return run


def extra_site_runners(site, families_all):
    """(normal runner, attack runners) for one extra site."""
    runners = {
        "sqli": _make_extra_payload_runner(site, "sqli", lambda: SQLI_PAYLOADS),
        "xss": _make_extra_payload_runner(site, "xss", lambda: XSS_PAYLOADS),
        "traversal": _make_extra_payload_runner(site, "traversal", lambda: TRAVERSAL_PAYLOADS),
        "cmdi": _make_extra_payload_runner(site, "cmdi", lambda: CMDI_PAYLOADS),
        "bruteforce": _make_extra_bruteforce(site),
        "scan": _make_extra_scan(site),
    }
    if SITE_SPECS[site]["enum"]:
        runners["enum"] = _make_extra_enum(site)
    if families_all:
        for family in NEW_FAMILIES:
            runners[family] = _make_extra_payload_runner(site, family, lambda f=family: NEW_PAYLOADS[f])
    return _make_extra_normal(site), runners


# ---------- capture new access.log lines produced by this run ----------
def capture_log_start(log_path):
    if log_path.exists():
        return log_path.stat().st_size
    return 0


def capture_log_end(log_path, start_size, out_path):
    out_path.parent.mkdir(parents=True, exist_ok=True)
    if not log_path.exists():
        print(f"  warning: log file not found at {log_path}, nothing captured")
        return 0
    with open(log_path, "rb") as f:
        f.seek(start_size)
        new_bytes = f.read()
    with open(out_path, "wb") as f:
        f.write(new_bytes)
    return new_bytes.count(b"\n")


def main():
    ap = argparse.ArgumentParser(description="Generate labelled traffic for the lab.")
    ap.add_argument("--site", choices=["juiceshop", "dvwa"] + EXTRA_SITES, default="juiceshop",
                     help="Which lab site to target.")
    ap.add_argument("--sessions", type=int, default=300)
    ap.add_argument("--seed", type=int, default=0)
    ap.add_argument("--out-tag", type=str, default="",
                     help="Suffix for output files, e.g. 'run3' -> requests_run3.csv")
    ap.add_argument("--log-path", type=str, default=None,
                     help="Access log to capture new lines from. Defaults to "
                          "lab/logs/access.log (juiceshop) or "
                          "lab/logs/dvwa_access.log (dvwa).")
    ap.add_argument("--workers", type=int, default=8,
                     help="Concurrent sessions, to keep a full run fast. "
                          "Lower this if the lab becomes unstable under load.")
    ap.add_argument("--campaigns", type=int, default=0,
                     help="How many attacker sessions go through several steps in a row "
                          "(see CAMPAIGN_NEXT). Default 0: same traffic as before.")
    ap.add_argument("--families", choices=["old", "all"], default="old",
                     help="'all' adds the new attack families (SSRF, XXE, SSTI, NoSQL, Log4Shell, "
                          "LDAP, XPath) to the attacker sessions. Default 'old': same traffic as before.")
    ap.add_argument("--port", type=int, default=None,
                     help="Port of the lab site on this machine, if not the default "
                          "(8080 juiceshop, 8081 dvwa). The host stays 127.0.0.1.")
    args = ap.parse_args()
    if args.port is not None:
        global BASE
        BASE_SITES[args.site] = f"{LAB_HOST}:{args.port}"
        if args.site == "juiceshop":
            BASE = BASE_SITES["juiceshop"]
        print(f"{args.site}: using {BASE_SITES[args.site]}")
    if args.site == "dvwa" and args.workers != 1:
        # DVWA loses logged-in sessions when sessions run in parallel: most pages
        # then redirect (302) to the login page. One worker fixes it (dvwa_check run).
        print(f"dvwa: using 1 worker instead of {args.workers}")
        args.workers = 1

    if args.site in EXTRA_SITES and args.workers > 4:
        print(f"{args.site}: using 4 workers instead of {args.workers}")
        args.workers = 4
    if args.log_path is None:
        args.log_path = ("lab/logs/access.log" if args.site == "juiceshop"
                          else f"lab/logs/{args.site}_access.log")

    if args.families == "all":
        add_new_family_runners()
        print("families: old + " + ", ".join(f"{f} ({len(NEW_PAYLOADS[f])} payloads)" for f in NEW_FAMILIES))

    random.seed(args.seed)
    reqlog = RequestLog()
    session_rows = []
    session_rows_lock = threading.Lock()
    sessions_out = sessions_path(args.out_tag, args.site)
    requests_out = requests_path(args.out_tag, args.site)

    log_path = Path(args.log_path)
    if not log_path.is_absolute():
        log_path = ROOT / log_path
    log_start_size = capture_log_start(log_path)

    if args.site in EXTRA_SITES:
        normal_runner, attack_runners = extra_site_runners(args.site, args.families == "all")
    else:
        normal_runner = run_normal_session if args.site == "juiceshop" else run_normal_session_dvwa
        attack_runners = ATTACK_RUNNERS if args.site == "juiceshop" else ATTACK_RUNNERS_DVWA

    n_attack = int(args.sessions * 0.30)
    n_normal = args.sessions - n_attack
    plan = ["normal"] * n_normal + random.choices(list(attack_runners.keys()), k=n_attack)
    random.shuffle(plan)
    n_campaigns = min(args.campaigns, n_attack)
    if n_campaigns:
        # Turn n_campaigns of the attacker sessions into campaigns; the steps are
        # picked here, before the sessions run, so a seed always gives the same plan.
        attack_slots = [i for i, k in enumerate(plan) if k != "normal"]
        for i in sorted(random.sample(attack_slots, k=n_campaigns)):
            plan[i] = ("campaign", campaign_steps())

    done_count = [0]
    done_lock = threading.Lock()

    def job(kind):
        ip = next_ip()
        if kind == "normal":
            start, end = normal_runner(ip, reqlog)
            row = [ip, "normal", "", start, end, ""]
        elif isinstance(kind, tuple):
            steps = kind[1]
            start, end = run_campaign(ip, reqlog, steps, attack_runners)
            row = [ip, "attack", "campaign", start, end, ">".join(steps)]
        else:
            start, end = attack_runners[kind](ip, reqlog)
            row = [ip, "attack", kind, start, end, ""]
        with session_rows_lock:
            session_rows.append(row)
        with done_lock:
            done_count[0] += 1
            if done_count[0] % 20 == 0:
                print(f"{done_count[0]}/{len(plan)} sessions done")

    t0 = time.monotonic()
    with ThreadPoolExecutor(max_workers=args.workers) as ex:
        list(ex.map(job, plan))
    elapsed = time.monotonic() - t0

    sessions_out.parent.mkdir(parents=True, exist_ok=True)
    with open(sessions_out, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["ip", "label", "attack_type", "start_time", "end_time", "steps"])
        w.writerows(session_rows)
    reqlog.write(requests_out)

    log_out_path = generated_log_path(args.site, args.out_tag)
    n_log_lines = capture_log_end(log_path, log_start_size, log_out_path)

    print(f"\nDone in {elapsed:.0f}s: site={args.site}, {len(session_rows)} sessions -> {sessions_out}")
    print(f"      {len(reqlog.rows)} requests -> {requests_out}")
    print(f"      {n_log_lines} new access-log lines -> {log_out_path}")

    print("\nStatus code counts:")
    for code, count in sorted(reqlog.status_counts.items(), key=lambda x: str(x[0])):
        print(f"  {code}: {count}")

    print("\nAttacks by type/variant/site:")
    for (atype, variant, site), count in sorted(reqlog.attack_counts.items()):
        label = f"{atype} ({variant})" if variant else atype
        print(f"  {label} [{site}]: {count}")

    campaigns = [k[1] for k in plan if isinstance(k, tuple)]
    if campaigns:
        print(f"\nCampaigns: {len(campaigns)}")
        print("  steps:", dict(Counter(st for c in campaigns for st in c).most_common()))
        pairs = Counter(f"{a}>{b}" for c in campaigns for a, b in zip(c, c[1:]))
        print("  step pairs:", dict(pairs.most_common()))


if __name__ == "__main__":
    main()