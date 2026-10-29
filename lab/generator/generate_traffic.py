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

Campaigns (--campaigns N): N of the attacker sessions go through several
steps in a row from the same IP (for example scan > enum > sqli), like a
real intrusion. Used for the next-step model. The steps are picked from
CAMPAIGN_START / CAMPAIGN_NEXT below, and each step reuses the normal
session function of that attack. With the default 0 a run is the same as before.
"""
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


def session_http(ip, user_agent=None):
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


# ---------- per-request logging (thread-safe: sessions run concurrently) ----------
class RequestLog:
    def __init__(self):
        self.rows = []
        self.status_counts = Counter()
        self.attack_counts = Counter()  # (attack_type, variant, site) -> count
        self._lock = threading.Lock()

    def record(self, ip, method, path, label, attack_type, variant, site):
        with self._lock:
            self.rows.append([now_iso(), ip, method, path, label, attack_type, variant, site])
            if label == "attack":
                self.attack_counts[(attack_type, variant, site)] += 1

    def log_response(self, resp, ip, label, attack_type, variant, site):
        with self._lock:
            self.status_counts[resp.status_code] += 1
        path = urllib.parse.urlsplit(resp.request.url).path
        self.record(ip, resp.request.method, path, label, attack_type, variant, site)

    def log_error(self):
        with self._lock:
            self.status_counts["error"] += 1

    def write(self, path):
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["time", "ip", "method", "path", "label", "attack_type", "variant", "site"])
            w.writerows(self.rows)


def send(reqlog, s, ip, method, url, label, attack_type, variant="", site="juiceshop", **kwargs):
    """... Redirects are NOT followed automatically: each hop must be its
    own send() call, so every request we make maps to exactly one log
    line and is labelled with its own real method/path (e.g. the login
    POST itself, not the page it redirects to)."""
    kwargs.setdefault("allow_redirects", False)
    for attempt in (1, 2):
        try:
            resp = s.request(method, url, timeout=5, **kwargs)
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
    if target == "search":
        send(reqlog, s, ip, "GET", BASE + "/rest/products/search",
             "attack", attack_type, params={"q": p})
    elif target == "login_email":
        send(reqlog, s, ip, "POST", BASE + "/rest/user/login",
             "attack", attack_type, json={"email": p, "password": "x"})
    elif target == "register_email":
        send(reqlog, s, ip, "POST", BASE + "/api/Users/",
             "attack", attack_type, json={
                 "email": p, "password": "x", "passwordRepeat": "x",
                 "securityQuestion": {"id": 1}, "securityAnswer": "x"})
    elif target == "feedback_comment":
        send(reqlog, s, ip, "POST", BASE + "/api/Feedbacks/",
             "attack", attack_type, json={"comment": p, "rating": 1})
    elif target == "basket_qty":
        send(reqlog, s, ip, "POST", BASE + "/api/BasketItems/",
             "attack", attack_type, json={"ProductId": 1, "quantity": p})


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
        send(reqlog, s, ip, "GET", BASE + "/ftp/" + payload, "attack", "traversal")
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
        if target == "search":
            send(reqlog, s, ip, "GET", BASE + "/rest/products/search",
                 "attack", "cmdi", params={"q": p})
        else:
            send(reqlog, s, ip, "POST", BASE + "/api/Feedbacks/",
                 "attack", "cmdi", json={"comment": p, "rating": 1})
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
    """One attacker, several attacks in a row from the same IP. Each request keeps
    the label of its own step; the session row says campaign and lists the steps."""
    start = None
    for i, step in enumerate(steps):
        s_start, end = runners[step](ip, reqlog)
        start = start or s_start
        if i < len(steps) - 1:
            pause()
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
    return username


def dvwa_set_security_low(reqlog, ip, s):
    """Set DVWA's security level to low, so vulnerability pages respond
    the same way every session."""
    base = BASE_SITES["dvwa"]
    r = send(reqlog, s, ip, "GET", base + "/security.php", "normal", "", site="dvwa")
    token = get_csrf_token(r.text) if r is not None else None
    send(reqlog, s, ip, "POST", base + "/security.php", "normal", "", site="dvwa",
         data={"security": "low", "seclev_submit": "Submit", "user_token": token or ""})


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
        send(reqlog, s, ip, "GET", base + "/vulnerabilities/sqli/", "attack", "sqli", site="dvwa",
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
        send(reqlog, s, ip, "GET", base + "/vulnerabilities/xss_r/", "attack", "xss", site="dvwa",
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
        send(reqlog, s, ip, "GET", base + "/vulnerabilities/fi/", "attack", "traversal", site="dvwa",
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
        send(reqlog, s, ip, "POST", base + "/vulnerabilities/exec/", "attack", "cmdi", site="dvwa",
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
    ap.add_argument("--site", choices=["juiceshop", "dvwa"], default="juiceshop",
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

    if args.log_path is None:
        args.log_path = ("lab/logs/access.log" if args.site == "juiceshop"
                          else "lab/logs/dvwa_access.log")

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