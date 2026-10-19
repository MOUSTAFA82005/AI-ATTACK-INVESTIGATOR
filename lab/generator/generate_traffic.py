"""
generate_traffic.py - traffic generator for the AI Attack Investigator lab.

LAB ONLY. Targets http://127.0.0.1:8080 (our own isolated Juice Shop/Nginx
in Docker) and nothing else. This script refuses to run against any other
host. Never remove or change this check.

Each simulated session gets its own fake IP (10.1.x.y, to never clash with
manual_examples.py's 10.0.0.x) sent via X-Forwarded-For, so Nginx logs a
distinct client IP per session (see lab/nginx/nginx.conf).

Outputs:
  data/labels/sessions.csv  - one row per session
  data/labels/requests.csv  - one row per HTTP request actually sent

Usage:
    python lab/generator/generate_traffic.py --sessions 300 --seed 1
"""
import argparse
import csv
import random
import string
import time
import urllib.parse
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

import requests

BASE = "http://127.0.0.1:8080"
if BASE != "http://127.0.0.1:8080":
    raise SystemExit("Refusing to run: BASE must stay the lab address.")

ROOT = Path(__file__).resolve().parents[2]
PAYLOAD_DIR = Path(__file__).resolve().parent / "payloads"
SESSIONS_PATH = ROOT / "data" / "labels" / "sessions.csv"
REQUESTS_PATH = ROOT / "data" / "labels" / "requests.csv"

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
}

# static files a real browser would request alongside "/"
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

SEARCH_TERM_RE = PRODUCT_TERMS  # alias for readability below

_ip_counter = [1]


def next_ip():
    """10.1.x.y, x grows past 255 sessions. Never clashes with 10.0.0.x."""
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


SQLI_PAYLOADS = load_payloads("sqli.txt")
XSS_PAYLOADS = load_payloads("xss.txt")
TRAVERSAL_PAYLOADS = load_payloads("traversal.txt")


def vary(payload):
    """Apply a random surface variation: URL-encode, mixed case, extra spaces."""
    choice = random.choice(["plain", "url_encode", "mixed_case", "spaces"])
    if choice == "url_encode":
        return urllib.parse.quote(payload, safe="")
    if choice == "mixed_case":
        return "".join(c.upper() if random.random() < 0.5 else c.lower() for c in payload)
    if choice == "spaces":
        return "  " + payload + "  "
    return payload


def session_http(ip, user_agent=None):
    s = requests.Session()
    s.headers.update({
        "X-Forwarded-For": ip,
        "User-Agent": user_agent or random.choice(BROWSER_UAS),
    })
    return s


def fake_email():
    return "u" + "".join(random.choices(string.digits, k=8)) + "@example-lab.test"


def pause():
    time.sleep(random.uniform(0.2, 1.0))


def now_iso():
    return datetime.now(timezone.utc).isoformat()


# ---------- per-request logging ----------
class RequestLog:
    def __init__(self):
        self.rows = []
        self.status_counts = Counter()

    def record(self, ip, method, path, label, attack_type):
        self.rows.append([now_iso(), ip, method, path, label, attack_type])

    def log_response(self, resp, ip, label, attack_type):
        self.status_counts[resp.status_code] += 1
        path = urllib.parse.urlsplit(resp.request.url).path
        self.record(ip, resp.request.method, path, label, attack_type)

    def write(self, path):
        path.parent.mkdir(parents=True, exist_ok=True)
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["time", "ip", "method", "path", "label", "attack_type"])
            w.writerows(self.rows)


def send(reqlog, s, ip, method, url, label, attack_type, **kwargs):
    """Send one request and log it, regardless of outcome."""
    try:
        resp = s.request(method, url, timeout=5, **kwargs)
        reqlog.log_response(resp, ip, label, attack_type)
        return resp
    except requests.RequestException as e:
        print(f"  request failed: {method} {url} -> {e}")
        reqlog.status_counts["error"] += 1
        return None


# ---------- normal session ----------
def run_normal_session(ip, reqlog):
    s = session_http(ip)
    start = now_iso()
    L = ("normal", "")

    send(reqlog, s, ip, "GET", BASE + "/", *L)
    for f in random.sample(STATIC_FILES, k=random.randint(2, len(STATIC_FILES))):
        send(reqlog, s, ip, "GET", BASE + f, *L)
        pause()

    for term in random.sample(PRODUCT_TERMS, k=random.randint(1, 3)):
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
    send(reqlog, s, ip, "POST", BASE + "/api/Feedbacks/", *L,
         json={"comment": random.choice(FEEDBACK_COMMENTS), "rating": random.randint(3, 5)})

    return start, now_iso()


# ---------- attack sessions ----------
# Each attack has a "surface" of endpoints it tries, so payloads spread
# across URL params and JSON bodies, not just one field.
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
    send(reqlog, s, ip, "GET", BASE + "/rest/products/search", "normal", "",
         params={"q": random.choice(PRODUCT_TERMS)})  # cover request
    pause()
    for payload in random.sample(SQLI_PAYLOADS, k=random.randint(4, 8)):
        send_payload_everywhere(reqlog, s, ip, "sqli", payload)
        pause()
    return start, now_iso()


def run_xss_session(ip, reqlog):
    s = session_http(ip, random.choice(BROWSER_UAS))  # looks like a normal browser
    start = now_iso()
    send(reqlog, s, ip, "GET", BASE + "/rest/products/search", "normal", "",
         params={"q": random.choice(PRODUCT_TERMS)})
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
         params={"q": random.choice(PRODUCT_TERMS)})  # cover request
    return start, now_iso()


def run_bruteforce_session(ip, reqlog):
    s = session_http(ip, ATTACK_UAS["bruteforce"])
    start = now_iso()
    target_email = "admin@juice-sh.op"  # well-known default account, lab only
    for _ in range(random.randint(6, 12)):
        send(reqlog, s, ip, "POST", BASE + "/rest/user/login", "attack", "bruteforce",
             json={"email": target_email, "password": "guess" + str(random.randint(0, 9999))})
        pause()
    if random.random() < 0.5:
        send(reqlog, s, ip, "POST", BASE + "/rest/user/login", "attack", "bruteforce",
             json={"email": target_email, "password": "admin123"})
    return start, now_iso()


ATTACK_RUNNERS = {
    "sqli": run_sqli_session,
    "xss": run_xss_session,
    "traversal": run_traversal_session,
    "bruteforce": run_bruteforce_session,
}


def main():
    ap = argparse.ArgumentParser(description="Generate labelled traffic for the lab.")
    ap.add_argument("--sessions", type=int, default=300)
    ap.add_argument("--seed", type=int, default=0)
    args = ap.parse_args()

    random.seed(args.seed)
    reqlog = RequestLog()
    session_rows = []

    n_attack = int(args.sessions * 0.30)
    n_normal = args.sessions - n_attack
    plan = ["normal"] * n_normal + random.choices(list(ATTACK_RUNNERS.keys()), k=n_attack)
    random.shuffle(plan)

    for i, kind in enumerate(plan, 1):
        ip = next_ip()
        if kind == "normal":
            start, end = run_normal_session(ip, reqlog)
            session_rows.append([ip, "normal", "", start, end])
        else:
            start, end = ATTACK_RUNNERS[kind](ip, reqlog)
            session_rows.append([ip, "attack", kind, start, end])
        if i % 20 == 0:
            print(f"{i}/{len(plan)} sessions done")

    SESSIONS_PATH.parent.mkdir(parents=True, exist_ok=True)
    with open(SESSIONS_PATH, "w", newline="", encoding="utf-8") as f:
        w = csv.writer(f)
        w.writerow(["ip", "label", "attack_type", "start_time", "end_time"])
        w.writerows(session_rows)
    reqlog.write(REQUESTS_PATH)

    print(f"\nDone: {len(session_rows)} sessions -> {SESSIONS_PATH}")
    print(f"      {len(reqlog.rows)} requests -> {REQUESTS_PATH}")
    print("\nStatus code counts:")
    for code, count in sorted(reqlog.status_counts.items(), key=lambda x: str(x[0])):
        print(f"  {code}: {count}")


if __name__ == "__main__":
    main()