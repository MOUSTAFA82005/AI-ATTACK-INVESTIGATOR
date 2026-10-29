"""
defense.py - what to do about each attacker: the fix, the action, and a WAF rule.

1) Fix (k-NN over the knowledge base, ml/knowledge_base.py):
   for every attack step in a session (sqli, scan, bruteforce, ...), the evidence of
   that step is written as words: the step name, the pages and fields it touched,
   the words inside its payloads, and what the server answered (401, 404, slow,
   many accounts, ...). Each knowledge-base entry is a point (TF-IDF of its signs);
   the nearest entries (cosine) are the weakness and its OWASP fix. The family is
   the one the detector / session layer found; k-NN picks the weakness inside it.
2) Action (Decision Tree): block the IP, rate-limit it, or allow it, from numbers
   that describe the session (risk, failed logins, IDs, probes, payload requests,
   stage). The tree is trained on development runs where the true kind of every
   session is known (python -m ml.train_defense), and is printed as if/else rules
   with export_text, so a person can read and check every block rule.
3) WAF rules: ModSecurity and Nginx lines built from the evidence (the IP, the
   page, the field), so the site owner can apply them right away.

See notebooks/12_defense.ipynb.
"""
import json
import re
from collections import Counter
from urllib.parse import unquote_plus

import joblib
import pandas as pd
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.neighbors import NearestNeighbors

from ml.detector import ROOT
from ml.knowledge_base import KNOWLEDGE_BASE
from ml.sessions import field_names, is_login_attempt
from ml.stage import STAGES

BLOCK_RULES_PATH = ROOT / "models" / "block_rules.joblib"
PAYLOAD_STEPS = ["sqli", "xss", "traversal", "cmdi"]
_BEHAVIOUR_STEP = {"scan": "scan", "enumeration": "enum", "bruteforce": "bruteforce"}
_WORD = re.compile(r"[a-z][a-z0-9_]+")
_USER_FIELD = re.compile(r"^(user(name)?|email|login|uname|account)$", re.I)
SLOW_GAP_SECONDS = 5          # median gap between login attempts above this = spread out (slow)
MANY_ACCOUNTS = 4             # login attempts on at least this many user names = spraying (dev runs:
                              # one-account guessing shows 1-3 names, because DVWA adds its own login)


# ------------------------------------------------------------------ evidence of one step
def step_rows(req):
    """{session: {step: rows}} for every flagged request, step as in ml/next_step.py."""
    flagged = req[(req["pred"] == 1) | (req["session_attack"] == 1)]
    step = [t if p == 1 else _BEHAVIOUR_STEP.get(b, "")
            for p, b, t in zip(flagged["pred"], flagged["behaviour"], flagged["type_pred"])]
    flagged = flagged.assign(_step=step)
    flagged = flagged[flagged["_step"] != ""]
    return {s: {k: r for k, r in g.groupby("_step")} for s, g in flagged.groupby("session")}


def _values(path, body):
    """The decoded text a client sent: query string and body."""
    query = str(path or "").partition("?")[2]
    return unquote_plus(query) + " " + unquote_plus(str(body or ""))


def _users(rows):
    """User names tried in login attempts (from query or body fields)."""
    users = set()
    for p, b in zip(rows["path"], rows["body"]):
        text = str(p or "").partition("?")[2] + "&" + str(b or "")
        try:
            obj = json.loads(b) if str(b or "").strip().startswith("{") else {}
        except ValueError:
            obj = {}
        pairs = list(obj.items()) if isinstance(obj, dict) else []
        pairs += [kv.split("=", 1) for kv in text.split("&") if "=" in kv]
        users |= {str(v) for k, v in pairs if _USER_FIELD.match(str(k))}
    return users


def evidence_text(step, rows, with_step=True):
    """The evidence of one attack step as words, for the k-NN."""
    words = [step] if with_step else []
    for path in rows["path"]:
        words += _WORD.findall(str(path).split("?", 1)[0].lower())           # page words
    for p, b in zip(rows["path"], rows["body"]):
        words += [n.lower() for n in field_names(p, b)]                     # field names
        words += _WORD.findall(_values(p, b).lower())                       # payload words
        words += _WORD.findall(str(p).lower().replace("%", " "))            # raw (still encoded)
    status = pd.to_numeric(rows["status"], errors="coerce")
    if (status.isin([401, 403])).any():
        words += ["failed", "401"]
    if (status == 404).mean() > 0.5:
        words += ["many", "not", "found", "404"]
    if (status >= 500).any():
        words += ["server", "error", "500"]
    logins = rows[[is_login_attempt(m, p, b) for m, p, b in zip(rows["method"], rows["path"], rows["body"])]]
    if len(logins):
        words += ["login", "password", "attempts"]
        words += ["many", "accounts", "different", "users"] if len(_users(logins)) >= MANY_ACCOUNTS \
            else ["one", "account", "same", "user"]
        gaps = pd.to_datetime(logins["timestamp"], utc=True, errors="coerce").diff().dt.total_seconds()
        if gaps.median() >= SLOW_GAP_SECONDS:
            words += ["slow", "spread", "over", "time"]
    return " ".join(words)


# ------------------------------------------------------------------ 1) fix: k-NN
class FixFinder:
    """k-NN over the knowledge base: the nearest entries to a step's evidence."""

    def __init__(self, kb=KNOWLEDGE_BASE):
        self.kb = kb
        self.vectorizer = TfidfVectorizer(token_pattern=r"[a-z0-9_]+", binary=True)
        points = self.vectorizer.fit_transform([e["title"].lower() + " " + e["signs"] for e in kb])
        self.knn = NearestNeighbors(metric="cosine").fit(points)

    def nearest(self, text, k=2, family=None):
        """
        [(entry, similarity), ...], most similar first. With `family` (the step the detector
        or the session layer found), only that family's entries are candidates: the k-NN then
        picks WHICH weakness of the family the evidence looks like (e.g. blind SQL injection vs
        SQL injection in the login form). Ties keep the knowledge-base order, so with no
        matching word the family's general entry comes first.
        """
        q = self.vectorizer.transform([text])
        dist, idx = self.knn.kneighbors(q, n_neighbors=len(self.kb))
        order = sorted(zip(dist[0], idx[0]), key=lambda t: (round(t[0], 9), t[1]))
        out = [(self.kb[i], round(1 - float(d), 3)) for d, i in order
               if family is None or self.kb[i]["family"] == family]
        if family is None:
            out = [(e, s) for e, s in out if s > 0]
        return out[:k]


# ------------------------------------------------------------------ 2) action: Decision Tree
# Counts only, no shares of the session: how many requests a normal visit has differs per
# site (DVWA needs a login and a settings page first), so a share learned on one site
# misleads on another. Checked on the dev runs: with attack_share the Juice-Shop-trained
# tree under-blocked 61 of 129 DVWA attackers. The number of login attempts is left out
# for the same reason: on DVWA every visitor logs in first, so a DVWA-trained tree learned
# "no login = not an attacker" (63 of 178 Juice Shop attackers under-blocked).
FEATURES = ["risk_score", "attack_requests", "payload_types", "failed_logins",
            "max_ids_one_resource", "probes", "not_found", "server_errors", "stage_rank"]


def session_features(sessions, req):
    """One row of numbers per session, the input of the block-rule tree."""
    s = sessions.set_index("session")
    types = req[req["pred"] == 1].groupby("session")["type_pred"].nunique()
    x = pd.DataFrame(index=s.index)
    for c in ["risk_score", "attack_requests", "failed_logins",
              "max_ids_one_resource", "probes", "not_found", "server_errors"]:
        x[c] = pd.to_numeric(s[c], errors="coerce").fillna(0)
    rank = {st: i + 1 for i, st in enumerate(STAGES)}
    x["stage_rank"] = s["stage"].map(rank).fillna(0) if "stage" in s else 0
    x["payload_types"] = types.reindex(s.index).fillna(0)
    return x[FEATURES]


def load_block_rules(path=BLOCK_RULES_PATH):
    return joblib.load(path) if path.exists() else None


# ------------------------------------------------------------------ 3) WAF rules
_CRS = {"sqli": "942 (SQL injection)", "xss": "941 (XSS)", "traversal": "930 (local file inclusion)",
        "cmdi": "932 (remote command execution)", "scan": "913 (scanner detection)"}
# Command injection: a shell separator followed by a command name (a separator alone also
# appears in normal text, e.g. "Great value; $5"). Checked on the dev runs in notebook 12.
_CMDI = (r'@rx (?i)(?:[;|`\n]|&&|&\s|\$\()\s*'
         r'(?:cat|ls|id|whoami|uname|ifconfig|ipconfig|netstat|ping|sleep|wget|curl|nc|bash|sh|echo|type|dir)\b')
_OPERATOR = {"sqli": "@detectSQLi", "xss": "@detectXSS", "cmdi": _CMDI}
# Attackers encode twice and hide words in /**/ comments; decode and strip before matching.
_DECODE = "t:none,t:urlDecodeUni,t:urlDecodeUni,t:removeComments"
# Path traversal: two dots (also percent-encoded, once or many times) then a slash or backslash
# (also encoded): ../  ..%2F  ..%252F  %2e%2e%2f ...
_TRAVERSAL = r'@rx (?i)(?:\.|%(?:25)*2e){2}(?:/|\\|%(?:25)*(?:2f|5c))'


def waf_rules(ip, action, steps, rule_id=1000001):
    """
    ModSecurity / Nginx lines for one session. steps: {step: rows}. Lines starting with '#'
    are Nginx settings or advice; the SecRule lines are ModSecurity rules with ids from
    rule_id upwards (add_defense gives every session its own range of 10).
    """
    rules = []
    if action == "block":
        rules.append(f'SecRule REMOTE_ADDR "@ipMatch {ip}" "id:{rule_id},phase:1,deny,status:403,'
                     f'log,msg:\'AI Attack Investigator: block attacker {ip}\'"')
        rules.append(f"# nginx: deny {ip};")
        rule_id += 1
    for step, rows in steps.items():
        page = Counter(str(p).split("?", 1)[0] for p in rows["path"]).most_common(1)[0][0]
        if step == "traversal":                 # the attack is often inside the path itself
            rules.append(f'SecRule REQUEST_URI|ARGS "{_TRAVERSAL}" "id:{rule_id},phase:2,deny,status:403,'
                         f'msg:\'path traversal\'"')
            rules.append(f"# also enable OWASP CRS rule group {_CRS[step]}")
            rule_id += 1
        elif step in _OPERATOR:
            fields = Counter(n for p, b in zip(rows["path"], rows["body"]) for n in field_names(p, b))
            target = "|".join(f"ARGS:{n}" for n, _ in fields.most_common(3)) or "ARGS"
            rules.append(f'SecRule REQUEST_FILENAME "@streq {page}" "id:{rule_id},phase:2,deny,status:403,'
                         f'chain,msg:\'{step} on {page}\'"\n    SecRule {target} "{_OPERATOR[step]}" "{_DECODE}"')
            rules.append(f"# also enable OWASP CRS rule group {_CRS[step]}")
            rule_id += 1
        elif step == "bruteforce":
            rules.append("# nginx: limit_req_zone $binary_remote_addr zone=login:10m rate=5r/m;\n"
                         f"# nginx: location = {page} {{ limit_req zone=login burst=3 nodelay; }}")
        elif step == "enum":
            rules.append("# nginx: limit_req_zone $binary_remote_addr zone=objects:10m rate=30r/m;\n"
                         f"# nginx: location ^~ {page.rsplit('/', 1)[0] or page} "
                         "{ limit_req zone=objects burst=10; }")
        elif step == "scan":
            rules.append(r'# nginx: location ~ /\.(?!well-known) { deny all; }  # hidden files (.git, .env)')
            rules.append(r"# nginx: location ~* \.(bak|old|swp|orig|sql)$ { deny all; }  # backups")
            rules.append(f"# also enable OWASP CRS rule group {_CRS['scan']}")
    return rules


# ------------------------------------------------------------------ all together
def add_defense(req, sessions, finder=None, tree=None, k=2):
    """
    Per session: `action` (block / rate_limit / allow), `fixes` (per step: nearest knowledge-base entries and their fixes) and
    `waf_rules`. Sessions with no attack step get action "allow" and empty lists.
    """
    finder = finder or FixFinder()
    steps = step_rows(req)
    sessions = sessions.copy()
    x = session_features(sessions, req)
    if tree is not None:
        actions = pd.Series(tree.predict(x), index=x.index)
    else:                                    # no trained tree: fall back to the risk level
        level = sessions.set_index("session")["risk_level"]
        actions = level.map({"critical": "block", "high": "block", "medium": "rate_limit"}).fillna("allow")
    out_action, out_fixes, out_rules = [], [], []
    for n, (sid, ip) in enumerate(zip(sessions["session"], sessions["ip"])):
        st = steps.get(sid, {})
        action = actions.get(sid, "allow") if st else "allow"
        fixes = []
        for step, rows in st.items():
            near = finder.nearest(evidence_text(step, rows), k, family=step)
            fixes.append({"step": step, "matches": [
                {"id": e["id"], "title": e["title"], "owasp": e["owasp"], "cwe": e["cwe"],
                 "source": e["source"], "similarity": sim, "fix": e["fix"]} for e, sim in near]})
        out_action.append(action)
        out_fixes.append(fixes)
        out_rules.append(waf_rules(ip, action, st, rule_id=1000001 + 10 * n) if st else [])
    sessions["action"] = out_action
    sessions["fixes"] = out_fixes
    sessions["waf_rules"] = out_rules
    return sessions
