"""Distributed campaigns: many addresses that only send probe requests, all with the same browser name.

A botnet that hunts for web shells spreads its requests over many addresses: every address asks once for
one random script (/a.php, /dd.php, /x.php ...) with the same, often very old, user agent. Each visitor alone
looks like a mistyped link, so the per-visitor models rightly leave it alone. Seen together, it is one tool.

This module only REPORTS such groups (result["campaigns"]) and marks their visitors (session["campaign"]).
It never changes a visitor's risk, reasons, stage or action, and it runs after the analysis in /investigate,
so the sealed-test path (main._investigate) is unchanged.
"""
import re
from collections import Counter

import pandas as pd

from backend.app.log_parser import decode, parse_log_detailed
from ml.probes import is_known_name
from ml.sessions import visitor_key

MIN_ADDRESSES = 5        # at least this many different addresses with the same agent ...
MIN_SHARE = 0.8          # ... and at least this share of that agent's visitors only probe (nothing served)
NOT_SERVED = {301, 302, 403, 404, 410, 429}
_SCRIPT = re.compile(r"\.(php\d?|asp|aspx|jsp|jspx|cgi|pl|cfm|action|do)$", re.I)
_CMS = re.compile(r"/(wp-|wordpress|phpcms|phpmyadmin|plus/|dede|uploads/|admin|manager|install|setup|cgi-bin|vendor/)", re.I)


def _suspicious(path):
    bare = str(path or "").split("?", 1)[0].split("#", 1)[0]
    return bool(_SCRIPT.search(bare) or _CMS.search(bare) or is_known_name(bare))


def _probe_only(session):
    """Every request of this visitor asked for a script or admin/CMS path the site did not serve."""
    tl = session.get("timeline") or []
    if not tl or session.get("crawler"):
        return False
    for t in tl:
        try:
            status = int(t.get("status"))
        except (TypeError, ValueError):
            return False
        if status not in NOT_SERVED or not _suspicious(t.get("path")):
            return False
    return True


def _agents(raw):
    """visitor key (as in session ids) -> user agent."""
    rows, _, _ = parse_log_detailed(decode(raw))
    if not rows:
        return {}
    df = pd.DataFrame(rows)
    if "user_agent" not in df:
        return {}
    df["_key"] = visitor_key(df)
    return df.groupby("_key")["user_agent"].first().to_dict()


def find_campaigns(result, raw):
    """Add result["campaigns"] (largest first) and mark the visitors in them. Returns the list."""
    sessions = result.get("sessions") or []
    agents = _agents(raw)
    by_agent = {}
    for s in sessions:
        ua = str(agents.get(str(s.get("session", "")).rsplit("#", 1)[0], "") or "").strip()
        if ua in ("", "-"):
            continue
        by_agent.setdefault(ua, []).append(s)

    found = []
    for ua, group in by_agent.items():
        probes = [s for s in group if _probe_only(s)]
        addresses = sorted({s["ip"] for s in probes})
        if len(addresses) < MIN_ADDRESSES or len(probes) < MIN_SHARE * len(group):
            continue
        paths = Counter(t["path"] for s in probes for t in s["timeline"])
        statuses = Counter(int(t["status"]) for s in probes for t in s["timeline"])
        times = sorted(t["timestamp"] for s in probes for t in s["timeline"] if t.get("timestamp"))
        found.append({
            "user_agent": ua,
            "addresses": addresses,
            "visitors": len(probes),
            "requests": sum(len(s["timeline"]) for s in probes),
            "examples": [p for p, _ in paths.most_common(8)],
            "statuses": {str(k): v for k, v in sorted(statuses.items())},
            "first": times[0] if times else None,
            "last": times[-1] if times else None,
            "_sessions": [s["session"] for s in probes],
        })

    found.sort(key=lambda c: (-len(c["addresses"]), c["user_agent"]))
    marks = {}
    for i, c in enumerate(found, 1):
        c["id"] = i
        for sid in c.pop("_sessions"):
            marks[sid] = i
    for s in sessions:
        if s.get("session") in marks:
            s["campaign"] = marks[s["session"]]
    result["campaigns"] = found
    return found
