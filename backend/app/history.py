"""Saved investigations and the statistics on the dashboard home page.

Every investigation a user runs is saved for that user only (backend/app/db.py).
summarize() keeps the small numbers the lists and charts need, so the home page never
has to open the full results.
"""
from collections import Counter

from fastapi import APIRouter, Depends, HTTPException

from backend.app.auth import get_auth, require_user

router = APIRouter()

LEVELS = ["critical", "high", "medium", "low", "none"]
STAGES = ["recon", "intrusion", "exploitation", "data_theft"]
ACTIONS = ["block", "rate_limit", "allow"]


def summarize(result, seconds=None):
    """Small summary of one /investigate result (stored next to it)."""
    sessions = result.get("sessions", [])
    timeline = [t for s in sessions for t in s.get("timeline", [])]
    types = Counter(t["attack_type"] for t in timeline if t.get("is_attack") and t.get("attack_type"))
    flagged = [s for s in sessions if s.get("risk_score", 0) > 0]
    top = sorted(flagged, key=lambda s: (-s.get("risk_score", 0), -s.get("requests", 0)))[:5]
    times = sorted(t["timestamp"] for t in timeline if t.get("timestamp"))
    return {
        "mode": result.get("mode"),
        "threshold": result.get("threshold"),
        "format": result.get("format"),
        "parsed": result.get("parsed", 0),
        "skipped": result.get("skipped", 0),
        "sessions_total": result.get("sessions_total", len(sessions)),
        "sessions_flagged": result.get("sessions_flagged", len(flagged)),
        "attack_requests": sum(1 for t in timeline if t.get("is_attack")),
        "payload_requests": sum(1 for t in timeline if t.get("label") == "attack"),
        "levels": {lv: sum(1 for s in sessions if s.get("risk_level") == lv) for lv in LEVELS},
        "actions": {a: sum(1 for s in flagged if s.get("action") == a) for a in ACTIONS},
        "stages": {st: sum(1 for s in sessions if st in (s.get("stage_path") or [])) for st in STAGES},
        "types": dict(types.most_common()),
        "top_sessions": [{"ip": s.get("ip"), "risk_score": s.get("risk_score"), "risk_level": s.get("risk_level"),
                          "action": s.get("action"), "attack_types": (s.get("attack_types") or [])[:3]} for s in top],
        "flagged_visitors": [{"ip": s.get("ip"), "risk_score": s.get("risk_score"), "risk_level": s.get("risk_level"),
                              "action": s.get("action"), "attack_types": (s.get("attack_types") or [])[:3]}
                             for s in sorted(flagged, key=lambda s: -s.get("risk_score", 0))[:500]],
        "log_start": times[0] if times else None,
        "log_end": times[-1] if times else None,
        "seconds": round(seconds, 1) if seconds is not None else None,
    }


def statistics(items):
    """Totals over a user's saved investigations (newest first, as the store returns them)."""
    total = Counter()
    levels, actions, stages, types = Counter(), Counter(), Counter(), Counter()
    attackers = {}
    for it in items:
        for k in ("parsed", "attack_requests", "payload_requests", "sessions_total", "sessions_flagged"):
            total[k] += it.get(k) or 0
        levels.update(it.get("levels", {}))
        actions.update(it.get("actions", {}))
        stages.update(it.get("stages", {}))
        types.update(it.get("types", {}))
        for s in it.get("top_sessions", []):
            ip = s.get("ip")
            if not ip:
                continue
            a = attackers.setdefault(ip, {"ip": ip, "risk_score": 0, "risk_level": "none", "seen_in": 0, "actions": Counter()})
            a["seen_in"] += 1
            a["actions"][s.get("action")] += 1
            if (s.get("risk_score") or 0) > a["risk_score"]:
                a["risk_score"], a["risk_level"] = s.get("risk_score") or 0, s.get("risk_level")
    top = sorted(attackers.values(), key=lambda a: (-a["risk_score"], -a["seen_in"]))[:8]
    for a in top:
        a["actions"] = dict(a["actions"])
    return {
        "investigations": len(items),
        "totals": dict(total),
        "levels": {lv: levels.get(lv, 0) for lv in LEVELS},
        "actions": {a: actions.get(a, 0) for a in ACTIONS},
        "stages": {st: stages.get(st, 0) for st in STAGES},
        "types": dict(types.most_common()),
        "top_attackers": top,
        "trend": [{"id": it["id"], "created_at": it["created_at"], "filename": it.get("filename"),
                   "parsed": it.get("parsed", 0), "attack_requests": it.get("attack_requests", 0),
                   "sessions_flagged": it.get("sessions_flagged", 0)} for it in reversed(items[:12])],
        "recent": items[:6],
    }


@router.get("/api/investigations")
def list_investigations(user=Depends(require_user)):
    return {"investigations": get_auth().store.investigations(user["id"])}


@router.get("/api/investigations/{inv_id}")
def get_investigation(inv_id: int, user=Depends(require_user)):
    result = get_auth().store.investigation(user["id"], inv_id)
    if result is None:
        raise HTTPException(404, "No such investigation.")
    return result


@router.delete("/api/investigations/{inv_id}", status_code=204)
def delete_investigation(inv_id: int, user=Depends(require_user)):
    if not get_auth().store.delete_investigation(user["id"], inv_id):
        raise HTTPException(404, "No such investigation.")


@router.get("/api/stats")
def stats(user=Depends(require_user)):
    return statistics(get_auth().store.investigations(user["id"]))
