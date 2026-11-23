"""Trusted addresses: IPs or networks an account says are its own (an office behind one NAT address,
its reverse proxy, a monitoring service).

Many people behind one address can look like one busy visitor, so the session layer may flag them
(README, Limitations). Detection is NOT changed: the visitor keeps its risk level, reasons and stage,
exactly as the measured system scored it. Only the suggested action changes: a trusted visitor is never
blocked or rate-limited, and the page says why. The model's own action is kept in `model_action`.

This runs after the analysis (backend/app/main.py, /investigate), so the sealed-test path
(main._investigate) is unchanged.
"""
import ipaddress

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field

from backend.app.auth import get_auth, require_user

router = APIRouter()

MAX_TRUSTED = 200          # per account
MAX_NOTE = 80


def normal_address(text):
    """'10.0.0.7' -> '10.0.0.7', '10.0.0.0/24' -> '10.0.0.0/24', '10.0.0.9/24' -> '10.0.0.0/24'.
    Raises ValueError for anything that is not an IP or a network, and for networks wider than /8 (v4) or /32 (v6),
    which would trust a large part of the internet."""
    text = (text or "").strip()
    if not text:
        raise ValueError("Type an IP address or a network such as 10.0.0.0/24.")
    try:
        net = ipaddress.ip_network(text, strict=False)
    except ValueError:
        raise ValueError(f"'{text[:60]}' is not an IP address or a network such as 10.0.0.0/24.") from None
    if net.prefixlen < (8 if net.version == 4 else 32):
        raise ValueError("That network is too wide. Use /8 or narrower for IPv4, /32 or narrower for IPv6.")
    if net.num_addresses == 1:
        return str(net.network_address)
    return str(net)


def networks(items):
    """The stored addresses as ip_network objects (bad rows are skipped)."""
    out = []
    for it in items:
        try:
            out.append(ipaddress.ip_network(it["address"], strict=False))
        except (ValueError, KeyError, TypeError):
            continue
    return out


def _matches(ip, nets):
    try:
        addr = ipaddress.ip_address(str(ip).strip().strip("[]"))
    except ValueError:
        return False
    return any(addr.version == n.version and addr in n for n in nets)


def apply_trusted(result, nets):
    """Mark the sessions from trusted addresses and set their action to allow. Returns how many were marked."""
    if not nets:
        return 0
    marked = 0
    for s in result.get("sessions", []):
        if not _matches(s.get("ip", ""), nets):
            continue
        marked += 1
        s["trusted"] = True
        if s.get("action") in ("block", "rate_limit"):
            s["model_action"] = s["action"]
            s["action"] = "allow"
            s["action_reason"] = (f"Trusted address: the model suggested {s['model_action'].replace('_', ' ')}, "
                                  "but this address is on your trusted list, so it is only shown.")
    result["trusted_visitors"] = marked
    return marked


# ------------------------------------------------------------------ API
class TrustedIn(BaseModel):
    address: str = Field(max_length=64)
    note: str = Field("", max_length=MAX_NOTE)


@router.get("/api/trusted")
def list_trusted(user=Depends(require_user)):
    return get_auth().store.trusted(user["id"])


@router.post("/api/trusted", status_code=201)
def add_trusted(body: TrustedIn, user=Depends(require_user)):
    store = get_auth().store
    try:
        address = normal_address(body.address)
    except ValueError as e:
        raise HTTPException(400, str(e)) from None
    if store.count_trusted(user["id"]) >= MAX_TRUSTED:
        raise HTTPException(409, f"You can keep at most {MAX_TRUSTED} trusted addresses.")
    new_id = store.add_trusted(user["id"], address, body.note.strip())
    if new_id is None:
        raise HTTPException(409, f"{address} is already on your trusted list.")
    return {"id": new_id, "address": address, "note": body.note.strip()}


@router.delete("/api/trusted/{item_id}", status_code=204)
def delete_trusted(item_id: int, user=Depends(require_user)):
    if not get_auth().store.delete_trusted(user["id"], item_id):
        raise HTTPException(404, "Not found.")
