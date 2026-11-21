"""FastAPI backend for the AI Attack Investigator."""
import os
import re
import sys
import threading
import time
from collections import Counter
from pathlib import Path
from urllib.parse import urlsplit

import joblib
import numpy as np
import pandas as pd
from fastapi import Depends, FastAPI, File, HTTPException, Query, Request, UploadFile
from fastapi.concurrency import run_in_threadpool
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.exception_handlers import http_exception_handler
from starlette.exceptions import HTTPException as StarletteHTTPException

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

# Settings kept on this machine only (e-mail, admin bootstrap): config/mail.env, never committed.
from backend.app.mailer import load_settings  # noqa: E402
_loaded = load_settings()
if _loaded:
    print(f"[settings] read {', '.join(sorted(_loaded))} from config/mail.env", file=sys.stderr, flush=True)

from backend.app.log_parser import FORMATS, decode, parse_log_detailed  # noqa: E402
from ml.detector import MODES, MODEL_PATH, attack_proba, served_files, to_frame  # noqa: E402
from ml.sessions import analyze_sessions  # noqa: E402
from ml.context_model import load_context_model  # noqa: E402
from ml.attack_type import attack_types, load_type_model  # noqa: E402
from ml.stage import add_stages  # noqa: E402
from ml.next_step import NextStepModel, add_next_steps  # noqa: E402
from ml.defense import FixFinder, add_defense, load_block_rules  # noqa: E402
from ml.outliers import unusual_requests  # noqa: E402
from ml.explain import reasons  # noqa: E402
from ml.probes import PROBE_REASON, probe_rows  # noqa: E402
from backend.app.privacy import mask_path, mask_secrets  # noqa: E402
from backend.app.auth import bootstrap_from_env, get_auth, is_https, require_user  # noqa: E402
from backend.app import accounts, history  # noqa: E402

# The API description pages (/docs, /redoc, /openapi.json) are off: they map every endpoint
# for a stranger. Set AAI_API_DOCS=1 on your own laptop to see them.
_DOCS = os.environ.get("AAI_API_DOCS") == "1"
app = FastAPI(title="TALON INVESTIGATOR", docs_url="/docs" if _DOCS else None,
              redoc_url="/redoc" if _DOCS else None, openapi_url="/openapi.json" if _DOCS else None)
FRONTEND = ROOT / "frontend"
MAX_UPLOAD_MB = 50
MAX_UPLOAD_BYTES = MAX_UPLOAD_MB * 1024 * 1024
MAX_FILENAME = 120                 # characters of the uploaded file's name that are kept
MAX_JOBS = 2                       # log analyses that may run at the same time (they use the CPU) ...
MAX_SAVED = 500                    # ... and saved investigations per account

# Loaded once at startup. Train it first with: python -m ml.train_detector
detector = joblib.load(MODEL_PATH) if MODEL_PATH.exists() else None
type_model = load_type_model()
# The learned behaviour model (brute force / enumeration / scan). It is the "sessions" part of the
# system that every results table measured ("model + sessions", eval/final_test.py); without the
# file the hand-written session rules (the baseline) decide.
_CONTEXT_PATH = ROOT / "models" / "context.joblib"
context_model = load_context_model(_CONTEXT_PATH) if _CONTEXT_PATH.exists() else None
# Both are None when the model file is missing; the endpoints still work without them.
next_step_model = NextStepModel.load()      # models/next_step.json
block_tree = load_block_rules()             # models/block_rules.joblib
fix_finder = FixFinder()                    # k-NN over the knowledge base, built once


if os.environ.get("AAI_ADMIN_EMAIL"):         # hosted demo only; on a laptop use: python -m backend.app.auth create
    bootstrap_from_env(get_auth().store)


# ------------------------------------------------------------------ pages and security headers
# The pages hold no data: they ask the API, which checks the login on every call.
PAGES = {"/": "index.html", "/login": "login.html", "/signup": "login.html", "/app": "app.html"}
for _path, _file in PAGES.items():
    app.add_api_route(_path, (lambda f=_file: FileResponse(FRONTEND / f)), methods=["GET"], include_in_schema=False)
app.mount("/static", StaticFiles(directory=FRONTEND / "static"), name="static")


@app.exception_handler(StarletteHTTPException)
async def not_found_page(request: Request, exc: StarletteHTTPException):
    """A browser that opens a page that does not exist gets the 404 page; API callers keep the JSON error."""
    wants_page = (exc.status_code == 404 and request.method == "GET"
                  and not request.url.path.startswith("/static/")
                  and "text/html" in request.headers.get("accept", ""))
    if wants_page:
        return FileResponse(FRONTEND / "404.html", status_code=404)
    return await http_exception_handler(request, exc)
app.include_router(accounts.router)
app.include_router(history.router)

SECURITY_HEADERS = {
    # Only this server's own files: no inline scripts, no other sites, no framing.
    "Content-Security-Policy": ("default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; "
                                "font-src 'self'; connect-src 'self'; object-src 'none'; base-uri 'none'; "
                                "form-action 'self'; frame-ancestors 'none'"),
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
}
HSTS = "max-age=31536000"           # sent only over HTTPS: the browser then refuses plain HTTP for a year
# A request that changes something is refused when the browser says it came from another site.
SAME_SITE = {"same-origin", "none"}   # "none" = typed in the address bar or a bookmark


@app.middleware("http")
async def security(request: Request, call_next):
    # A request that changes something must come from this site's own pages (the cookie is
    # SameSite=Strict already; this also stops other local pages from posting to us).
    if request.method not in ("GET", "HEAD", "OPTIONS"):
        origin = request.headers.get("origin")
        fetch_site = request.headers.get("sec-fetch-site")
        if ((origin is not None and urlsplit(origin).netloc != request.url.netloc)
                or (fetch_site is not None and fetch_site not in SAME_SITE)):
            return JSONResponse({"detail": "Cross-site request refused."}, status_code=403)
    response = await call_next(request)
    for k, v in SECURITY_HEADERS.items():
        response.headers.setdefault(k, v)
    if is_https(request):
        response.headers.setdefault("Strict-Transport-Security", HSTS)
    if request.url.path.startswith(("/api/", "/me", "/investigate", "/analyze", "/login", "/signup")):
        response.headers["Cache-Control"] = "no-store"      # results never stay in the browser cache
    return response


@app.get("/health")
def health():
    return {"status": "ok", "model_loaded": detector is not None}


def _threshold(mode):
    if mode not in MODES:
        raise HTTPException(400, f"Unknown mode '{mode}'. Use one of: {', '.join(MODES)}.")
    return MODES[mode]


def _filename(name):
    """The uploaded file's name as shown and saved: no folders, no control characters, not too long."""
    name = re.split(r"[\\/]", name or "")[-1]
    name = re.sub(r"[\x00-\x1f\x7f]", "", name).strip()
    return name[:MAX_FILENAME] or "log"


class _Jobs:
    """At most MAX_JOBS analyses at once, and one per account, so one person (or a stolen
    login) cannot keep the server busy for everybody else."""

    def __init__(self):
        self._lock = threading.Lock()
        self._running = set()

    def start(self, user_id):
        with self._lock:
            if user_id in self._running:
                raise HTTPException(429, "Your previous log is still being analysed. Wait for it to finish.")
            if len(self._running) >= MAX_JOBS:
                raise HTTPException(503, "The server is busy with other logs. Try again in a minute.",
                                    headers={"Retry-After": "30"})
            self._running.add(user_id)

    def end(self, user_id):
        with self._lock:
            self._running.discard(user_id)


jobs = _Jobs()


async def _run(user, work, *args):
    """Run CPU-heavy work in a worker thread (the server keeps answering other requests)."""
    jobs.start(user["id"])
    try:
        return await run_in_threadpool(work, *args)
    finally:
        jobs.end(user["id"])


async def _read_upload(file: UploadFile):
    """Checks the model and the file size; returns the raw bytes."""
    if detector is None:
        raise HTTPException(
            503,
            "The detection model is not loaded. Put models/detector.joblib in place "
            "(python -m ml.train_detector, or get it from Safi) and restart the server.",
        )

    # Read at most MAX_UPLOAD_BYTES + 1, so a huge file is never fully loaded into memory.
    raw = await file.read(MAX_UPLOAD_BYTES + 1)
    if len(raw) > MAX_UPLOAD_BYTES:
        raise HTTPException(
            413, f"File is larger than {MAX_UPLOAD_MB} MB. Upload a smaller log or split it into parts."
        )
    if not raw.strip():
        raise HTTPException(400, "The file is empty. Upload an access log that contains at least one line.")
    return raw


def _predict(raw, threshold=MODES["sensitive"]):
    """Shared by /analyze and /investigate: parses the log and runs the model.

    Returns (rows, skipped, fmt). The rows are NOT masked yet: each endpoint masks
    what it returns, after it has finished its own analysis.

    Every row gets: attack_prob, label, unusual (review mark) and reasons (why the
    detector called it an attack). unusual and reasons never change the label.
    """
    rows, skipped, fmt = parse_log_detailed(decode(raw))
    if fmt is None:
        raise HTTPException(
            400,
            "Unknown log format. Upload a web server access log in one of these formats: "
            f"{', '.join(FORMATS)}.",
        )
    if rows:
        # Everything below works on the ORIGINAL (unmasked) text.
        X = to_frame([r["method"] for r in rows], [r["path"] for r in rows], [r["body"] for r in rows])
        probs = attack_proba(detector, X, [r["method"] for r in rows], [r["path"] for r in rows],
                             [r["body"] for r in rows])
        pred = (probs >= threshold).astype(int)

        # A real file that the site served to a visitor is not a probe (same as eval/final_test.py).
        frame = pd.DataFrame({"ip": [r["ip"] for r in rows],
                              "path": [r["path"] for r in rows],
                              "status": [r["status"] for r in rows]})
        served = np.asarray(served_files(frame, X, pred), dtype=bool)
        pred[served] = 0
        # Known scanner targets the site does not have (ml/probes.py): no payload, so the session layer
        # marks them as a scan (they never become payload attacks).
        probe = probe_rows(frame["path"], frame["status"], [r["method"] for r in rows])

        unusual = np.asarray(unusual_requests(X), dtype=bool) | served   # one call per log
        why = reasons(detector, X)                                        # one call per log

        for r, p, is_attack, odd, sentences, was_served, is_probe in zip(rows, probs, pred, unusual, why, served, probe):
            r["attack_prob"] = round(float(p), 3)
            r["_proba"] = float(p)              # unrounded, for the session and defence layers (not returned)
            r["label"] = "attack" if is_attack else "normal"
            r["unusual"] = bool(odd)
            r["known_probe"] = bool(is_probe)
            r["reasons"] = [] if was_served else list(sentences)   # a request called normal has no reasons
            if is_probe:
                r["reasons"].append(PROBE_REASON)
    return rows, skipped, fmt


@app.post("/analyze")
async def analyze(file: UploadFile = File(...), mode: str = Query("sensitive"), user=Depends(require_user)):
    """Read an access log and mark each request as normal or attack.

    mode: "sensitive" (default, threshold 0.7) or "quiet" (0.8: fewer false alarms, misses more)."""
    threshold = _threshold(mode)
    raw = await _read_upload(file)
    rows, skipped, fmt = await _run(user, _predict, raw, threshold)

    # Mask AFTER the model has seen the original text, so detection does not change.
    for r in rows:
        r.pop("_proba", None)
        r["body"] = mask_secrets(r["body"])
        r["path"] = mask_path(r["path"])

    attacks = sum(r["label"] == "attack" for r in rows)
    return {
        "filename": _filename(file.filename),
        "format": fmt,
        "mode": mode,
        "threshold": threshold,
        "has_body": any(r["body"] for r in rows),
        "lines": len(rows) + skipped,
        "parsed": len(rows),
        "skipped": skipped,
        "attacks": attacks,
        "normal": len(rows) - attacks,
        "results": rows,
    }


def _clean(value):
    """Make one value safe for JSON: Timestamp -> ISO text, numpy -> Python, NaN/NaT -> None."""
    if isinstance(value, (list, tuple, np.ndarray)):
        return [_clean(v) for v in value]
    if isinstance(value, dict):
        return {k: _clean(v) for k, v in value.items()}
    if value is None or value is pd.NaT:
        return None
    if isinstance(value, pd.Timestamp):
        return value.isoformat()
    if isinstance(value, np.bool_):
        return bool(value)
    if isinstance(value, np.integer):
        return int(value)
    if isinstance(value, (float, np.floating)):
        return None if value != value else float(value)   # NaN is the only value not equal to itself
    return value


# "row" = the position of the request in `rows`; it lets us find the unusual mark and the
# reasons of a request again after analyze_sessions has re-ordered everything.
# user_agent: a visitor is IP + user agent (v10, ml/sessions.py visitor_key) and crawlers are told apart
# by it; without this column every visitor behind one IP was merged into one session.
_REQUEST_COLUMNS = ["ip", "timestamp", "method", "path", "status", "size", "body", "user_agent",
                    "attack_prob", "_proba", "label", "known_probe", "row"]

@app.post("/investigate")
async def investigate(file: UploadFile = File(...), mode: str = Query("sensitive"), save: bool = Query(True),
                      user=Depends(require_user)):
    """Group the requests of a log into sessions (one IP, gaps under 30 min) and score each one.

    mode: "sensitive" (default, threshold 0.7) or "quiet" (0.8), as in /analyze."""
    threshold = _threshold(mode)
    store = get_auth().store
    if save and store.count_investigations(user["id"]) >= MAX_SAVED:
        raise HTTPException(409, f"You have {MAX_SAVED} saved investigations. Delete some old ones first.")
    started = time.monotonic()
    raw = await _read_upload(file)
    result = await _run(user, _investigate, raw, threshold, _filename(file.filename), mode)
    return _finish(result, user, save, started)


def _investigate(raw, threshold, filename, mode):
    """The work behind /investigate (runs in a worker thread)."""
    rows, skipped, fmt = _predict(raw, threshold)
    result = {
        "filename": filename,
        "format": fmt,
        "mode": mode,
        "threshold": threshold,
        "has_body": any(r["body"] for r in rows),
        "parsed": len(rows),
        "skipped": skipped,
        "sessions_total": 0,
        "sessions_flagged": 0,
        "sessions": [],
    }
    if not rows:
        return result

    # Input for analyze_sessions: one row per request, pred = the model's decision.
    df = pd.DataFrame(rows).assign(row=range(len(rows)))[_REQUEST_COLUMNS]
    df["pred"] = (df["label"] == "attack").astype(int)
    df["proba"] = df.pop("_proba")                       # input of the behaviour model, as in eval/final_test.py
    df["attack_prob"] = df["proba"]                        # defence rules use the unrounded value too
    sessions, reqs = analyze_sessions(df, context_model)

    # Requests in time order. Rows without a readable time go last; ties keep file order.
    reqs = reqs.assign(_t=pd.to_datetime(reqs["timestamp"], utc=True, errors="coerce"))
    reqs = reqs.sort_values("_t", kind="stable").reset_index(drop=True)

    # Attack type for the rows the model called attacks: ONE call, on the ORIGINAL
    # (unmasked) method/path/body of all of them. Masking happens later.
    reqs["attack_type"] = None
    is_attack = reqs["label"] == "attack"
    if is_attack.any():
        sub = reqs[is_attack]
        reqs.loc[is_attack, "attack_type"] = list(
            attack_types(sub["method"].tolist(), sub["path"].tolist(), sub["body"].tolist(), type_model)
        )
    # The next-step and defence modules want "" (not None) for requests that are not payload attacks.
    reqs["type_pred"] = [t if isinstance(t, str) else "" for t in reqs["attack_type"]]

    # Stage first: defence needs the stage (and a critical session is always blocked).
    reqs, sessions = add_stages(reqs, sessions)
    sessions = add_next_steps(reqs, sessions, next_step_model)           # empty lists if no model
    sessions = add_defense(reqs, sessions, fix_finder, block_tree)       # risk-level fallback if no tree

    timelines = {sid: group for sid, group in reqs.groupby("session")}

    out = []
    for s in sessions.to_dict("records"):
        s = {k: _clean(v) for k, v in s.items()}
        behaviours = s["behaviours"]
        timeline = []
        group = timelines.get(s["session"])
        if group is not None:
            for r in group.to_dict("records"):
                r = {k: _clean(v) for k, v in r.items()}
                source = rows[r["row"]]                    # the row as parsed (has unusual + reasons)
                if r["label"] == "attack":
                    attack_type = r["attack_type"]
                elif r["session_attack"] == 1 and behaviours:
                    attack_type = r["behaviour"]         # part of a behaviour, not a single-request attack
                else:
                    attack_type = None
                timeline.append({
                    "timestamp": r["timestamp"],
                    "method": r["method"],
                    "path": mask_path(r["path"]),          # mask AFTER prediction and analysis
                    "status": r["status"],
                    "body": mask_secrets(r["body"]),
                    "attack_prob": round(r["attack_prob"], 3),
                    "label": r["label"],
                    "session_attack": r["session_attack"],
                    "is_attack": r["label"] == "attack" or r["session_attack"] == 1,
                    "attack_type": attack_type,
                    "stage": r["stage"],
                    "unusual": source["unusual"],
                    "reasons": list(source["reasons"]),
                })
        s["timeline"] = timeline
        # Distinct types in this session, most frequent first.
        counts = Counter(t["attack_type"] for t in timeline if t["attack_type"])
        s["attack_types"] = [name for name, _ in counts.most_common()]
        s["unusual_requests"] = sum(t["unusual"] for t in timeline)   # a review mark, not a risk input
        out.append(s)

    result["sessions_total"] = len(out)
    result["sessions_flagged"] = sum(s["risk_score"] > 0 for s in out)
    result["sessions"] = out
    return result


def _finish(result, user, save, started):
    """Save the (already masked) result for this user, so it appears in History and on Home."""
    seconds = time.monotonic() - started
    result["seconds"] = round(seconds, 1)
    if save:
        result["id"] = get_auth().store.save_investigation(
            user["id"], result["filename"], history.summarize(result, seconds), result)
    return result