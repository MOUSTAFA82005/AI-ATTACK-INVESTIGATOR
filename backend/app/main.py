"""FastAPI backend for the AI Attack Investigator."""
import sys
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.responses import FileResponse

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from backend.app.log_parser import FORMATS, decode, parse_log_detailed  # noqa: E402
from ml.detector import MODEL_PATH, to_frame  # noqa: E402
from ml.sessions import analyze_sessions  # noqa: E402
from backend.app.privacy import mask_path, mask_secrets  # noqa: E402

app = FastAPI(title="AI Attack Investigator")
FRONTEND = ROOT / "frontend"
THRESHOLD = 0.5
MAX_UPLOAD_MB = 50
MAX_UPLOAD_BYTES = MAX_UPLOAD_MB * 1024 * 1024

# Loaded once at startup. Train it first with: python -m ml.train_detector
detector = joblib.load(MODEL_PATH) if MODEL_PATH.exists() else None


@app.get("/")
def index():
    return FileResponse(FRONTEND / "index.html")


@app.get("/health")
def health():
    return {"status": "ok", "model_loaded": detector is not None}

async def _read_and_predict(file: UploadFile):
    """Shared by /analyze and /investigate.

    Checks the model, the file size and the format, parses the log and runs the model.
    Returns (rows, skipped, fmt). The rows are NOT masked yet: each endpoint masks
    what it returns, after it has finished its own analysis.
    """
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

    rows, skipped, fmt = parse_log_detailed(decode(raw))
    if fmt is None:
        raise HTTPException(
            400,
            "Unknown log format. Upload a web server access log in one of these formats: "
            f"{', '.join(FORMATS)}.",
        )
    if rows:
        X = to_frame([r["method"] for r in rows], [r["path"] for r in rows], [r["body"] for r in rows])
        probs = detector.predict_proba(X)[:, 1]
        for r, p in zip(rows, probs):
            r["attack_prob"] = round(float(p), 3)
            r["label"] = "attack" if p >= THRESHOLD else "normal"
    return rows, skipped, fmt


@app.post("/analyze")
async def analyze(file: UploadFile = File(...)):
    """Read an access log and mark each request as normal or attack."""
    rows, skipped, fmt = await _read_and_predict(file)

    # Mask AFTER the model has seen the original text, so detection does not change.
    for r in rows:
        r["body"] = mask_secrets(r["body"])
        r["path"] = mask_path(r["path"])

    attacks = sum(r["label"] == "attack" for r in rows)
    return {
        "filename": file.filename,
        "format": fmt,
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


_REQUEST_COLUMNS = ["ip", "timestamp", "method", "path", "status", "body", "attack_prob", "label"]


@app.post("/investigate")
async def investigate(file: UploadFile = File(...)):
    """Group the requests of a log into sessions (one IP, gaps under 30 min) and score each one."""
    rows, skipped, fmt = await _read_and_predict(file)

    result = {
        "filename": file.filename,
        "format": fmt,
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
    df = pd.DataFrame(rows)[_REQUEST_COLUMNS]
    df["pred"] = (df["label"] == "attack").astype(int)
    sessions, reqs = analyze_sessions(df)

    # Requests in time order. Rows without a readable time go last; ties keep file order.
    reqs = reqs.assign(_t=pd.to_datetime(reqs["timestamp"], utc=True, errors="coerce"))
    reqs = reqs.sort_values("_t", kind="stable")
    timelines = {sid: group for sid, group in reqs.groupby("session")}

    out = []
    for s in sessions.to_dict("records"):
        s = {k: _clean(v) for k, v in s.items()}
        timeline = []
        group = timelines.get(s["session"])
        if group is not None:
            for r in group.to_dict("records"):
                r = {k: _clean(v) for k, v in r.items()}
                timeline.append({
                    "timestamp": r["timestamp"],
                    "method": r["method"],
                    "path": mask_path(r["path"]),          # mask AFTER prediction and analysis
                    "status": r["status"],
                    "body": mask_secrets(r["body"]),
                    "attack_prob": r["attack_prob"],
                    "label": r["label"],
                    "session_attack": r["session_attack"],
                    "is_attack": r["label"] == "attack" or r["session_attack"] == 1,
                })
        s["timeline"] = timeline
        out.append(s)

    result["sessions_total"] = len(out)
    result["sessions_flagged"] = sum(s["risk_score"] > 0 for s in out)
    result["sessions"] = out
    return result