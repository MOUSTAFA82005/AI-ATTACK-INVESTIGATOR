"""FastAPI backend for the AI Attack Investigator."""
import sys
from pathlib import Path

import joblib
from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.responses import FileResponse

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from backend.app.log_parser import FORMATS, decode, parse_log_detailed  # noqa: E402
from ml.detector import MODEL_PATH, to_frame  # noqa: E402
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


@app.post("/analyze")
async def analyze(file: UploadFile = File(...)):
    """Read an access log and mark each request as normal or attack."""
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