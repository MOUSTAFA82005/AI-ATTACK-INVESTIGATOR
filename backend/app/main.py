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

app = FastAPI(title="AI Attack Investigator")
FRONTEND = ROOT / "frontend"
THRESHOLD = 0.5

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
        raise HTTPException(503, "No model found. Run: python -m ml.train_detector")

    rows, skipped, fmt = parse_log_detailed(decode(await file.read()))
    if fmt is None:
        raise HTTPException(400, f"Unknown log format. Supported formats: {', '.join(FORMATS)}")
    if rows:
        X = to_frame([r["method"] for r in rows], [r["path"] for r in rows], [r["body"] for r in rows])
        probs = detector.predict_proba(X)[:, 1]
        for r, p in zip(rows, probs):
            r["attack_prob"] = round(float(p), 3)
            r["label"] = "attack" if p >= THRESHOLD else "normal"

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
