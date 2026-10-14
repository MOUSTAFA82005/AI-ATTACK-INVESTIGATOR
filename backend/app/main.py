"""FastAPI backend for the AI Attack Investigator (week 1 skeleton)."""
from pathlib import Path

from fastapi import FastAPI, File, UploadFile
from fastapi.responses import FileResponse

app = FastAPI(title="AI Attack Investigator")
FRONTEND = Path(__file__).resolve().parents[2] / "frontend"


@app.get("/")
def index():
    return FileResponse(FRONTEND / "index.html")


@app.get("/health")
def health():
    return {"status": "ok"}


@app.post("/analyze")
async def analyze(file: UploadFile = File(...)):
    """Receive an access log file. Week 1: count lines only; ML comes later."""
    content = (await file.read()).decode("utf-8", errors="replace")
    lines = [l for l in content.splitlines() if l.strip()]
    return {"filename": file.filename, "lines": len(lines), "results": []}
