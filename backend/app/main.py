"""FastAPI backend for the AI Attack Investigator."""
import sys
from pathlib import Path

import joblib
import numpy as np
import pandas as pd
from collections import Counter
from fastapi import FastAPI, File, HTTPException, UploadFile
from fastapi.responses import FileResponse

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from backend.app.log_parser import FORMATS, decode, parse_log_detailed  # noqa: E402
from ml.detector import MODEL_PATH, served_files, to_frame  # noqa: E402
from ml.sessions import analyze_sessions  # noqa: E402
from ml.attack_type import attack_types, load_type_model  # noqa: E402
from ml.stage import add_stages  # noqa: E402
from ml.next_step import NextStepModel, add_next_steps  # noqa: E402
from ml.defense import FixFinder, add_defense, load_block_rules  # noqa: E402
from ml.outliers import unusual_requests  # noqa: E402
from ml.explain import reasons  # noqa: E402
from backend.app.privacy import mask_path, mask_secrets  # noqa: E402

app = FastAPI(title="AI Attack Investigator")
FRONTEND = ROOT / "frontend"
THRESHOLD = 0.5
MAX_UPLOAD_MB = 50
MAX_UPLOAD_BYTES = MAX_UPLOAD_MB * 1024 * 1024

# Loaded once at startup. Train it first with: python -m ml.train_detector
detector = joblib.load(MODEL_PATH) if MODEL_PATH.exists() else None
type_model = load_type_model()
# Both are None when the model file is missing; the endpoints still work without them.
next_step_model = NextStepModel.load()      # models/next_step.json
block_tree = load_block_rules()             # models/block_rules.joblib
fix_finder = FixFinder()                    # k-NN over the knowledge base, built once


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

    Every row gets: attack_prob, label, unusual (review mark) and reasons (why the
    detector called it an attack). unusual and reasons never change the label.
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
        # Everything below works on the ORIGINAL (unmasked) text.
        X = to_frame([r["method"] for r in rows], [r["path"] for r in rows], [r["body"] for r in rows])
        probs = detector.predict_proba(X)[:, 1]
        pred = (probs >= THRESHOLD).astype(int)

        # A real file that the site served to a visitor is not a probe (same as eval/final_test.py).
        frame = pd.DataFrame({"ip": [r["ip"] for r in rows],
                              "path": [r["path"] for r in rows],
                              "status": [r["status"] for r in rows]})
        served = np.asarray(served_files(frame, X, pred), dtype=bool)
        pred[served] = 0

        unusual = np.asarray(unusual_requests(X), dtype=bool) | served   # one call per log
        why = reasons(detector, X)                                        # one call per log

        for r, p, is_attack, odd, sentences, was_served in zip(rows, probs, pred, unusual, why, served):
            r["attack_prob"] = round(float(p), 3)
            r["label"] = "attack" if is_attack else "normal"
            r["unusual"] = bool(odd)
            r["reasons"] = [] if was_served else list(sentences)   # a request called normal has no reasons
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


# "row" = the position of the request in `rows`; it lets us find the unusual mark and the
# reasons of a request again after analyze_sessions has re-ordered everything.
_REQUEST_COLUMNS = ["ip", "timestamp", "method", "path", "status", "size", "body",
                    "attack_prob", "label", "row"]

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
    df = pd.DataFrame(rows).assign(row=range(len(rows)))[_REQUEST_COLUMNS]
    df["pred"] = (df["label"] == "attack").astype(int)
    sessions, reqs = analyze_sessions(df)

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
                    "attack_prob": r["attack_prob"],
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