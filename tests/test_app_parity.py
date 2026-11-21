"""The app (/investigate) must give the same answer as eval/final_test.py, the system every results
table measured. Found 2026-11-21: the app ran the hand-written session rules (no context model),
dropped the user agent (visitor = IP + user agent since v10) and misaligned the stage model's
context features. This test fails if the two ever drift apart again."""
from pathlib import Path

import pandas as pd
import pytest

ROOT = Path(__file__).resolve().parents[1]
LOG = ROOT / "data" / "raw" / "webgoat_generated_run7.log"
MODELS = ["detector.joblib", "context.joblib", "attack_type.joblib", "stage.joblib", "block_rules.joblib"]


@pytest.mark.skipif(not LOG.exists() or not all((ROOT / "models" / m).exists() for m in MODELS),
                    reason="needs the lab log and the trained models")
def test_app_matches_measured_pipeline():
    import eval.final_test as ft
    from backend.app import main
    from backend.app.log_parser import decode, parse_log
    raw = b"".join(LOG.read_bytes().splitlines(keepends=True)[:2000])
    rows, _ = parse_log(decode(raw))
    df = pd.DataFrame(rows).assign(label="normal", attack_type="")
    req, ses = ft.investigate(*ft._pipeline(df))
    want = ses.set_index("session")[["risk_score", "risk_level", "action", "stage"]]
    flagged = req.groupby("session").apply(lambda x: int(((x["pred"] == 1) | (x["session_attack"] == 1)).sum()))
    app = main._investigate(raw, main.MODES["sensitive"], "x", "sensitive")
    got = pd.DataFrame([{k: s[k] for k in ["session", "risk_score", "risk_level", "action", "stage"]}
                        | {"flagged": sum(t["is_attack"] for t in s["timeline"])}
                        for s in app["sessions"]]).set_index("session")
    assert set(got.index) == set(want.index)
    want = want.assign(flagged=flagged).reindex(got.index)
    for c in got.columns:
        assert (got[c].astype(str) == want[c].astype(str)).all(), c
