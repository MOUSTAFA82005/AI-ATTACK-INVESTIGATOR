"""The learned stage model (ml/stage.py): it only gives a stage to requests the other
models called an attack, and only one of the four stage names."""
import pandas as pd

from ml.stage import STAGES, load_stage_model, request_stages, rule_stages


def requests():
    rows = []
    for i in range(20):
        rows.append({"ip": f"10.0.0.{i}", "timestamp": f"2026-11-02T10:00:{i:02d}+00:00", "method": "GET",
                     "path": "/products", "status": 200, "size": 3000, "body": "", "pred": 0, "behaviour": "",
                     "session": f"10.0.0.{i}#0", "session_attack": 0})
    for k in range(5):
        rows.append({"ip": "6.6.6.6", "timestamp": f"2026-11-02T10:01:{k:02d}+00:00", "method": "GET",
                     "path": f"/search?q=x%27+or+1%3D1--{k}", "status": 200, "size": 3000 + 9000 * (k == 4),
                     "body": "", "pred": 1, "behaviour": "", "session": "6.6.6.6#0", "session_attack": 0})
    for k in range(20):
        rows.append({"ip": "7.7.7.7", "timestamp": f"2026-11-02T10:02:{k:02d}+00:00", "method": "GET",
                     "path": f"/api/orders/{k}", "status": 200 if k < 5 else 404, "size": 800, "body": "",
                     "pred": 0, "behaviour": "enumeration", "session": "7.7.7.7#0", "session_attack": 1})
    return pd.DataFrame(rows)


def test_rules_baseline_still_works():
    s = rule_stages(requests())
    assert set(s) <= set(STAGES) | {""}


def test_model_stages_only_attacks():
    req = requests()
    s = request_stages(req)                       # the trained model if present, else the rules
    assert (s[(req["pred"] == 0) & (req["behaviour"] == "")] == "").all()
    assert (s[(req["pred"] == 1) | (req["behaviour"] != "")] != "").all()
    assert set(s) <= set(STAGES) | {""}


def test_without_model_falls_back_to_rules():
    req = requests()
    assert request_stages(req, None).equals(rule_stages(req))
    assert load_stage_model("models/does_not_exist.joblib") is None
