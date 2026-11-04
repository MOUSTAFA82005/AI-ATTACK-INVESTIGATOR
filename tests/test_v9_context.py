"""v9 context features: 'compared to the other visitors' and body-less login attempts."""
import pandas as pd

from ml.context_model import FEATURES, context_features


def _req(ip, path, i, method="GET", status=200, body=""):
    return {"ip": ip, "timestamp": f"2026-01-01T00:{i // 60:02d}:{i % 60:02d}+00:00", "method": method,
            "path": path, "status": status, "size": 500, "user_agent": "Mozilla/5.0", "body": body, "proba": 0.0}


def _features(rows):
    X, d = context_features(pd.DataFrame(rows))
    return X.reset_index(drop=True), d.reset_index(drop=True)


def test_sweep_of_a_page_everybody_opens_stands_out():
    rows = [_req(f"10.0.0.{u}", f"/profile/{u % 5 + 1}", u) for u in range(40)]          # 40 users, 1 profile each
    rows += [_req("10.9.9.9", f"/profile/{n}", 100 + n) for n in range(1, 31)]           # one IP, 30 profiles
    X, d = _features(rows)
    sweep = d["ip"] == "10.9.9.9"
    assert X.loc[sweep, "ids_vs_typical"].min() > 2.5
    assert X.loc[~sweep, "ids_vs_typical"].max() == 0


def test_shop_where_everybody_browses_many_items_is_not_a_sweep():
    rows = [_req(f"10.0.0.{u}", f"/product/{n}", u * 20 + n) for u in range(30) for n in range(1, 16)]
    X, _ = _features(rows)
    assert X["ids_vs_typical"].max() == 0


def test_probing_one_form_with_many_values():
    rows = [_req(f"10.0.0.{u}", f"/search?q=word{u}", u) for u in range(30)]
    rows += [_req("10.9.9.9", f"/search?q=probe{n}x", 100 + n) for n in range(40)]
    X, d = _features(rows)
    probe = d["ip"] == "10.9.9.9"
    assert X.loc[probe, "values_vs_typical"].min() > 3
    assert X.loc[~probe, "values_vs_typical"].max() == 0


def test_post_to_login_without_logged_body_is_a_login_attempt():
    X, _ = _features([_req("10.0.0.1", "/login.php", i, method="POST") for i in range(20)])
    assert X["password_field"].eq(1).all() and X["attempts_this_form"].max() == 20


def test_logged_body_still_decides():
    X, _ = _features([_req("10.0.0.1", "/login", 0, method="POST", body="q=hello")])
    assert X["password_field"].iloc[0] == 0


def test_feature_list():
    X, _ = _features([_req("10.0.0.1", "/", 0)])
    assert list(X.columns) == FEATURES and "ids_vs_typical" in FEATURES and "values_vs_typical" in FEATURES


def test_payload_probes_inside_a_scan_are_one_scan_step():
    from ml.next_step import session_steps
    kinds = ["sqli", "xss", "cmdi", "traversal"] * 5
    req = pd.DataFrame({"session": "s1", "timestamp": [f"2026-01-01T00:00:{i:02d}+00:00" for i in range(20)],
                        "pred": 1, "session_attack": 1, "behaviour": "scan", "type_pred": kinds})
    assert session_steps(req) == {"s1": ["scan"]}
    req["behaviour"] = ""                       # payloads outside a scan keep their own type
    req["type_pred"] = ["sqli"] * 10 + ["xss"] * 10
    assert session_steps(req) == {"s1": ["sqli", "xss"]}
