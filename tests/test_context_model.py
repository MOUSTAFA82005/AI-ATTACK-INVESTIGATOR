"""The learned behaviour model (ml/context_model.py): features that mean the same on any
site, and, when models/context.joblib is trained, its decisions on small made-up logs."""
import os

import pandas as pd
import pytest

from ml.context_model import FEATURES, MODEL_PATH, context_features, load_context_model
from ml.sessions import analyze_sessions


def log(rows):
    """rows: (ip, second, method, path, status, size[, body])."""
    out = []
    for r in rows:
        ip, sec, method, path, status, size, *body = r
        out.append({"ip": ip, "timestamp": f"2026-11-02T10:{sec // 60:02d}:{sec % 60:02d}+00:00", "method": method,
                    "path": path, "status": status, "size": size, "body": body[0] if body else "",
                    "user_agent": "Mozilla/5.0", "proba": 0.0, "pred": 0})
    return pd.DataFrame(out)


def visitors(n=30):
    rows = []
    for i in range(n):
        ip = f"10.0.0.{i}"
        for k, page in enumerate(["/", "/products", "/products/3", "/about", "/cart"]):
            rows.append((ip, i + k, "GET", page, 200, 3000 + 400 * k))
    return rows


NAMES = [w + ext for w in ["backup", "old", "test", "admin", "db", "dump", "site", "www", "config", "data"]
         for ext in [".zip", ".bak", ".sql", ".tar"]] + [".env", ".git/config", "phpinfo.php"]


def scanner(not_found_status, size_of):
    return [("6.6.6.6", 50 + i % 9, "GET", f"/{name}", not_found_status, size_of(name))
            for i, name in enumerate(NAMES)]


def brute(fail_status):
    return [("7.7.7.7", 55, "POST", "/login", fail_status, 900, f"user=admin&password=guess{i}") for i in range(12)]


def test_features_have_no_missing_values():
    X, _ = context_features(log(visitors() + scanner(404, len) + brute(401)))
    assert list(X.columns) == FEATURES and not X.isna().any().any()


@pytest.mark.parametrize("status,size_of", [(404, lambda n: 200 + len(n)), (200, lambda n: 5000)])
def test_not_found_looks_the_same_whatever_the_status(status, size_of):
    # a 404 page that echoes the address, or a catch-all 200 page: both are "one answer for many pages"
    X, d = context_features(log(visitors() + scanner(status, size_of)))
    scan = (d["ip"] == "6.6.6.6").values
    assert X.loc[scan, "s_top_answer_share"].min() > 0.9
    assert X.loc[~scan, "s_top_answer_share"].max() < 0.5
    assert X.loc[scan, "page_popularity"].max() == 0


@pytest.mark.parametrize("status", [401, 200])
def test_brute_force_counted_the_same_with_401_or_200(status):
    X, d = context_features(log(visitors() + brute(status)))
    b = (d["ip"] == "7.7.7.7").values
    assert X.loc[b, "attempts_this_form"].min() == 12 and X.loc[b, "form_same_answer"].min() == 12


model_needed = pytest.mark.skipif(not os.path.exists(MODEL_PATH), reason="train it: python -m ml.train_context")


@model_needed
@pytest.mark.parametrize("status,size_of", [(404, lambda n: 200 + len(n)), (200, lambda n: 5000)])
def test_model_finds_a_scanner_and_leaves_visitors_alone(status, size_of):
    df = log(visitors() + scanner(status, size_of))
    _, req = analyze_sessions(df, load_context_model())
    assert (req.loc[req["ip"] == "6.6.6.6", "behaviour"] == "scan").mean() > 0.9
    assert (req.loc[req["ip"] != "6.6.6.6", "behaviour"] == "").all()


@model_needed
@pytest.mark.parametrize("status", [401, 200])
def test_model_finds_brute_force(status):
    _, req = analyze_sessions(log(visitors() + brute(status)), load_context_model())
    assert (req.loc[req["ip"] == "7.7.7.7", "behaviour"] == "bruteforce").all()
    assert (req.loc[req["ip"] != "7.7.7.7", "behaviour"] == "").all()


@model_needed
def test_a_user_who_mistypes_twice_is_not_a_brute_force():
    # Other visitors log in too, as on any real site. If NOBODY else ever used the login form,
    # three different values sent to a form only this visitor uses look like a small probe and
    # the model flags them as a scan: a known boundary, stated in RESULTS.md section 7.
    others = [(f"10.0.0.{j}", 30, "POST", "/login", 200, 900, f"user=u{j}&password=s{j}") for j in range(3)]
    rows = visitors() + others + [("8.8.8.8", 40 + i, "POST", "/login", 401 if i < 2 else 200, 900,
                                   f"user=me&password=p{i}") for i in range(3)]
    _, req = analyze_sessions(log(rows), load_context_model())
    assert (req["behaviour"] == "").all()


@model_needed
def test_enumeration_of_ids():
    rows = visitors() + [("9.9.9.9", 50, "GET", f"/api/orders/{i}", 200, 700 + i) for i in range(1, 41)]
    _, req = analyze_sessions(log(rows), load_context_model())
    assert (req.loc[req["ip"] == "9.9.9.9", "behaviour"] == "enumeration").mean() > 0.9
    assert (req.loc[req["ip"] != "9.9.9.9", "behaviour"] == "").all()


def test_mixed_copies_put_a_scan_inside_one_visitors_browsing():
    from ml.train_context import mixed_copies
    df = log(visitors(3) + scanner(404, len))
    df["attack_type"] = ["scan" if ip == "6.6.6.6" else "" for ip in df["ip"]]
    m = mixed_copies(df)
    assert m["ip"].nunique() == 1 and m["ip"].iloc[0].startswith("mixed-")
    assert (m["attack_type"] == "scan").sum() == len(NAMES) and (m["attack_type"] == "").sum() == 5
    # brute forces are not mixed (a user who logs in again would look like one)
    df["attack_type"] = ["bruteforce" if ip == "6.6.6.6" else "" for ip in df["ip"]]
    assert mixed_copies(df).empty
