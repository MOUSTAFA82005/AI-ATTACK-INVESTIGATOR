"""v10 session changes: one visitor = IP + user agent; logs without answer sizes."""
import pandas as pd

from ml.context_model import context_features
from ml.sessions import add_session_ids, visitor_key


def _name(i):
    return chr(97 + i % 26) + chr(97 + i // 26)


def _df(rows):
    d = pd.DataFrame(rows, columns=["ip", "timestamp", "method", "path", "status", "size", "user_agent"])
    d["body"] = ""
    d["proba"] = 0.0
    return d


def test_one_ip_many_agents_are_many_visitors():
    d = _df([["1.1.1.1", "2026-01-01T00:00:00Z", "GET", "/a", 200, 10, "Firefox"],
             ["1.1.1.1", "2026-01-01T00:00:01Z", "GET", "/a", 200, 10, "Chrome"],
             ["1.1.1.1", "2026-01-01T00:00:02Z", "GET", "/b", 200, 10, "Firefox"]])
    s = add_session_ids(d)
    assert s["session"].nunique() == 2
    assert s["ip"].nunique() == 1


def test_scanner_test_numbers_in_agent_stay_one_visitor():
    d = _df([["1.1.1.1", f"2026-01-01T00:00:0{i}Z", "GET", f"/t{i}", 404, 10,
              f"Mozilla/5.00 (Nikto/2.1.6) (Evasions:None) (Test:00{i}123)"] for i in range(5)])
    assert add_session_ids(d)["session"].nunique() == 1


def test_no_agent_falls_back_to_ip():
    d = _df([["1.1.1.1", "2026-01-01T00:00:00Z", "GET", "/a", 200, 10, ""],
             ["1.1.1.1", "2026-01-01T00:00:01Z", "GET", "/b", 200, 10, "-"]])
    assert set(visitor_key(d)) == {"1.1.1.1"}


def test_log_without_sizes_does_not_look_like_one_answer():
    rows = [[f"10.0.0.{i % 5}", f"2026-01-01T00:{i // 60:02d}:{i % 60:02d}Z", "GET", "/page-" + _name(i % 60), 200, 0, "UA"]
            for i in range(120)]
    X, _ = context_features(_df(rows))
    # every page is its own answer, not one shared "200:0" page
    assert X["s_top_answer_share"].max() < 0.5


def test_not_found_still_shared_without_sizes():
    rows = [[f"10.0.0.{i % 5}", f"2026-01-01T00:{i // 60:02d}:{i % 60:02d}Z", "GET", "/page-" + _name(i % 60), 200, 0, "UA"]
            for i in range(120)]
    rows += [["9.9.9.9", f"2026-01-01T01:00:{i:02d}Z", "GET", "/hidden-" + _name(i), 404, 0, "scanner"] for i in range(40)]
    X, d = context_features(_df(rows))
    scan = (d["ip"] == "9.9.9.9").values
    assert X.loc[scan, "s_top_answer_share"].min() == 1.0
