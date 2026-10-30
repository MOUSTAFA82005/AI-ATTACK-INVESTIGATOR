"""Sites that answer every unknown page with 200 (the same catch-all page) still show a scan."""
import pandas as pd

from ml.sessions import analyze_sessions, soft_not_found

CATCH_ALL = 3259      # size of the catch-all page


def _log(with_size=True):
    rows = []
    t = pd.Timestamp("2026-10-30T10:00:00Z")
    for i in range(6):                                   # ordinary visitors: home page + a product
        ip = f"10.0.0.{i}"
        rows += [(ip, t, "GET", "/", 200, CATCH_ALL), (ip, t, "GET", f"/api/products/{i}", 200, 512)]
    for i in range(20):                                  # a scanner guessing pages
        rows.append(("10.9.9.9", t + pd.Timedelta(seconds=i), "GET", f"/guess{chr(97 + i)}", 200, CATCH_ALL))
    df = pd.DataFrame(rows, columns=["ip", "timestamp", "method", "path", "status", "size"])
    df["timestamp"] = df["timestamp"].astype(str)
    df["body"], df["pred"] = "", 0
    return df if with_size else df.drop(columns="size")


def test_guessed_pages_are_soft_not_found_and_home_page_is_not():
    df = _log()
    soft = soft_not_found(df)
    assert soft[df["ip"] == "10.9.9.9"].all()
    assert not soft[df["ip"] != "10.9.9.9"].any()


def test_without_size_nothing_is_marked():
    assert not soft_not_found(_log(with_size=False)).any()


def test_scanner_session_is_flagged_and_visitors_are_not():
    sessions, req = analyze_sessions(_log())
    s = sessions.set_index("ip")
    assert "scan" in s.loc["10.9.9.9", "behaviours"] and s.loc["10.9.9.9", "soft_not_found"] == 20
    assert all(len(b) == 0 for ip, b in s["behaviours"].items() if ip != "10.9.9.9")
    assert req.loc[req["ip"] == "10.9.9.9", "session_attack"].all()
