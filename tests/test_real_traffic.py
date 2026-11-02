"""Session rules on real-shop traffic (v5): pictures, paging and crawlers are not attacks."""
import pandas as pd

from ml.sessions import _id_of, analyze_sessions


def test_static_files_have_no_object_id():
    assert _id_of("/image/8367?name=a.jpg&wh=200x200") == (None, None)
    assert _id_of("/image/42/productModel/100x100") == (None, None)
    assert _id_of("/static/js/app.123.js") == (None, None)
    assert _id_of("/api/Users/42") == ("/api/Users/{id}", "42")


def test_paging_and_cache_busting_are_not_ids():
    assert _id_of("/filter?page=7") == (None, None)
    assert _id_of("/plugins/x/criteria.js?_=1700000000") == (None, None)
    assert _id_of("/vulnerabilities/sqli/?id=7&Submit=Submit") == ("/vulnerabilities/sqli/?id={id}", "7")


def _session(paths, statuses):
    t = pd.date_range("2026-01-01", periods=len(paths), freq="s", tz="UTC")
    return pd.DataFrame({"ip": "1.2.3.4", "timestamp": t.astype(str), "method": "GET", "path": paths,
                         "status": statuses, "body": "", "pred": 0})


def test_crawler_with_few_dead_links_is_not_a_scan():
    paths = [f"/page/{i}/x{i}" for i in range(300)]
    statuses = [404 if i % 20 == 0 else 200 for i in range(300)]     # 15 dead links, 5%
    sessions, _ = analyze_sessions(_session(paths, statuses))
    assert "scan" not in sessions.iloc[0]["behaviours"]


def test_many_not_found_answers_are_still_a_scan():
    paths = [f"/hidden{i}" for i in range(20)] + ["/"] * 5
    statuses = [404] * 20 + [200] * 5
    sessions, _ = analyze_sessions(_session(paths, statuses))
    assert "scan" in sessions.iloc[0]["behaviours"]


def test_every_swept_resource_is_marked():
    paths = [f"/api/BasketItems/{i}" for i in range(20)] + [f"/rest/basket/{i}" for i in range(25)]
    _, req = analyze_sessions(_session(paths, [200] * 45))
    assert (req["behaviour"] == "enumeration").all()


def test_search_engine_crawler_is_low_risk_not_hidden():
    paths = [f"/product/{i}" for i in range(100)]
    d = _session(paths, [200] * 100)
    d["user_agent"] = "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
    sessions, req = analyze_sessions(d)
    s = sessions.iloc[0]
    assert s["crawler"] and s["risk_level"] == "low" and s["behaviours"] == []
    assert req["session_attack"].sum() == 0
    d["user_agent"] = "Mozilla/5.0 (Windows NT 10.0; Win64; x64)"
    sessions, _ = analyze_sessions(d)
    assert "enumeration" in sessions.iloc[0]["behaviours"]


def test_pipe_as_a_value_separator_is_not_shell():
    from ml.features import value_features
    shell = lambda p: value_features("GET", p, "")["v_ctx_shell"]
    assert shell("/filter?f=c221|Android") == 0
    assert shell("/filter?f=p65,216|Full+HD") == 0
    assert shell("/filter?f=p5,v2|%D9%85") == 0          # decoded: a Persian letter after "|"
    assert shell("/x?ip=127.0.0.1|ls") == 1
    assert shell("/x?a=1||id") >= 1
