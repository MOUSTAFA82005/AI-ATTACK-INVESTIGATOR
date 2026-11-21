"""v12 fixes: quoted links re-scored, user-agent-rotating IPs merged, known exploit endpoints."""
import numpy as np
import pandas as pd

from ml import sessions as ses
from ml.detector import QUOTED_LINK, attack_proba, to_frame
from ml.probes import known_probe


class _Fake:
    """Says 0.99 for every request on the first call and 0.2 on later calls (the re-score)."""
    def __init__(self):
        self.calls = 0

    def predict_proba(self, X):
        self.calls += 1
        p = np.full(len(X), 0.99 if self.calls == 1 else 0.2)
        return np.c_[1 - p, p]


def _rows(paths):
    return ["GET"] * len(paths), paths, [""] * len(paths)


def test_quoted_link_is_removed_before_scoring():
    m, p, b = _rows(["/honeypot//%22http://glastopf.org//%22", '/a/"http://x.org/b"'])
    assert QUOTED_LINK.search(p[0]) and QUOTED_LINK.search(p[1])
    out = attack_proba(_Fake(), to_frame(m, p, b), m, p, b)
    assert np.allclose(out, 0.2)


def test_only_quoted_links_are_rescored():
    m, p, b = _rows(["/page?id=1'%20or%201=1--", "/honeypot//%22http://glastopf.org//%22"])
    out = attack_proba(_Fake(), to_frame(m, p, b), m, p, b)
    assert np.allclose(out, [0.99, 0.2])


def test_payload_inside_quotes_is_not_removed():
    for p in ["/x/%22http://a.com/'%20or%201=1--%22", '/x/"http://a.com/<script>"', "/x/%22http://a.com/%20union%22"]:
        assert not QUOTED_LINK.search(p), p


def test_score_never_goes_up():
    m, p, b = _rows(["/page", "/honeypot//%22http://glastopf.org//%22"])
    X = to_frame(m, p, b)
    assert (attack_proba(_Fake(), X, m, p, b) <= 0.99 + 1e-12).all()


def _df(ip_agents):
    rows = [{"ip": ip, "user_agent": ua} for ip, ua in ip_agents]
    return pd.DataFrame(rows)


def test_rotating_agents_become_one_visitor():
    rot = [("1.1.1.1", f"Browser {c}") for c in "ABCDEFG" for _ in range(2)]      # 7 agents, 14 requests
    k = ses.visitor_key(_df(rot))
    assert k.nunique() == 1 and k.iloc[0] == "1.1.1.1"


def test_people_behind_one_proxy_stay_apart():
    proxy = [("2.2.2.2", f"Browser {c}") for c in "ABCDEF" for _ in range(10)]    # 6 people, 10 requests each
    assert ses.visitor_key(_df(proxy)).nunique() == 6


def test_few_agents_stay_apart():
    few = [("3.3.3.3", "Phone A"), ("3.3.3.3", "Phone B"), ("3.3.3.3", "Mail app")]
    assert ses.visitor_key(_df(few)).nunique() == 3


def test_known_exploit_endpoints():
    for p in ["/api/session/properties", "/ueditor/net/controller.ashx?action=catchimage",
              "/Ueditor/controller.ashx?action=catchimage", "/plus/download.php?arrs1&open=1",
              "/_ignition/execute-solution"]:
        assert known_probe(p, 404) and known_probe(p, 429), p
    for p in ["/backup", "/bk/", "/BC"]:
        assert known_probe(p, 404, "HEAD") and not known_probe(p, 404, "GET"), p
    for p in ["/old", "/blog/backup", "/api/session", "/plus/index.php"]:
        assert not known_probe(p, 404), p
    assert not known_probe("/api/session/properties", 200)          # a real Metabase answers it


def test_refused_with_429_counts():
    assert known_probe("/.env", 429) and not known_probe("/.env", 301)
