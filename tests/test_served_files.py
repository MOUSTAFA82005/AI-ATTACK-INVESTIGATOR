"""A download-like file the site really serves is not a probe; a guessed one still is."""
import numpy as np
import pandas as pd

from ml.detector import served_files, to_frame
from ml.features import value_features


def _check(rows):
    df = pd.DataFrame(rows, columns=["ip", "method", "path", "status"]).assign(body="")
    X = to_frame(df["method"], df["path"], df["body"])
    pred = np.ones(len(df), dtype=int)          # pretend the detector flagged every row
    return list(served_files(df, X, pred))


def test_served_download_is_cleared():
    assert _check([("1.1.1.1", "GET", "/files/tool-2.1.tar.gz", 200),
                   ("2.2.2.2", "GET", "/files/dhcpd.conf", 304)]) == [True, True]


def test_guessed_file_is_kept():
    assert _check([("1.1.1.1", "GET", "/backup.zip", 404)]) == [False]


def test_ip_with_another_alarm_is_kept():
    # same IP also sent an injection: its downloads are part of the attack
    assert _check([("1.1.1.1", "GET", "/files/site.tar.gz", 200),
                   ("1.1.1.1", "GET", "/search?q=' or 1=1--", 200)]) == [False, False]


def test_sensitive_file_is_kept_even_when_served():
    assert _check([("1.1.1.1", "GET", "/.env", 200), ("2.2.2.2", "GET", "/.git/config", 200)]) == [False, False]


def test_web_shell_name_only_at_the_right_place():
    probe = lambda p: value_features("GET", p, "")["p_probe_path"]
    assert probe("/shell.php") == 1 and probe("/uploads/shell.jsp") == 1 and probe("/shell") == 1
    assert probe("/blog/geekery/shell-shortcut-hacks.html") == 0 and probe("/blog/tags/shell?page=1") == 0
