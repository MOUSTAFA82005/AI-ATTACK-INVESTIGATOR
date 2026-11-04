import pandas as pd

from ml.detector import served_files, to_frame


def run(rows, pred=None):
    df = pd.DataFrame(rows, columns=["ip", "method", "path", "status"]).assign(body="")
    X = to_frame(df["method"], df["path"], df["body"])
    return list(served_files(df, X, pred if pred is not None else [1] * len(df)))


def test_served_login_page_is_not_an_alarm():
    assert run([("1.1.1.1", "GET", "/blog/wp-login.php", 200)]) == [True]
    assert run([("1.1.1.1", "GET", "/blog/wp-admin/profile.php", 302)]) == [True]
    assert run([("1.1.1.1", "GET", "/admin.php", 200)]) == [True]


def test_even_when_the_same_ip_has_other_alarms():
    out = run([("1.1.1.1", "GET", "/blog/wp-login.php", 200), ("1.1.1.1", "GET", "/?id=1' or 1=1--", 200)])
    assert out == [True, False]


def test_missing_login_page_stays_an_alarm():
    assert run([("1.1.1.1", "GET", "/wp-login.php", 404)]) == [False]


def test_backup_copies_and_leaks_stay_alarms():
    for p in ["/blog/wp-login.php.bak", "/blog/wp-login.php.zip", "/blog/wp-login~", "/.env", "/.git/config",
              "/phpmyadmin/", "/blog/wp-login.php.0"]:
        assert run([("1.1.1.1", "GET", p, 200)]) == [False], p


def test_payload_on_login_page_stays_an_alarm():
    assert run([("1.1.1.1", "GET", "/wp-login.php?redirect_to=<script>alert(1)</script>", 200)]) == [False]


def test_not_flagged_stays_not_flagged():
    assert run([("1.1.1.1", "GET", "/blog/wp-login.php", 200)], pred=[0]) == [False]
