"""Known-probe list (ml/probes.py): scanner targets count only when the site does not have them."""
import pytest

from ml.probes import is_known_name, known_probe


@pytest.mark.parametrize("path", ["/.git/HEAD", "/scripts/.svn/entries", "/filter/.DS_Store", "/dump.sql",
                                  "/backup.tar.gz", "/wp-config.php.bak", "/.env", "/c99.php", "/phpmyadmin/",
                                  "/app/etc/local.xml", "/wp-includes/wlwmanifest.xml", "/site_backup.zip?x=1"])
def test_known_names(path):
    assert is_known_name(path)
    assert known_probe(path, 404) and known_probe(path, "403")


@pytest.mark.parametrize("path", ["/", "/index.php", "/blog/wp-login.php", "/wp-admin/", "/wp-content/uploads/a.jpg",
                                  "/pub/docs/readme.txt", "/cgi-bin/search.cgi", "/~user/", "/cornforth~",
                                  "/images/logo.png", "/static/app.js", "/downloads/report.pdf"])
def test_ordinary_pages_are_not_probes(path):
    assert not known_probe(path, 404)


def test_served_file_is_not_a_probe():
    assert not known_probe("/backup.zip", 200)       # the site really publishes it
    assert not known_probe("/dump.sql", 302)
    assert not known_probe("/dump.sql", None) and not known_probe("/dump.sql", "")
