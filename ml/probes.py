"""
Known-probe list: requests for files that a scanner looks for and a site should never publish (version-control
folders, editor and OS leftovers, backup and database dumps, config files, well-known web shells, admin tools).

Why a list and not the model: such a request carries no payload. "/dump.sql" or "/.svn/entries" looks like any page
name; it is an attack only because of WHAT is asked for. The learned detector reads the request's shape, so it
cannot know these names (v11 sealed post-hoc analysis: 51 of 99 families missed by rules, v10 and v11 alike were
such probes). The list comes from public scanner wordlists (nikto, dirb/SecLists "common sensitive files") and the
Biblio-US17 DEV months only; nothing from a sealed set.

A match counts only when the site said the file is not there or not allowed (403, 404, 410). A site that serves the
file (WordPress serving its own wp-login.php, a site that really publishes /backup.zip) is not probed, it is used.
Requests with several probes from one visitor are also caught by the session layer ("scan"); this list adds the
single probe and logs without client addresses.
"""
import re

_NAMES = [
    # version control and editor / OS leftovers
    r"/\.(git|svn|hg|bzr)(/|$)", r"/cvs/(entries|root|repository)$", r"/\.ds_store$", r"/thumbs\.db$",
    r"\.(swp|swo)$",
    # secrets and configuration
    r"/\.env(\.[a-z]+)?$", r"/\.ht(access|passwd)$", r"/web\.config$", r"/\.aws/", r"/\.ssh/",
    r"/(wp-config|config|configuration|settings|local|database|db)\.(php|inc|xml|ini|json|ya?ml)"
    r"\.(bak|old|orig|save|swp|txt|backup|dist|1|2|~)$",
    r"/wp-config\.(old|bak|txt|save|orig)$", r"/app/etc/local\.xml$", r"/config/database\.yml$",
    r"/(php|web|server)\.?ini$", r"/composer\.(json|lock)$", r"/package\.json$",
    # database dumps and site backups
    r"\.sql(\.(gz|zip|bz2|tar|7z))?$", r"\.(mdb|sqlite3?|db)$",
    r"/[^/]*(backup|bkp|dump|database|db|site|www|htdocs|public_html|wwwroot|web)[^/]*"
    r"\.(zip|rar|7z|tar|tgz|tar\.gz|tar\.bz2|gz|bz2|bak|old)$",
    # web shells and admin / info tools
    r"/(c99|c100|r57|wso|b374k|alfa|indoxploit|shell|cmd|webshell|up|upload)\.(php\d?|aspx?|jspx?)$",
    r"/(phpmyadmin|pma|myadmin|mysqladmin|phpmyadmin\d*|dbadmin|sqladmin)(/|$)", r"/adminer(-[\d.]+)?\.php$",
    r"/(phpinfo|info|php_info|test|i)\.php$", r"/server-(status|info)$",
    # well-known application files looked for by CMS scanners
    # (not wp-login / wp-admin / wp-content: real WordPress sites answer 403/404 there to ordinary visitors and
    # bots, SR-BH dev normal had 45,660 such rows; guessing logins is left to the session layer)
    r"/wp-includes/wlwmanifest\.xml$", r"/(user|admin)/config\.php$",
    r"/(owa|ecp|autodiscover)/", r"/(actuator|jmx-console|web-console|manager/html|solr/admin)(/|$)",
    r"/(vendor/phpunit|phpunit)/", r"/(_profiler|telescope|elmah\.axd|trace\.axd)(/|$)",
]
_KNOWN = re.compile("|".join(f"(?:{p})" for p in _NAMES), re.I)
NOT_THERE = {403, 404, 410}


def is_known_name(path):
    """The path (without query) asks for a known scanner target."""
    return bool(_KNOWN.search(str(path or "").split("?", 1)[0].split("#", 1)[0]))


def known_probe(path, status):
    """A known scanner target that the site does not have or does not allow."""
    try:
        status = int(status)
    except (TypeError, ValueError):
        return False
    return status in NOT_THERE and is_known_name(path)


PROBE_REASON = "Asked for a file that scanners look for (a backup, a dump, a config or version-control file), and the site does not have it"


def probe_rows(paths, statuses):
    """Boolean array: known_probe for each request."""
    import numpy as np
    return np.array([known_probe(p, s) for p, s in zip(paths, statuses)], dtype=bool)
