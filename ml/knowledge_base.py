"""
knowledge_base.py - the weaknesses our system can name, and how to fix each one.

One entry per weakness. `family` is the attack family the detector or the session
layer reports (sqli, xss, traversal, cmdi, bruteforce, enum, scan). `signs` are the
words a log shows when this weakness is attacked; the k-NN in ml/defense.py matches
a session's evidence against them to pick the closest entry. `fix` is what the site
owner should change, taken from the OWASP Cheat Sheet Series named in `source`.

We wrote these entries ourselves from OWASP, so k-NN retrieves from our own list,
not from past real incidents. That is said in the report.
"""

KNOWLEDGE_BASE = [
    # ---------------------------------------------------------------- SQL injection
    {
        "id": "sqli-query",
        "family": "sqli",
        "title": "SQL injection in a query parameter",
        "owasp": "A03:2021 Injection", "cwe": "CWE-89",
        "source": "OWASP SQL Injection Prevention Cheat Sheet",
        "signs": "sql query parameter search filter id select union order by where quote comment "
                 "server error 500 database",
        "fix": [
            "Build every SQL query with parameterised statements (prepared statements); never "
            "join user input into the query text.",
            "If the ORM is used, use its query builder and avoid raw query functions with user input.",
            "Validate the parameter against an allow list (type, length, characters) before use.",
            "Run the database account with the least privileges the page needs.",
            "Return a generic error page; do not show database errors to the user.",
        ],
    },
    {
        "id": "sqli-blind",
        "family": "sqli",
        "title": "Blind (time-based) SQL injection",
        "owasp": "A03:2021 Injection", "cwe": "CWE-89",
        "source": "OWASP SQL Injection Prevention Cheat Sheet",
        "signs": "sql sleep benchmark waitfor delay pg_sleep time based blind slow response timeout",
        "fix": [
            "Use parameterised statements for every query (the same fix as any SQL injection).",
            "Set a short query timeout in the database driver so a delayed query cannot hold a worker.",
            "Validate numeric parameters as numbers before they reach the database.",
            "Alert on many slow responses from one client: it is a sign of blind injection.",
        ],
    },
    {
        "id": "sqli-login",
        "family": "sqli",
        "title": "SQL injection in the login form (authentication bypass)",
        "owasp": "A03:2021 Injection", "cwe": "CWE-89",
        "source": "OWASP SQL Injection Prevention Cheat Sheet; OWASP Authentication Cheat Sheet",
        "signs": "sql login signin email username password form post body quote or comment auth bypass",
        "fix": [
            "Look the user up with a parameterised query and compare a password hash in code, "
            "never inside the SQL text.",
            "Hash passwords with a slow algorithm (Argon2id or bcrypt).",
            "Validate the username/email format before the query.",
            "Log and rate-limit failed logins.",
        ],
    },
    # ---------------------------------------------------------------- XSS
    {
        "id": "xss-reflected",
        "family": "xss",
        "title": "Reflected cross-site scripting (XSS)",
        "owasp": "A03:2021 Injection", "cwe": "CWE-79",
        "source": "OWASP Cross Site Scripting Prevention Cheat Sheet",
        "signs": "xss script alert onerror onload img svg iframe javascript search query parameter "
                 "reflected html tag",
        "fix": [
            "Encode every user value for the place it is written (HTML body, attribute, JavaScript, URL).",
            "Use a template engine or framework that encodes output by default, and do not turn it off.",
            "Add a Content-Security-Policy header that blocks inline scripts.",
            "Validate input against an allow list where the format is known.",
        ],
    },
    {
        "id": "xss-stored",
        "family": "xss",
        "title": "Stored cross-site scripting in user content",
        "owasp": "A03:2021 Injection", "cwe": "CWE-79",
        "source": "OWASP Cross Site Scripting Prevention Cheat Sheet",
        "signs": "xss script post body feedback comment review message profile name stored html",
        "fix": [
            "Encode user content when it is shown, on every page that shows it.",
            "If users may send rich text, clean it with a well-known HTML sanitiser (e.g. DOMPurify).",
            "Add a Content-Security-Policy header that blocks inline scripts.",
            "Set session cookies HttpOnly so a script cannot read them.",
        ],
    },
    # ---------------------------------------------------------------- traversal
    {
        "id": "traversal-file",
        "family": "traversal",
        "title": "Path traversal / local file inclusion",
        "owasp": "A01:2021 Broken Access Control", "cwe": "CWE-22",
        "source": "OWASP Input Validation Cheat Sheet; OWASP File Upload / path traversal guidance",
        "signs": "traversal file path page include download dot dot slash etc passwd win ini "
                 "parameter file name",
        "fix": [
            "Never build a file path from user input; map an allowed name or ID to a fixed file instead.",
            "If a path must come from input, resolve it to its canonical form and check that it is "
            "inside the allowed folder.",
            "Run the web server with an account that cannot read system files.",
            "Turn off directory listing.",
        ],
    },
    {
        "id": "traversal-encoded",
        "family": "traversal",
        "title": "Encoded path traversal (filter bypass)",
        "owasp": "A01:2021 Broken Access Control", "cwe": "CWE-22",
        "source": "OWASP Input Validation Cheat Sheet",
        "signs": "traversal encoded double encoding percent 2e 2f 5c 252e unicode null byte bypass filter",
        "fix": [
            "Decode the input fully (once, to its canonical form) before any check.",
            "Check the final resolved path, not the raw string, against the allowed folder.",
            "Reject input that still contains encoded characters after decoding.",
        ],
    },
    # ---------------------------------------------------------------- command injection
    {
        "id": "cmdi-os",
        "family": "cmdi",
        "title": "OS command injection",
        "owasp": "A03:2021 Injection", "cwe": "CWE-78",
        "source": "OWASP OS Command Injection Defense Cheat Sheet",
        "signs": "cmdi command exec shell ip host ping semicolon pipe ampersand backtick whoami id cat "
                 "ls uname",
        "fix": [
            "Do not call the system shell with user input; use the language's library function "
            "for the job instead (e.g. a DNS or ping library).",
            "If a program must be run, pass arguments as a list (no shell) and validate them "
            "against an allow list (e.g. a strict IP address format).",
            "Run the web application with the least privileges it needs.",
        ],
    },
    {
        "id": "cmdi-blind",
        "family": "cmdi",
        "title": "Blind (time-based) command injection",
        "owasp": "A03:2021 Injection", "cwe": "CWE-78",
        "source": "OWASP OS Command Injection Defense Cheat Sheet",
        "signs": "cmdi command sleep ping timeout delay slow response blind time based",
        "fix": [
            "Remove the shell call or pass arguments as a list without a shell.",
            "Validate the input strictly (for an IP: four numbers 0-255, nothing else).",
            "Set a timeout on any external program the page runs.",
        ],
    },
    # ---------------------------------------------------------------- brute force
    {
        "id": "bruteforce-account",
        "family": "bruteforce",
        "title": "Password guessing on one account",
        "owasp": "A07:2021 Identification and Authentication Failures", "cwe": "CWE-307",
        "source": "OWASP Authentication Cheat Sheet; OWASP Credential Stuffing Prevention Cheat Sheet",
        "signs": "bruteforce one account same user many passwords repeated quickly",
        "fix": [
            "Limit failed logins per account: slow down, then lock for a short time after a few failures.",
            "Add multi-factor authentication for important accounts.",
            "Show a CAPTCHA after repeated failures.",
            "Alert the account owner about many failed logins.",
        ],
    },
    {
        "id": "bruteforce-spray",
        "family": "bruteforce",
        "title": "Password spraying / credential stuffing (many accounts)",
        "owasp": "A07:2021 Identification and Authentication Failures", "cwe": "CWE-307",
        "source": "OWASP Credential Stuffing Prevention Cheat Sheet",
        "signs": "bruteforce many accounts different users spray common password",
        "fix": [
            "Limit login attempts per client IP, not only per account.",
            "Check new passwords against lists of breached passwords.",
            "Add multi-factor authentication.",
            "Use the same error message and timing for 'unknown user' and 'wrong password'.",
        ],
    },
    {
        "id": "bruteforce-slow",
        "family": "bruteforce",
        "title": "Slow password guessing",
        "owasp": "A07:2021 Identification and Authentication Failures", "cwe": "CWE-307",
        "source": "OWASP Authentication Cheat Sheet",
        "signs": "bruteforce slow spread over time few attempts long gaps between tries",
        "fix": [
            "Count failed logins over a long window (hours), not only per minute.",
            "Require a CAPTCHA or MFA after a few failures, even when they are spread out.",
            "Review this client: it may also be a user who forgot a password.",
        ],
    },
    # ---------------------------------------------------------------- enumeration
    {
        "id": "enum-idor",
        "family": "enum",
        "title": "Object ID enumeration (possible IDOR)",
        "owasp": "A01:2021 Broken Access Control", "cwe": "CWE-639",
        "source": "OWASP Insecure Direct Object Reference Prevention Cheat Sheet",
        "signs": "enum enumeration id numeric sequential many ids one resource basket order user "
                 "account record api",
        "fix": [
            "On every request, check on the server that the logged-in user owns the object asked for.",
            "Use random, hard-to-guess IDs (UUIDs) in URLs instead of counting numbers.",
            "Rate-limit requests to the resource per user and per IP.",
        ],
    },
    # ---------------------------------------------------------------- scanning
    {
        "id": "scan-files",
        "family": "scan",
        "title": "Probing for exposed sensitive files",
        "owasp": "A05:2021 Security Misconfiguration", "cwe": "CWE-538",
        "source": "OWASP Web Security Testing Guide (configuration testing)",
        "signs": "scan probe git env config backup bak old swp htaccess hidden file sensitive",
        "fix": [
            "Do not deploy source control folders, backups or config files to the web root.",
            "Deny access to hidden files and backup extensions in the web server configuration.",
            "Keep secrets outside the web root (environment variables or a secrets store).",
        ],
    },
    {
        "id": "scan-admin",
        "family": "scan",
        "title": "Searching for admin and debug pages",
        "owasp": "A05:2021 Security Misconfiguration", "cwe": "CWE-200",
        "source": "OWASP Web Security Testing Guide (configuration testing)",
        "signs": "scan probe admin administrator manager console phpmyadmin debug status server info "
                 "panel",
        "fix": [
            "Put admin pages behind authentication and, if possible, allow them only from an "
            "internal network or VPN.",
            "Remove debug and status pages from production.",
            "Do not reveal software versions in headers or error pages.",
        ],
    },
    {
        "id": "scan-dirs",
        "family": "scan",
        "title": "Directory and file guessing (many missing pages)",
        "owasp": "A05:2021 Security Misconfiguration", "cwe": "CWE-548",
        "source": "OWASP Web Security Testing Guide (configuration testing)",
        "signs": "scan many not found 404 paths directory guessing listing wordlist",
        "fix": [
            "Turn off directory listing.",
            "Rate-limit clients that cause many 404 answers.",
            "Make sure no unlinked page is left on the server without protection.",
        ],
    },
]

FAMILIES = ["sqli", "xss", "traversal", "cmdi", "bruteforce", "enum", "scan"]
