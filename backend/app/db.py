"""Local storage for the dashboard: user accounts and saved investigations (SQLite, stdlib only).

The database lives in var/app.db (ignored by git). Override the place with the
AAI_DB environment variable, or pass ":memory:" in tests.

Saved results are the /investigate answers after masking (paths and bodies already
masked), stored zlib-compressed. Every query on investigations is scoped to one user,
so a user can never read another user's results.
"""
import json
import os
import sqlite3
import threading
import time
import zlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DB_PATH = Path(os.environ.get("AAI_DB", ROOT / "var" / "app.db"))

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    username   TEXT NOT NULL UNIQUE COLLATE NOCASE,   -- the name shown in the dashboard; can log in with it
    email      TEXT,                       -- where codes are sent; can log in with it (unique, see below)
    password   TEXT NOT NULL,              -- JSON: salt, scrypt parameters, hash (never the password)
    status     TEXT NOT NULL DEFAULT 'pending' CHECK (status IN ('pending', 'active', 'disabled')),
    totp_secret     TEXT NOT NULL,         -- unused since codes come by e-mail (kept so older databases open)
    totp_confirmed  INTEGER NOT NULL DEFAULT 0,   -- 1 once the e-mail address is confirmed with a code
    totp_last_step  INTEGER NOT NULL DEFAULT 0,   -- unused (kept so older databases open)
    created_at REAL NOT NULL,
    last_login REAL
);
CREATE TABLE IF NOT EXISTS investigations (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at REAL NOT NULL,
    filename   TEXT,
    summary    TEXT NOT NULL,              -- JSON, small: what the lists and statistics need
    result     BLOB NOT NULL               -- zlib(JSON) of the full masked result
);
CREATE INDEX IF NOT EXISTS inv_user ON investigations(user_id, created_at);
CREATE TABLE IF NOT EXISTS trusted_addresses (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    address    TEXT NOT NULL,              -- one IP or a network (CIDR), stored in normal form
    note       TEXT NOT NULL DEFAULT '',
    created_at REAL NOT NULL,
    UNIQUE (user_id, address)
);
"""
# Older databases had no email column (the user name held the address); add it on open.
EMAIL_INDEX = "CREATE UNIQUE INDEX IF NOT EXISTS users_email ON users(email COLLATE NOCASE)"


class Store:
    """One SQLite connection shared by the server threads, guarded by a lock."""

    def __init__(self, path=DB_PATH):
        if str(path) != ":memory:":
            Path(path).parent.mkdir(parents=True, exist_ok=True)
        self._db = sqlite3.connect(str(path), check_same_thread=False)
        self._db.row_factory = sqlite3.Row
        self._db.execute("PRAGMA foreign_keys = ON")
        self._db.executescript(SCHEMA)
        if "email" not in [r[1] for r in self._db.execute("PRAGMA table_info(users)")]:
            with self._db:
                self._db.execute("ALTER TABLE users ADD COLUMN email TEXT")
                self._db.execute("UPDATE users SET email = lower(username) WHERE username LIKE '%_@_%'")
        self._db.execute(EMAIL_INDEX)
        self._lock = threading.Lock()

    def _q(self, sql, args=(), one=False):
        with self._lock, self._db:
            cur = self._db.execute(sql, args)
            rows = cur.fetchall()
            return (rows[0] if rows else None) if one else rows

    def _exec(self, sql, args=()):
        with self._lock, self._db:
            return self._db.execute(sql, args).lastrowid

    # ------------------------------------------------------------------ users
    @staticmethod
    def _user(row):
        if row is None:
            return None
        u = dict(row)
        u["password"] = json.loads(u["password"])
        return u

    def add_user(self, username, password_record, email=None, status="pending"):
        """Returns the new id, or None when the user name or e-mail is taken (both ignore upper/lower case)."""
        try:
            return self._exec("INSERT INTO users (username, email, password, totp_secret, status, created_at) "
                              "VALUES (?, ?, ?, '', ?, ?)",
                              (username, email, json.dumps(password_record), status, time.time()))
        except sqlite3.IntegrityError:
            return None

    def user_by_name(self, username):
        return self._user(self._q("SELECT * FROM users WHERE username = ?", (username,), one=True))

    def user_by_email(self, email):
        return self._user(self._q("SELECT * FROM users WHERE email = ? COLLATE NOCASE", (email,), one=True))

    def user_by_login(self, login):
        """The account for what was typed in the login box: an e-mail address (has '@') or a user name."""
        return self.user_by_email(login) if "@" in login else self.user_by_name(login)

    def delete_unconfirmed(self, older_than):
        """Drop sign-ups that never confirmed their e-mail, so they do not hold a name or address forever."""
        with self._lock, self._db:
            return self._db.execute("DELETE FROM users WHERE totp_confirmed = 0 AND created_at < ?", (older_than,)).rowcount

    def user_by_id(self, user_id):
        return self._user(self._q("SELECT * FROM users WHERE id = ?", (user_id,), one=True))

    def users(self):
        rows = self._q("SELECT u.id, u.username, u.email, u.status, u.totp_confirmed, u.created_at, u.last_login, "
                       "(SELECT COUNT(*) FROM investigations i WHERE i.user_id = u.id) AS investigations "
                       "FROM users u ORDER BY u.status = 'pending' DESC, u.created_at")
        return [dict(r) for r in rows]

    def update_user(self, user_id, **fields):
        allowed = {"username", "email", "status", "last_login", "totp_secret", "totp_confirmed", "totp_last_step"}
        sets = {k: v for k, v in fields.items() if k in allowed}
        if "password" in fields:
            sets["password"] = json.dumps(fields["password"])
        if not sets:
            return
        cols = ", ".join(f"{k} = ?" for k in sets)
        self._exec(f"UPDATE users SET {cols} WHERE id = ?", (*sets.values(), user_id))

    def delete_user(self, user_id):
        self._exec("DELETE FROM users WHERE id = ?", (user_id,))

    def active_users(self):
        return self._q("SELECT COUNT(*) AS n FROM users WHERE status = 'active'", one=True)["n"]

    # ------------------------------------------------------------------ investigations
    def save_investigation(self, user_id, filename, summary, result):
        blob = zlib.compress(json.dumps(result, separators=(",", ":")).encode("utf-8"), 6)
        return self._exec("INSERT INTO investigations (user_id, created_at, filename, summary, result) VALUES (?, ?, ?, ?, ?)",
                          (user_id, time.time(), filename, json.dumps(summary), blob))

    def count_investigations(self, user_id):
        return self._q("SELECT COUNT(*) AS n FROM investigations WHERE user_id = ?", (user_id,), one=True)["n"]

    def investigations(self, user_id, limit=None):
        sql = "SELECT id, created_at, filename, summary FROM investigations WHERE user_id = ? ORDER BY created_at DESC, id DESC"
        rows = self._q(sql + (" LIMIT ?" if limit else ""), (user_id, limit) if limit else (user_id,))
        return [{"id": r["id"], "created_at": r["created_at"], "filename": r["filename"], **json.loads(r["summary"])}
                for r in rows]

    def investigation(self, user_id, inv_id):
        row = self._q("SELECT id, created_at, result FROM investigations WHERE id = ? AND user_id = ?",
                      (inv_id, user_id), one=True)
        if row is None:
            return None
        result = json.loads(zlib.decompress(row["result"]))
        return {**result, "id": row["id"], "created_at": row["created_at"]}

    def delete_investigation(self, user_id, inv_id):
        with self._lock, self._db:
            return self._db.execute("DELETE FROM investigations WHERE id = ? AND user_id = ?", (inv_id, user_id)).rowcount

    # ------------------------------------------------------------------ trusted addresses
    # Addresses an account trusts (an office NAT, its own proxy, a monitoring service). Visitors from them are
    # still scored and shown, but never blocked or rate-limited for that account (see backend/app/trusted.py).
    def trusted(self, user_id):
        rows = self._q("SELECT id, address, note, created_at FROM trusted_addresses WHERE user_id = ? ORDER BY created_at, id",
                       (user_id,))
        return [dict(r) for r in rows]

    def count_trusted(self, user_id):
        return self._q("SELECT COUNT(*) AS n FROM trusted_addresses WHERE user_id = ?", (user_id,), one=True)["n"]

    def add_trusted(self, user_id, address, note=""):
        """Returns the new id, or None when this account already trusts that address."""
        try:
            return self._exec("INSERT INTO trusted_addresses (user_id, address, note, created_at) VALUES (?, ?, ?, ?)",
                              (user_id, address, note, time.time()))
        except sqlite3.IntegrityError:
            return None

    def delete_trusted(self, user_id, item_id):
        with self._lock, self._db:
            return self._db.execute("DELETE FROM trusted_addresses WHERE id = ? AND user_id = ?", (item_id, user_id)).rowcount
