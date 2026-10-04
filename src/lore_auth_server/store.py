"""SQLite storage for users, repository grants, repositories and API keys."""

from __future__ import annotations

import hashlib
import hmac
import re
import secrets
import sqlite3
import threading
import time
from dataclasses import dataclass
from pathlib import Path

ALL_REPOSITORIES = "urc-*"
USER_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.@-]{0,63}$")
REPOSITORY_ID_RE = re.compile(r"^[0-9a-f]{32}$")

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    name          TEXT PRIMARY KEY,
    display_name  TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    is_admin      INTEGER NOT NULL DEFAULT 0,
    disabled      INTEGER NOT NULL DEFAULT 0,
    created_at    INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS repositories (
    resource_id TEXT PRIMARY KEY,
    name        TEXT NOT NULL,
    creator     TEXT NOT NULL DEFAULT '',
    created_at  INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS grants (
    user_name   TEXT NOT NULL REFERENCES users(name) ON DELETE CASCADE,
    resource_id TEXT NOT NULL,
    PRIMARY KEY (user_name, resource_id)
);
CREATE TABLE IF NOT EXISTS api_keys (
    key_hash   TEXT PRIMARY KEY,
    user_name  TEXT NOT NULL REFERENCES users(name) ON DELETE CASCADE,
    label      TEXT NOT NULL DEFAULT '',
    created_at INTEGER NOT NULL
);
"""

# scrypt parameters: about 16 MiB of memory per hash.
_SCRYPT_N, _SCRYPT_R, _SCRYPT_P = 2**14, 8, 1


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(password.encode(), salt=salt, n=_SCRYPT_N, r=_SCRYPT_R, p=_SCRYPT_P)
    return f"scrypt${_SCRYPT_N}${_SCRYPT_R}${_SCRYPT_P}${salt.hex()}${digest.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        scheme, n, r, p, salt, digest = stored.split("$")
    except ValueError:
        return False
    if scheme != "scrypt":
        return False
    candidate = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt), n=int(n), r=int(r), p=int(p))
    return hmac.compare_digest(candidate.hex(), digest)


def _hash_api_key(key: str) -> str:
    # API keys are long random strings, so a plain digest is sufficient.
    return hashlib.sha256(key.encode()).hexdigest()


def resource_for(repository: str) -> str:
    """Map a repository ID or '*' to a Lore resource ID (urc-<id> or urc-*)."""
    if repository in ("*", "all", ALL_REPOSITORIES):
        return ALL_REPOSITORIES
    if repository.startswith("urc-"):
        repository = repository[4:]
    if not REPOSITORY_ID_RE.match(repository):
        raise ValueError(f"not a repository ID: {repository}")
    return f"urc-{repository}"


@dataclass
class User:
    name: str
    display_name: str
    is_admin: bool
    disabled: bool


@dataclass
class Repository:
    resource_id: str
    name: str
    creator: str


class Store:
    def __init__(self, path: Path):
        path.parent.mkdir(parents=True, exist_ok=True)
        self._db = sqlite3.connect(path, check_same_thread=False, isolation_level=None)
        self._db.row_factory = sqlite3.Row
        self._lock = threading.Lock()
        with self._lock:
            self._db.execute("PRAGMA foreign_keys = ON")
            self._db.execute("PRAGMA journal_mode = WAL")
            self._db.executescript(SCHEMA)

    def close(self) -> None:
        with self._lock:
            self._db.close()

    def _query(self, sql: str, args: tuple = ()) -> list[sqlite3.Row]:
        with self._lock:
            return self._db.execute(sql, args).fetchall()

    def _execute(self, sql: str, args: tuple = ()) -> int:
        with self._lock:
            return self._db.execute(sql, args).rowcount

    # Users

    def add_user(self, name: str, password: str, display_name: str = "", is_admin: bool = False) -> None:
        if not USER_NAME_RE.match(name):
            raise ValueError("user name may contain letters, digits and _ . @ - (max 64 chars)")
        if self.get_user(name):
            raise ValueError(f"user {name} already exists")
        self._execute(
            "INSERT INTO users (name, display_name, password_hash, is_admin, created_at) VALUES (?, ?, ?, ?, ?)",
            (name, display_name or name, hash_password(password), int(is_admin), int(time.time())),
        )

    def get_user(self, name: str) -> User | None:
        rows = self._query("SELECT name, display_name, is_admin, disabled FROM users WHERE name = ?", (name,))
        if not rows:
            return None
        r = rows[0]
        return User(r["name"], r["display_name"], bool(r["is_admin"]), bool(r["disabled"]))

    def list_users(self) -> list[User]:
        rows = self._query("SELECT name, display_name, is_admin, disabled FROM users ORDER BY name")
        return [User(r["name"], r["display_name"], bool(r["is_admin"]), bool(r["disabled"])) for r in rows]

    def check_password(self, name: str, password: str) -> User | None:
        rows = self._query("SELECT password_hash FROM users WHERE name = ?", (name,))
        stored = rows[0]["password_hash"] if rows else hash_password("timing-equalizer")
        ok = verify_password(password, stored)
        user = self.get_user(name) if rows else None
        if ok and user and not user.disabled:
            return user
        return None

    def set_password(self, name: str, password: str) -> None:
        if not self._execute("UPDATE users SET password_hash = ? WHERE name = ?", (hash_password(password), name)):
            raise ValueError(f"no such user: {name}")

    def set_admin(self, name: str, is_admin: bool) -> None:
        if not self._execute("UPDATE users SET is_admin = ? WHERE name = ?", (int(is_admin), name)):
            raise ValueError(f"no such user: {name}")

    def set_disabled(self, name: str, disabled: bool) -> None:
        if not self._execute("UPDATE users SET disabled = ? WHERE name = ?", (int(disabled), name)):
            raise ValueError(f"no such user: {name}")

    def remove_user(self, name: str) -> None:
        if not self._execute("DELETE FROM users WHERE name = ?", (name,)):
            raise ValueError(f"no such user: {name}")

    # Repositories

    def add_repository(self, resource_id: str, name: str, creator: str = "") -> None:
        self._execute(
            "INSERT INTO repositories (resource_id, name, creator, created_at) VALUES (?, ?, ?, ?) "
            "ON CONFLICT(resource_id) DO UPDATE SET name = excluded.name",
            (resource_id, name, creator, int(time.time())),
        )

    def remove_repository(self, resource_id: str) -> None:
        self._execute("DELETE FROM repositories WHERE resource_id = ?", (resource_id,))
        self._execute("DELETE FROM grants WHERE resource_id = ?", (resource_id,))

    def get_repository(self, resource_id: str) -> Repository | None:
        rows = self._query("SELECT resource_id, name, creator FROM repositories WHERE resource_id = ?", (resource_id,))
        return Repository(rows[0]["resource_id"], rows[0]["name"], rows[0]["creator"]) if rows else None

    def list_repositories(self) -> list[Repository]:
        rows = self._query("SELECT resource_id, name, creator FROM repositories ORDER BY name")
        return [Repository(r["resource_id"], r["name"], r["creator"]) for r in rows]

    def resolve_repository(self, name_or_id: str) -> str:
        """Resource ID for a repository name, repository ID or '*'."""
        try:
            return resource_for(name_or_id)
        except ValueError:
            rows = self._query("SELECT resource_id FROM repositories WHERE name = ?", (name_or_id,))
            if len(rows) == 1:
                return rows[0]["resource_id"]
            if len(rows) > 1:
                raise ValueError(f"repository name {name_or_id} is ambiguous, use its ID") from None
            raise ValueError(f"unknown repository: {name_or_id} (use its 32-character ID)") from None

    # Grants

    def grant(self, user: str, resource_id: str) -> None:
        if not self.get_user(user):
            raise ValueError(f"no such user: {user}")
        self._execute("INSERT OR IGNORE INTO grants (user_name, resource_id) VALUES (?, ?)", (user, resource_id))

    def revoke(self, user: str, resource_id: str) -> None:
        self._execute("DELETE FROM grants WHERE user_name = ? AND resource_id = ?", (user, resource_id))

    def grants_of(self, user: str) -> list[str]:
        rows = self._query("SELECT resource_id FROM grants WHERE user_name = ? ORDER BY resource_id", (user,))
        return [r["resource_id"] for r in rows]

    # API keys

    def create_api_key(self, user: str, label: str = "") -> str:
        if not self.get_user(user):
            raise ValueError(f"no such user: {user}")
        key = "lak_" + secrets.token_urlsafe(32)
        self._execute(
            "INSERT INTO api_keys (key_hash, user_name, label, created_at) VALUES (?, ?, ?, ?)",
            (_hash_api_key(key), user, label, int(time.time())),
        )
        return key

    def user_for_api_key(self, key: str) -> User | None:
        rows = self._query("SELECT user_name FROM api_keys WHERE key_hash = ?", (_hash_api_key(key),))
        if not rows:
            return None
        user = self.get_user(rows[0]["user_name"])
        return user if user and not user.disabled else None

    def list_api_keys(self, user: str) -> list[tuple[str, str, int]]:
        rows = self._query(
            "SELECT key_hash, label, created_at FROM api_keys WHERE user_name = ? ORDER BY created_at", (user,)
        )
        return [(r["key_hash"][:12], r["label"], r["created_at"]) for r in rows]

    def revoke_api_keys(self, user: str) -> int:
        return self._execute("DELETE FROM api_keys WHERE user_name = ?", (user,))
