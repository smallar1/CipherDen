"""
db.py — CipherDen vault database layer.

Manages SQLite connection lifecycle and schema migrations.
All datetime values are stored as TEXT in ISO 8601 UTC format.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

# ---------------------------------------------------------------------------
# Schema migrations
# Each entry is a (version, sql) tuple applied in order.
# Never edit an existing migration — add a new one instead.
# ---------------------------------------------------------------------------

_MIGRATIONS: list[tuple[int, str]] = [
    (
        1,
        """
        CREATE TABLE IF NOT EXISTS schema_version (
            version     INTEGER NOT NULL
        );

        INSERT INTO schema_version (version) VALUES (0);

        CREATE TABLE IF NOT EXISTS entries (
            id           TEXT    PRIMARY KEY NOT NULL,  -- UUID v4 as text
            title        TEXT    NOT NULL,
            username     TEXT    NOT NULL DEFAULT '',
            password_enc BLOB    NOT NULL,              -- AES-GCM ciphertext bytes
            url          TEXT             DEFAULT NULL,
            notes        TEXT             DEFAULT NULL,
            created_at   TEXT    NOT NULL,              -- ISO 8601 UTC e.g. 2025-01-01T00:00:00Z
            updated_at   TEXT    NOT NULL               -- ISO 8601 UTC, updated on every write
        );

        CREATE INDEX IF NOT EXISTS idx_entries_title ON entries (title);
        """,
    ),
    (
        2,
        """
        CREATE TABLE IF NOT EXISTS vault_config (
            id          INTEGER PRIMARY KEY CHECK (id = 1),  -- enforces single row
            salt_hex    TEXT    NOT NULL,                    -- 32-byte Argon2id salt, hex-encoded
            argon2_t    INTEGER NOT NULL,                    -- time cost
            argon2_m    INTEGER NOT NULL,                    -- memory cost (KiB)
            argon2_p    INTEGER NOT NULL                     -- parallelism
        );
        """,
    ),
    (
        3,
        """
        ALTER TABLE vault_config ADD COLUMN sentinel_enc BLOB NOT NULL DEFAULT x'';
        """,
    ),
]


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _get_schema_version(conn: sqlite3.Connection) -> int:
    """Return the current schema version, or -1 if the version table does not exist."""
    row = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='schema_version'"
    ).fetchone()
    if row is None:
        return -1
    row = conn.execute("SELECT version FROM schema_version").fetchone()
    return row[0] if row else -1


def _set_schema_version(conn: sqlite3.Connection, version: int) -> None:
    conn.execute("UPDATE schema_version SET version = ?", (version,))


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def run_migrations(conn: sqlite3.Connection) -> None:
    """
    Apply any pending migrations to the database in order.

    Safe to call on every startup — already-applied migrations are skipped.
    Each migration runs in its own transaction; a failure rolls back only
    that migration and raises, leaving previous migrations intact.
    """
    current_version = _get_schema_version(conn)

    for version, sql in _MIGRATIONS:
        if version <= current_version:
            continue

        with conn:  # transaction: commits on success, rolls back on exception
            conn.executescript(sql)
            _set_schema_version(conn, version)


def open_db(path: Path) -> sqlite3.Connection:
    """
    Open (or create) the SQLite database at *path* and run pending migrations.

    WAL mode is enabled for safe concurrent reads from the CLI and backend.
    Foreign keys are enforced at the connection level.
    """
    conn = sqlite3.connect(path, check_same_thread=False)
    conn.row_factory = sqlite3.Row

    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")

    run_migrations(conn)
    return conn
