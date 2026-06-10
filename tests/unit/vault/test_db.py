"""
tests/unit/vault/test_db.py — Unit tests for the vault database layer.

Tests cover:
- Schema correctness (columns, types, constraints, indexes)
- Migrations runner (fresh DB, idempotency, version tracking)
- open_db pragmas (WAL, foreign keys)
- Behavioural constraints (NOT NULL, PRIMARY KEY, BLOB round-trip)
- _get_schema_version internal helper
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

import pytest

from cipherden.vault.db import (
    _MIGRATIONS,
    _get_schema_version,
    open_db,
    run_migrations,
)

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def tmp_db_path(tmp_path: Path) -> Path:
    """Return a path to a non-existent DB file in a temp directory."""
    return tmp_path / "test_vault.db"


@pytest.fixture
def conn(tmp_db_path: Path) -> sqlite3.Connection:
    """Open a fully migrated in-memory-like DB via open_db and close after test."""
    c = open_db(tmp_db_path)
    yield c
    c.close()


@pytest.fixture
def bare_conn(tmp_db_path: Path) -> sqlite3.Connection:
    """Raw sqlite3 connection with no migrations applied — for testing the runner itself."""
    c = sqlite3.connect(tmp_db_path)
    c.row_factory = sqlite3.Row
    yield c
    c.close()


# ---------------------------------------------------------------------------
# _get_schema_version
# ---------------------------------------------------------------------------


class TestGetSchemaVersion:
    def test_returns_minus_one_on_empty_db(self, bare_conn: sqlite3.Connection) -> None:
        assert _get_schema_version(bare_conn) == -1

    def test_returns_correct_version_after_migration(self, conn: sqlite3.Connection) -> None:
        assert _get_schema_version(conn) == len(_MIGRATIONS)


# ---------------------------------------------------------------------------
# run_migrations
# ---------------------------------------------------------------------------


class TestRunMigrations:
    def test_applies_all_migrations_to_fresh_db(self, bare_conn: sqlite3.Connection) -> None:
        run_migrations(bare_conn)
        assert _get_schema_version(bare_conn) == len(_MIGRATIONS)

    def test_idempotent_on_already_migrated_db(self, conn: sqlite3.Connection) -> None:
        """Calling run_migrations a second time must be a no-op."""
        run_migrations(conn)
        run_migrations(conn)
        assert _get_schema_version(conn) == len(_MIGRATIONS)

    def test_version_matches_migration_count(self, conn: sqlite3.Connection) -> None:
        assert _get_schema_version(conn) == len(_MIGRATIONS)

    def test_schema_version_table_has_single_row(self, conn: sqlite3.Connection) -> None:
        rows = conn.execute("SELECT COUNT(*) FROM schema_version").fetchone()[0]
        assert rows == 1


# ---------------------------------------------------------------------------
# open_db — pragmas
# ---------------------------------------------------------------------------


class TestOpenDb:
    def test_returns_connection(self, tmp_db_path: Path) -> None:
        c = open_db(tmp_db_path)
        assert isinstance(c, sqlite3.Connection)
        c.close()

    def test_wal_mode_enabled(self, conn: sqlite3.Connection) -> None:
        mode = conn.execute("PRAGMA journal_mode").fetchone()[0]
        assert mode == "wal"

    def test_foreign_keys_enabled(self, conn: sqlite3.Connection) -> None:
        fk = conn.execute("PRAGMA foreign_keys").fetchone()[0]
        assert fk == 1

    def test_row_factory_is_sqlite_row(self, conn: sqlite3.Connection) -> None:
        assert conn.row_factory is sqlite3.Row

    def test_creates_db_file_on_disk(self, tmp_db_path: Path) -> None:
        assert not tmp_db_path.exists()
        c = open_db(tmp_db_path)
        c.close()
        assert tmp_db_path.exists()

    def test_reopening_same_db_does_not_raise(self, tmp_db_path: Path) -> None:
        c1 = open_db(tmp_db_path)
        c1.close()
        c2 = open_db(tmp_db_path)
        c2.close()


# ---------------------------------------------------------------------------
# entries table — schema correctness
# ---------------------------------------------------------------------------


class TestEntriesSchema:
    def _col_map(self, conn: sqlite3.Connection) -> dict:
        """Return {col_name: {type, notnull, pk, dflt_value}} for the entries table."""
        rows = conn.execute("PRAGMA table_info(entries)").fetchall()
        return {
            r["name"]: {
                "type": r["type"],
                "notnull": bool(r["notnull"]),
                "pk": bool(r["pk"]),
                "dflt_value": r["dflt_value"],
            }
            for r in rows
        }

    def test_all_columns_present(self, conn: sqlite3.Connection) -> None:
        expected = {
            "id",
            "title",
            "username",
            "password_enc",
            "url",
            "notes",
            "created_at",
            "updated_at",
        }
        assert set(self._col_map(conn).keys()) == expected

    def test_id_is_primary_key(self, conn: sqlite3.Connection) -> None:
        assert self._col_map(conn)["id"]["pk"] is True

    def test_id_is_text_type(self, conn: sqlite3.Connection) -> None:
        assert self._col_map(conn)["id"]["type"] == "TEXT"

    def test_password_enc_is_blob(self, conn: sqlite3.Connection) -> None:
        assert self._col_map(conn)["password_enc"]["type"] == "BLOB"

    def test_title_not_null(self, conn: sqlite3.Connection) -> None:
        assert self._col_map(conn)["title"]["notnull"] is True

    def test_username_not_null(self, conn: sqlite3.Connection) -> None:
        assert self._col_map(conn)["username"]["notnull"] is True

    def test_username_default_is_empty_string(self, conn: sqlite3.Connection) -> None:
        assert self._col_map(conn)["username"]["dflt_value"] == "''"

    def test_password_enc_not_null(self, conn: sqlite3.Connection) -> None:
        assert self._col_map(conn)["password_enc"]["notnull"] is True

    def test_created_at_not_null(self, conn: sqlite3.Connection) -> None:
        assert self._col_map(conn)["created_at"]["notnull"] is True

    def test_updated_at_not_null(self, conn: sqlite3.Connection) -> None:
        assert self._col_map(conn)["updated_at"]["notnull"] is True

    def test_url_is_nullable(self, conn: sqlite3.Connection) -> None:
        assert self._col_map(conn)["url"]["notnull"] is False

    def test_notes_is_nullable(self, conn: sqlite3.Connection) -> None:
        assert self._col_map(conn)["notes"]["notnull"] is False

    def test_title_index_exists(self, conn: sqlite3.Connection) -> None:
        indexes = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='index' AND tbl_name='entries'"
        ).fetchall()
        names = [r["name"] for r in indexes]
        assert "idx_entries_title" in names


# ---------------------------------------------------------------------------
# entries table — behavioural / constraint tests
# ---------------------------------------------------------------------------


class TestEntriesConstraints:
    def _insert(self, conn: sqlite3.Connection, **overrides) -> None:
        defaults = {
            "id": "00000000-0000-0000-0000-000000000001",
            "title": "Test Entry",
            "username": "user@example.com",
            "password_enc": b"\xde\xad\xbe\xef",
            "url": "https://example.com",
            "notes": None,
            "created_at": "2025-01-01T00:00:00.000Z",
            "updated_at": "2025-01-01T00:00:00.000Z",
        }
        defaults.update(overrides)
        conn.execute(
            """
            INSERT INTO entries
                (id, title, username, password_enc, url, notes, created_at, updated_at)
            VALUES
                (:id, :title, :username, :password_enc, :url, :notes, :created_at, :updated_at)
            """,
            defaults,
        )
        conn.commit()

    def test_valid_insert_succeeds(self, conn: sqlite3.Connection) -> None:
        self._insert(conn)
        row = conn.execute("SELECT * FROM entries").fetchone()
        assert row["id"] == "00000000-0000-0000-0000-000000000001"

    def test_password_enc_round_trips_as_bytes(self, conn: sqlite3.Connection) -> None:
        payload = bytes(range(32))
        self._insert(conn, password_enc=payload)
        row = conn.execute("SELECT password_enc FROM entries").fetchone()
        assert row["password_enc"] == payload

    def test_null_title_raises(self, conn: sqlite3.Connection) -> None:
        with pytest.raises(sqlite3.IntegrityError):
            self._insert(conn, title=None)

    def test_null_password_enc_raises(self, conn: sqlite3.Connection) -> None:
        with pytest.raises(sqlite3.IntegrityError):
            self._insert(conn, password_enc=None)

    def test_null_created_at_raises(self, conn: sqlite3.Connection) -> None:
        with pytest.raises(sqlite3.IntegrityError):
            self._insert(conn, created_at=None)

    def test_null_updated_at_raises(self, conn: sqlite3.Connection) -> None:
        with pytest.raises(sqlite3.IntegrityError):
            self._insert(conn, updated_at=None)

    def test_duplicate_id_raises(self, conn: sqlite3.Connection) -> None:
        self._insert(conn)
        with pytest.raises(sqlite3.IntegrityError):
            self._insert(conn)

    def test_url_can_be_null(self, conn: sqlite3.Connection) -> None:
        self._insert(conn, url=None)
        row = conn.execute("SELECT url FROM entries").fetchone()
        assert row["url"] is None

    def test_notes_can_be_null(self, conn: sqlite3.Connection) -> None:
        self._insert(conn, notes=None)
        row = conn.execute("SELECT notes FROM entries").fetchone()
        assert row["notes"] is None

    def test_username_defaults_to_empty_string(self, conn: sqlite3.Connection) -> None:
        conn.execute(
            """
            INSERT INTO entries (id, title, password_enc, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?)
            """,
            (
                "00000000-0000-0000-0000-000000000002",
                "No Username Entry",
                b"\x00\x01",
                "2025-01-01T00:00:00.000Z",
                "2025-01-01T00:00:00.000Z",
            ),
        )
        conn.commit()
        row = conn.execute(
            "SELECT username FROM entries WHERE id = ?", ("00000000-0000-0000-0000-000000000002",)
        ).fetchone()
        assert row["username"] == ""


# ---------------------------------------------------------------------------
# vault_config table — schema correctness
# ---------------------------------------------------------------------------


class TestVaultConfigSchema:
    def _col_map(self, conn: sqlite3.Connection) -> dict:
        rows = conn.execute("PRAGMA table_info(vault_config)").fetchall()
        return {
            r["name"]: {
                "type": r["type"],
                "notnull": bool(r["notnull"]),
                "pk": bool(r["pk"]),
            }
            for r in rows
        }

    def test_vault_config_table_exists(self, conn: sqlite3.Connection) -> None:
        row = conn.execute(
            "SELECT name FROM sqlite_master WHERE type='table' AND name='vault_config'"
        ).fetchone()
        assert row is not None

    def test_all_columns_present(self, conn: sqlite3.Connection) -> None:
        expected = {"id", "salt_hex", "argon2_t", "argon2_m", "argon2_p"}
        assert set(self._col_map(conn).keys()) == expected

    def test_id_is_primary_key(self, conn: sqlite3.Connection) -> None:
        assert self._col_map(conn)["id"]["pk"] is True

    def test_salt_hex_not_null(self, conn: sqlite3.Connection) -> None:
        assert self._col_map(conn)["salt_hex"]["notnull"] is True

    def test_argon2_params_not_null(self, conn: sqlite3.Connection) -> None:
        cols = self._col_map(conn)
        assert cols["argon2_t"]["notnull"] is True
        assert cols["argon2_m"]["notnull"] is True
        assert cols["argon2_p"]["notnull"] is True


# ---------------------------------------------------------------------------
# vault_config table — single-row constraint
# ---------------------------------------------------------------------------


class TestVaultConfigConstraints:
    def _insert(self, conn: sqlite3.Connection, row_id: int = 1) -> None:
        conn.execute(
            """
            INSERT INTO vault_config (id, salt_hex, argon2_t, argon2_m, argon2_p)
            VALUES (?, ?, ?, ?, ?)
            """,
            (row_id, "aa" * 32, 3, 65536, 4),
        )
        conn.commit()

    def test_valid_insert_succeeds(self, conn: sqlite3.Connection) -> None:
        self._insert(conn)
        row = conn.execute("SELECT id FROM vault_config").fetchone()
        assert row["id"] == 1

    def test_second_row_with_different_id_raises(self, conn: sqlite3.Connection) -> None:
        """CHECK (id = 1) must reject any row where id != 1."""
        self._insert(conn)
        with pytest.raises(sqlite3.IntegrityError):
            self._insert(conn, row_id=2)

    def test_duplicate_id_raises(self, conn: sqlite3.Connection) -> None:
        self._insert(conn)
        with pytest.raises(sqlite3.IntegrityError):
            self._insert(conn, row_id=1)
