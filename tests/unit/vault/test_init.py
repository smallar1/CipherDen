"""
tests/unit/vault/test_init.py — Unit tests for vault initialisation.

Tests cover:
- vault_init creates the DB file and vault_config row
- vault_init returns a 32-byte key
- vault_init is a no-op (raises) on an already-initialised vault
- vault_config row contains correct Argon2 params
- salt is stored as a 64-char hex string (32 bytes)
- derived key matches re-derivation from stored salt
- is_initialised returns correct state
- vault directory is created if it does not exist
"""

from __future__ import annotations

from pathlib import Path

import pytest

from cipherden.vault.crypto import ARGON2_M, ARGON2_P, ARGON2_T, derive_key
from cipherden.vault.db import open_db
from cipherden.vault.init import VaultAlreadyExistsError, is_initialised, vault_init

PASSWORD = "correct-horse-battery-staple"  # pragma: allowlist secret


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def vault_path(tmp_path: Path) -> Path:
    return tmp_path / "test_vault.db"


@pytest.fixture
def initialised_vault(vault_path: Path) -> tuple[Path, bytes]:
    key = vault_init(PASSWORD, vault_path=vault_path)
    return vault_path, key


# ---------------------------------------------------------------------------
# vault_init — happy path
# ---------------------------------------------------------------------------


class TestVaultInit:
    def test_returns_bytes(self, vault_path: Path) -> None:
        key = vault_init(PASSWORD, vault_path=vault_path)
        assert isinstance(key, bytes)

    def test_returns_32_byte_key(self, vault_path: Path) -> None:
        key = vault_init(PASSWORD, vault_path=vault_path)
        assert len(key) == 32

    def test_creates_db_file(self, vault_path: Path) -> None:
        assert not vault_path.exists()
        vault_init(PASSWORD, vault_path=vault_path)
        assert vault_path.exists()

    def test_creates_parent_directory(self, tmp_path: Path) -> None:
        nested_path = tmp_path / "nested" / "dir" / "vault.db"
        assert not nested_path.parent.exists()
        vault_init(PASSWORD, vault_path=nested_path)
        assert nested_path.exists()

    def test_vault_config_row_exists(self, vault_path: Path) -> None:
        vault_init(PASSWORD, vault_path=vault_path)
        conn = open_db(vault_path)
        row = conn.execute("SELECT * FROM vault_config").fetchone()
        conn.close()
        assert row is not None

    def test_vault_config_id_is_1(self, vault_path: Path) -> None:
        vault_init(PASSWORD, vault_path=vault_path)
        conn = open_db(vault_path)
        row = conn.execute("SELECT id FROM vault_config").fetchone()
        conn.close()
        assert row["id"] == 1

    def test_salt_hex_is_64_chars(self, vault_path: Path) -> None:
        vault_init(PASSWORD, vault_path=vault_path)
        conn = open_db(vault_path)
        row = conn.execute("SELECT salt_hex FROM vault_config").fetchone()
        conn.close()
        assert len(row["salt_hex"]) == 64  # 32 bytes * 2 hex chars

    def test_salt_hex_is_valid_hex(self, vault_path: Path) -> None:
        vault_init(PASSWORD, vault_path=vault_path)
        conn = open_db(vault_path)
        row = conn.execute("SELECT salt_hex FROM vault_config").fetchone()
        conn.close()
        assert bytes.fromhex(row["salt_hex"]) is not None

    def test_argon2_params_stored_correctly(self, vault_path: Path) -> None:
        vault_init(PASSWORD, vault_path=vault_path)
        conn = open_db(vault_path)
        row = conn.execute("SELECT argon2_t, argon2_m, argon2_p FROM vault_config").fetchone()
        conn.close()
        assert row["argon2_t"] == ARGON2_T
        assert row["argon2_m"] == ARGON2_M
        assert row["argon2_p"] == ARGON2_P

    def test_returned_key_matches_rederivation(self, vault_path: Path) -> None:
        key = vault_init(PASSWORD, vault_path=vault_path)
        conn = open_db(vault_path)
        row = conn.execute(
            "SELECT salt_hex, argon2_t, argon2_m, argon2_p FROM vault_config"
        ).fetchone()
        conn.close()
        salt = bytes.fromhex(row["salt_hex"])
        rederived = derive_key(
            PASSWORD, salt, t=row["argon2_t"], m=row["argon2_m"], p=row["argon2_p"]
        )
        assert key == rederived

    def test_different_passwords_produce_different_keys(self, tmp_path: Path) -> None:
        key1 = vault_init(PASSWORD, vault_path=tmp_path / "v1.db")
        key2 = vault_init(  # pragma: allowlist secret
            "different-password-xyz-123", vault_path=tmp_path / "v2.db"
        )
        assert key1 != key2


# ---------------------------------------------------------------------------
# vault_init — already initialised
# ---------------------------------------------------------------------------


class TestVaultInitAlreadyExists:
    def test_raises_vault_already_exists_error(self, initialised_vault: tuple) -> None:
        vault_path, _ = initialised_vault
        with pytest.raises(VaultAlreadyExistsError):
            vault_init(PASSWORD, vault_path=vault_path)

    def test_does_not_overwrite_existing_salt(self, initialised_vault: tuple) -> None:
        vault_path, _ = initialised_vault
        conn = open_db(vault_path)
        original_salt = conn.execute("SELECT salt_hex FROM vault_config").fetchone()["salt_hex"]
        conn.close()

        with pytest.raises(VaultAlreadyExistsError):
            vault_init(  # pragma: allowlist secret
                "different-password-xyz-123", vault_path=vault_path
            )

        conn = open_db(vault_path)
        salt_after = conn.execute("SELECT salt_hex FROM vault_config").fetchone()["salt_hex"]
        conn.close()
        assert original_salt == salt_after


# ---------------------------------------------------------------------------
# is_initialised
# ---------------------------------------------------------------------------


class TestIsInitialised:
    def test_returns_false_when_file_does_not_exist(self, vault_path: Path) -> None:
        assert not vault_path.exists()
        assert is_initialised(vault_path=vault_path) is False

    def test_returns_false_on_empty_db(self, vault_path: Path) -> None:
        # DB exists but vault_init was never called.
        conn = open_db(vault_path)
        conn.close()
        assert is_initialised(vault_path=vault_path) is False

    def test_returns_true_after_init(self, vault_path: Path) -> None:
        vault_init(PASSWORD, vault_path=vault_path)
        assert is_initialised(vault_path=vault_path) is True
