"""
tests/unit/vault/test_session.py — Unit tests for VaultSession.

Tests cover:
- unlock() returns a VaultSession with a 32-byte key
- unlock() raises WrongPasswordError on wrong password
- unlock() raises VaultNotInitialisedError on uninitialised vault
- lock() zeroes the key buffer
- key property raises VaultLockedError after lock()
- is_locked reflects state correctly
- context manager calls lock() on exit
- context manager calls lock() on exception
"""

from __future__ import annotations

from pathlib import Path

import pytest

from cipherden.vault.db import open_db
from cipherden.vault.init import vault_init
from cipherden.vault.session import (
    VaultLockedError,
    VaultNotInitialisedError,
    VaultSession,
    WrongPasswordError,
)

PASSWORD = "correct-horse-battery-staple"  # pragma: allowlist secret
WRONG_PASSWORD = "wrong-password-xyz-123"  # pragma: allowlist secret


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


@pytest.fixture
def vault_path(tmp_path: Path) -> Path:
    return tmp_path / "test_vault.db"


@pytest.fixture
def initialised_vault(vault_path: Path) -> Path:
    vault_init(PASSWORD, vault_path=vault_path)
    return vault_path


# ---------------------------------------------------------------------------
# VaultSession.unlock — happy path
# ---------------------------------------------------------------------------


class TestVaultSessionUnlock:
    def test_returns_vault_session(self, initialised_vault: Path) -> None:
        session = VaultSession.unlock(PASSWORD, vault_path=initialised_vault)
        session.lock()
        assert isinstance(session, VaultSession)

    def test_key_is_bytearray(self, initialised_vault: Path) -> None:
        session = VaultSession.unlock(PASSWORD, vault_path=initialised_vault)
        assert isinstance(session.key, bytearray)
        session.lock()

    def test_key_is_32_bytes(self, initialised_vault: Path) -> None:
        session = VaultSession.unlock(PASSWORD, vault_path=initialised_vault)
        assert len(session.key) == 32
        session.lock()

    def test_is_not_locked_after_unlock(self, initialised_vault: Path) -> None:
        session = VaultSession.unlock(PASSWORD, vault_path=initialised_vault)
        assert session.is_locked is False
        session.lock()

    def test_key_matches_rederivation(self, initialised_vault: Path) -> None:
        from cipherden.vault.crypto import derive_key

        session = VaultSession.unlock(PASSWORD, vault_path=initialised_vault)
        conn = open_db(initialised_vault)
        row = conn.execute(
            "SELECT salt_hex, argon2_t, argon2_m, argon2_p FROM vault_config"
        ).fetchone()
        conn.close()
        salt = bytes.fromhex(row["salt_hex"])
        rederived = derive_key(
            PASSWORD, salt, t=row["argon2_t"], m=row["argon2_m"], p=row["argon2_p"]
        )
        assert session.key == rederived
        session.lock()


# ---------------------------------------------------------------------------
# VaultSession.unlock — wrong password
# ---------------------------------------------------------------------------


class TestVaultSessionWrongPassword:
    def test_raises_wrong_password_error(self, initialised_vault: Path) -> None:
        with pytest.raises(WrongPasswordError):
            VaultSession.unlock(WRONG_PASSWORD, vault_path=initialised_vault)

    def test_wrong_password_does_not_return_session(self, initialised_vault: Path) -> None:
        result = None
        try:
            result = VaultSession.unlock(WRONG_PASSWORD, vault_path=initialised_vault)
        except WrongPasswordError:
            pass
        assert result is None


# ---------------------------------------------------------------------------
# VaultSession.unlock — not initialised
# ---------------------------------------------------------------------------


class TestVaultSessionNotInitialised:
    def test_raises_vault_not_initialised_error(self, vault_path: Path) -> None:
        # vault_path exists as an empty DB (open_db creates it) but no vault_config row
        open_db(vault_path).close()
        with pytest.raises(VaultNotInitialisedError):
            VaultSession.unlock(PASSWORD, vault_path=vault_path)

    def test_raises_on_missing_file(self, tmp_path: Path) -> None:
        missing = tmp_path / "nonexistent.db"
        # open_db will create the file but leave vault_config empty
        with pytest.raises(VaultNotInitialisedError):
            VaultSession.unlock(PASSWORD, vault_path=missing)


# ---------------------------------------------------------------------------
# lock()
# ---------------------------------------------------------------------------


class TestVaultSessionLock:
    def test_is_locked_after_lock(self, initialised_vault: Path) -> None:
        session = VaultSession.unlock(PASSWORD, vault_path=initialised_vault)
        session.lock()
        assert session.is_locked is True

    def test_key_is_zeroed_after_lock(self, initialised_vault: Path) -> None:
        session = VaultSession.unlock(PASSWORD, vault_path=initialised_vault)
        session.lock()
        assert all(b == 0 for b in session._key)

    def test_key_property_raises_after_lock(self, initialised_vault: Path) -> None:
        session = VaultSession.unlock(PASSWORD, vault_path=initialised_vault)
        session.lock()
        with pytest.raises(VaultLockedError):
            _ = session.key

    def test_double_lock_does_not_raise(self, initialised_vault: Path) -> None:
        session = VaultSession.unlock(PASSWORD, vault_path=initialised_vault)
        session.lock()
        session.lock()  # must not raise


# ---------------------------------------------------------------------------
# Context manager
# ---------------------------------------------------------------------------


class TestVaultSessionContextManager:
    def test_context_manager_returns_session(self, initialised_vault: Path) -> None:
        with VaultSession.unlock(PASSWORD, vault_path=initialised_vault) as session:
            assert isinstance(session, VaultSession)

    def test_key_accessible_inside_context(self, initialised_vault: Path) -> None:
        with VaultSession.unlock(PASSWORD, vault_path=initialised_vault) as session:
            assert len(session.key) == 32

    def test_session_locked_after_context_exits(self, initialised_vault: Path) -> None:
        with VaultSession.unlock(PASSWORD, vault_path=initialised_vault) as session:
            pass
        assert session.is_locked is True

    def test_key_zeroed_after_context_exits(self, initialised_vault: Path) -> None:
        with VaultSession.unlock(PASSWORD, vault_path=initialised_vault) as session:
            pass
        assert all(b == 0 for b in session._key)

    def test_session_locked_on_exception(self, initialised_vault: Path) -> None:
        session = None
        with pytest.raises(RuntimeError):
            with VaultSession.unlock(PASSWORD, vault_path=initialised_vault) as s:
                session = s
                raise RuntimeError("simulated error")
        assert session is not None
        assert session.is_locked is True
