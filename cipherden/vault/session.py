"""
session.py — CipherDen vault session management.

VaultSession holds the in-memory AES-256-GCM key for an unlocked vault.
The key is stored as a bytearray so it can be zeroed on lock.

Usage:
    with VaultSession.unlock(password, vault_path) as session:
        key = session.key  # bytearray, 32 bytes
    # key is zeroed here automatically

Or manually:
    session = VaultSession.unlock(password, vault_path)
    try:
        ...
    finally:
        session.lock()
"""

from __future__ import annotations

from pathlib import Path

from cryptography.exceptions import InvalidTag

from cipherden.vault.crypto import (
    SENTINEL_PLAINTEXT,
    decrypt,
    derive_key,
)
from cipherden.vault.db import open_db
from cipherden.vault.init import VAULT_FILE


class VaultLockedError(Exception):
    """Raised when an operation is attempted on a locked session."""


class WrongPasswordError(Exception):
    """Raised when the supplied password does not match the vault."""


class VaultNotInitialisedError(Exception):
    """Raised when unlock is attempted on a vault with no vault_config row."""


class VaultSession:
    """
    Represents an unlocked vault session.

    The 32-byte AES-256-GCM key is held in a bytearray and zeroed when
    lock() is called or the context manager exits.
    """

    def __init__(self, key: bytearray) -> None:
        self._key = key
        self._locked = False

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @classmethod
    def unlock(cls, password: str, vault_path: Path = VAULT_FILE) -> VaultSession:
        """
        Derive the vault key from *password* and verify it against the sentinel.

        Args:
            password:   The master password supplied by the user.
            vault_path: Path to the vault DB. Defaults to ~/.cipherden/cipherden.db.

        Returns:
            An unlocked VaultSession.

        Raises:
            VaultNotInitialisedError: If the vault has no vault_config row.
            WrongPasswordError:       If the sentinel decryption fails.
        """
        conn = open_db(vault_path)
        try:
            row = conn.execute(
                "SELECT salt_hex, argon2_t, argon2_m, argon2_p, sentinel_enc FROM vault_config"
            ).fetchone()
        finally:
            conn.close()

        if row is None:
            raise VaultNotInitialisedError(
                f"No vault found at {vault_path}. Run 'cipherden vault init' first."
            )

        salt = bytes.fromhex(row["salt_hex"])
        key = derive_key(
            password,
            salt,
            t=row["argon2_t"],
            m=row["argon2_m"],
            p=row["argon2_p"],
        )

        try:
            plaintext = decrypt(key, bytes(row["sentinel_enc"]))
        except InvalidTag, ValueError:
            # Zero the key immediately — wrong password, discard it.
            for i in range(len(key)):
                key[i] = 0
            raise WrongPasswordError("Incorrect master password.") from None

        if plaintext != SENTINEL_PLAINTEXT:
            for i in range(len(key)):
                key[i] = 0
            raise WrongPasswordError("Incorrect master password.")

        return cls(key)

    @property
    def key(self) -> bytearray:
        """The 32-byte session key. Raises VaultLockedError if locked."""
        if self._locked:
            raise VaultLockedError("Vault is locked. Call unlock() first.")
        return self._key

    def lock(self) -> None:
        """Zero the key buffer and mark the session as locked."""
        for i in range(len(self._key)):
            self._key[i] = 0
        self._locked = True

    @property
    def is_locked(self) -> bool:
        return self._locked

    # ------------------------------------------------------------------
    # Context manager
    # ------------------------------------------------------------------

    def __enter__(self) -> VaultSession:
        return self

    def __exit__(self, *_: object) -> None:
        if not self._locked:
            self.lock()
