"""
init.py — CipherDen vault initialisation.

Responsible for:
  - Creating ~/.cipherden/ if it does not exist
  - Creating the SQLite database via open_db (runs all migrations)
  - Writing the vault_config header row (salt + Argon2 params)
  - Deriving and returning the session key (never written to disk)

Re-running vault_init on an already-initialised vault is a no-op;
the existing vault is left untouched.
"""

from __future__ import annotations

import sqlite3
from pathlib import Path

from cipherden.vault.crypto import (
    ARGON2_M,
    ARGON2_P,
    ARGON2_T,
    derive_key,
    generate_salt,
)
from cipherden.vault.db import open_db

VAULT_DIR = Path.home() / ".cipherden"
VAULT_FILE = VAULT_DIR / "cipherden.db"


class VaultAlreadyExistsError(Exception):
    """Raised when vault_init is called on an already-initialised vault."""


def vault_init(password: str, vault_path: Path = VAULT_FILE) -> bytes:
    """
    Initialise a new CipherDen vault.

    Creates the vault directory and database if they do not exist, writes
    the Argon2id salt and parameters to vault_config, and returns the
    derived session key.

    Args:
        password:   The master password supplied by the user.
        vault_path: Override the default vault location (used in tests).

    Returns:
        32-byte session key derived from password + salt. Never persisted.

    Raises:
        VaultAlreadyExistsError: If vault_config already has a row (vault
                                 was previously initialised).
    """
    vault_path.parent.mkdir(parents=True, exist_ok=True)

    conn = open_db(vault_path)

    try:
        existing = conn.execute("SELECT id FROM vault_config").fetchone()
        if existing is not None:
            raise VaultAlreadyExistsError(
                f"Vault already initialised at {vault_path}. "
                "Use 'cipherden vault unlock' to open it."
            )

        salt = generate_salt()

        with conn:
            conn.execute(
                """
                INSERT INTO vault_config (id, salt_hex, argon2_t, argon2_m, argon2_p)
                VALUES (1, ?, ?, ?, ?)
                """,
                (salt.hex(), ARGON2_T, ARGON2_M, ARGON2_P),
            )

        key = derive_key(password, salt)
        return key

    finally:
        conn.close()


def is_initialised(vault_path: Path = VAULT_FILE) -> bool:
    """Return True if a vault exists and has a vault_config row."""
    if not vault_path.exists():
        return False
    try:
        conn = open_db(vault_path)
        try:
            row = conn.execute("SELECT id FROM vault_config").fetchone()
            return row is not None
        finally:
            conn.close()
    except sqlite3.DatabaseError:
        return False
