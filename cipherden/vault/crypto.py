"""
crypto.py — CipherDen cryptographic primitives.

Handles Argon2id key derivation only.
AES-256-GCM encrypt/decrypt lives in a separate module (SCRUM-27).

The derived key is NEVER written to disk. It exists in memory for the
duration of the unlocked session only.
"""

from __future__ import annotations

import os

from argon2.low_level import Type, hash_secret_raw

# ---------------------------------------------------------------------------
# Argon2id parameters
# Stored alongside the salt in vault_config so future re-derivation uses
# the exact same params even if defaults change in a later version.
# ---------------------------------------------------------------------------

ARGON2_T = 3  # time cost (iterations)
ARGON2_M = 65536  # memory cost (64 MiB in KiB)
ARGON2_P = 4  # parallelism
ARGON2_HASH_LEN = 32  # 256-bit output key
SALT_BYTES = 32


def generate_salt() -> bytes:
    """Return 32 cryptographically random bytes for use as an Argon2id salt."""
    return os.urandom(SALT_BYTES)


def derive_key(
    password: str,
    salt: bytes,
    t: int = ARGON2_T,
    m: int = ARGON2_M,
    p: int = ARGON2_P,
) -> bytes:
    """
    Derive a 256-bit key from *password* and *salt* using Argon2id.

    Args:
        password: The master password as a plain string.
        salt:     32-byte random salt from generate_salt() or loaded from vault_config.
        t:        Time cost. Defaults to ARGON2_T.
        m:        Memory cost in KiB. Defaults to ARGON2_M.
        p:        Parallelism. Defaults to ARGON2_P.

    Returns:
        32-byte derived key. Never store or log this value.
    """
    return hash_secret_raw(
        secret=password.encode(),
        salt=salt,
        time_cost=t,
        memory_cost=m,
        parallelism=p,
        hash_len=ARGON2_HASH_LEN,
        type=Type.ID,
    )
