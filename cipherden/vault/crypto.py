"""
crypto.py — CipherDen cryptographic primitives.

Handles Argon2id key derivation and AES-256-GCM encrypt/decrypt.

The derived key is NEVER written to disk. It exists in memory for the
duration of the unlocked session only. Keys are held as bytearrays so
they can be zeroed on lock.
"""

from __future__ import annotations

import os

from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

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

# AES-256-GCM constants
NONCE_BYTES = 12  # 96-bit nonce, recommended for GCM

# Sentinel plaintext — a fixed known value encrypted at init time.
# Used to verify the correct master password was supplied on unlock.
SENTINEL_PLAINTEXT = b"cipherden-sentinel-v1"


def generate_salt() -> bytes:
    """Return 32 cryptographically random bytes for use as an Argon2id salt."""
    return os.urandom(SALT_BYTES)


def derive_key(
    password: str,
    salt: bytes,
    t: int = ARGON2_T,
    m: int = ARGON2_M,
    p: int = ARGON2_P,
) -> bytearray:
    """
    Derive a 256-bit key from *password* and *salt* using Argon2id.

    Args:
        password: The master password as a plain string.
        salt:     32-byte random salt from generate_salt() or loaded from vault_config.
        t:        Time cost. Defaults to ARGON2_T.
        m:        Memory cost in KiB. Defaults to ARGON2_M.
        p:        Parallelism. Defaults to ARGON2_P.

    Returns:
        32-byte derived key as a bytearray. Mutable so it can be zeroed on lock.
        Never store or log this value.
    """
    raw = hash_secret_raw(
        secret=password.encode(),
        salt=salt,
        time_cost=t,
        memory_cost=m,
        parallelism=p,
        hash_len=ARGON2_HASH_LEN,
        type=Type.ID,
    )
    return bytearray(raw)


def encrypt(key: bytearray, plaintext: bytes) -> bytes:
    """
    Encrypt *plaintext* with AES-256-GCM using *key*.

    A random 12-byte nonce is prepended to the ciphertext in the output.
    Output format: nonce (12 bytes) || ciphertext+tag (len(plaintext) + 16 bytes)

    Args:
        key:       32-byte key from derive_key().
        plaintext: Arbitrary bytes to encrypt.

    Returns:
        nonce + ciphertext as bytes. Safe to store in the database.
    """
    nonce = os.urandom(NONCE_BYTES)
    aesgcm = AESGCM(bytes(key))
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return nonce + ciphertext


def decrypt(key: bytearray, ciphertext: bytes) -> bytes:
    """
    Decrypt AES-256-GCM *ciphertext* with *key*.

    Expects the format produced by encrypt(): nonce (12 bytes) prepended.

    Args:
        key:        32-byte key from derive_key().
        ciphertext: nonce + ciphertext bytes as stored in the database.

    Returns:
        Decrypted plaintext bytes.

    Raises:
        cryptography.exceptions.InvalidTag: If the key is wrong or data is corrupt.
        ValueError: If ciphertext is too short to contain a nonce.
    """
    if len(ciphertext) < NONCE_BYTES:
        msg = f"Ciphertext too short: expected at least {NONCE_BYTES} bytes, got {len(ciphertext)}"
        raise ValueError(msg)
    nonce = ciphertext[:NONCE_BYTES]
    data = ciphertext[NONCE_BYTES:]
    aesgcm = AESGCM(bytes(key))
    return aesgcm.decrypt(nonce, data, None)
