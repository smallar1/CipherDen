"""
tests/unit/vault/test_crypto.py — Unit tests for the crypto module.

Tests cover:
- Salt generation (length, randomness)
- Key derivation (output length, determinism, sensitivity to inputs)
- Parameter defaults match spec
"""

from __future__ import annotations

from cipherden.vault.crypto import (
    ARGON2_HASH_LEN,
    ARGON2_M,
    ARGON2_P,
    ARGON2_T,
    SALT_BYTES,
    derive_key,
    generate_salt,
)

_PASSWORD = "correct-horse-battery-staple"  # pragma: allowlist secret


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------


class TestConstants:
    def test_salt_bytes_is_32(self) -> None:
        assert SALT_BYTES == 32

    def test_hash_len_is_32(self) -> None:
        assert ARGON2_HASH_LEN == 32

    def test_argon2_t_is_3(self) -> None:
        assert ARGON2_T == 3

    def test_argon2_m_is_65536(self) -> None:
        assert ARGON2_M == 65536

    def test_argon2_p_is_4(self) -> None:
        assert ARGON2_P == 4


# ---------------------------------------------------------------------------
# generate_salt
# ---------------------------------------------------------------------------


class TestGenerateSalt:
    def test_returns_bytes(self) -> None:
        assert isinstance(generate_salt(), bytes)

    def test_length_is_32(self) -> None:
        assert len(generate_salt()) == 32

    def test_two_salts_are_not_equal(self) -> None:
        # Probability of collision: 1/2^256 — effectively impossible.
        assert generate_salt() != generate_salt()


# ---------------------------------------------------------------------------
# derive_key
# ---------------------------------------------------------------------------


class TestDeriveKey:
    def test_returns_bytes(self) -> None:
        key = derive_key(_PASSWORD, generate_salt())
        assert isinstance(key, bytes)

    def test_output_length_is_32(self) -> None:
        key = derive_key(_PASSWORD, generate_salt())
        assert len(key) == 32

    def test_deterministic_with_same_inputs(self) -> None:
        salt = generate_salt()
        assert derive_key(_PASSWORD, salt) == derive_key(_PASSWORD, salt)

    def test_different_passwords_produce_different_keys(self) -> None:
        salt = generate_salt()
        assert (
            derive_key("password-one-abc", salt)  # pragma: allowlist secret
            != derive_key("password-two-xyz", salt)  # pragma: allowlist secret
        )

    def test_different_salts_produce_different_keys(self) -> None:
        assert derive_key(_PASSWORD, generate_salt()) != derive_key(_PASSWORD, generate_salt())

    def test_custom_params_accepted(self) -> None:
        # Lower params for speed — just verifies the call succeeds.
        key = derive_key(_PASSWORD, generate_salt(), t=1, m=8192, p=1)
        assert len(key) == 32

    def test_key_is_not_password_bytes(self) -> None:
        key = derive_key(_PASSWORD, generate_salt())
        assert key != _PASSWORD.encode()
