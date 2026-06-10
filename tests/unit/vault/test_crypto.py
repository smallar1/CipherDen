"""
tests/unit/vault/test_crypto.py — Unit tests for the crypto module.

Tests cover:
- Salt generation (length, randomness)
- Key derivation (output length, type, determinism, sensitivity to inputs)
- AES-256-GCM encrypt/decrypt (round-trip, nonce prepended, wrong key raises)
- AAD binding (correct AAD decrypts, wrong/missing AAD raises DecryptionError)
- Parameter defaults match spec
"""

from __future__ import annotations

import pytest

from cipherden.exceptions import DecryptionError
from cipherden.vault.crypto import (
    ARGON2_HASH_LEN,
    ARGON2_M,
    ARGON2_P,
    ARGON2_T,
    NONCE_BYTES,
    SALT_BYTES,
    SENTINEL_PLAINTEXT,
    decrypt,
    derive_key,
    encrypt,
    generate_salt,
)

_PASSWORD = "correct-horse-battery-staple"  # pragma: allowlist secret
_AAD = b"vault-uuid-1234:password"


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------


class TestConstants:
    def test_salt_bytes_is_32(self) -> None:
        assert SALT_BYTES == 32

    def test_hash_len_is_32(self) -> None:
        assert ARGON2_HASH_LEN == 32

    def test_nonce_bytes_is_12(self) -> None:
        assert NONCE_BYTES == 12

    def test_argon2_t_is_3(self) -> None:
        assert ARGON2_T == 3

    def test_argon2_m_is_65536(self) -> None:
        assert ARGON2_M == 65536

    def test_argon2_p_is_4(self) -> None:
        assert ARGON2_P == 4

    def test_sentinel_plaintext_is_bytes(self) -> None:
        assert isinstance(SENTINEL_PLAINTEXT, bytes)

    def test_sentinel_plaintext_is_not_empty(self) -> None:
        assert len(SENTINEL_PLAINTEXT) > 0


# ---------------------------------------------------------------------------
# generate_salt
# ---------------------------------------------------------------------------


class TestGenerateSalt:
    def test_returns_bytes(self) -> None:
        assert isinstance(generate_salt(), bytes)

    def test_length_is_32(self) -> None:
        assert len(generate_salt()) == 32

    def test_two_salts_are_not_equal(self) -> None:
        assert generate_salt() != generate_salt()


# ---------------------------------------------------------------------------
# derive_key
# ---------------------------------------------------------------------------


class TestDeriveKey:
    def test_returns_bytearray(self) -> None:
        key = derive_key(_PASSWORD, generate_salt())
        assert isinstance(key, bytearray)

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
        key = derive_key(_PASSWORD, generate_salt(), t=1, m=8192, p=1)
        assert len(key) == 32

    def test_key_is_mutable(self) -> None:
        key = derive_key(_PASSWORD, generate_salt())
        key[0] = 0  # must not raise

    def test_key_can_be_zeroed(self) -> None:
        key = derive_key(_PASSWORD, generate_salt())
        for i in range(len(key)):
            key[i] = 0
        assert all(b == 0 for b in key)

    def test_key_is_not_password_bytes(self) -> None:
        key = derive_key(_PASSWORD, generate_salt())
        assert bytes(key) != _PASSWORD.encode()


# ---------------------------------------------------------------------------
# encrypt / decrypt
# ---------------------------------------------------------------------------


class TestEncryptDecrypt:
    def _key(self) -> bytearray:
        return derive_key(_PASSWORD, generate_salt(), t=1, m=8192, p=1)

    def test_encrypt_returns_bytes(self) -> None:
        key = self._key()
        assert isinstance(encrypt(key, b"hello"), bytes)

    def test_encrypt_output_longer_than_plaintext(self) -> None:
        key = self._key()
        plaintext = b"hello world"
        # nonce (12) + plaintext + GCM tag (16)
        assert len(encrypt(key, plaintext)) == NONCE_BYTES + len(plaintext) + 16

    def test_nonce_is_prepended(self) -> None:
        key = self._key()
        ciphertext = encrypt(key, b"hello")
        assert len(ciphertext) >= NONCE_BYTES

    def test_two_encryptions_differ_due_to_random_nonce(self) -> None:
        key = self._key()
        assert encrypt(key, b"hello") != encrypt(key, b"hello")

    def test_round_trip(self) -> None:
        key = self._key()
        plaintext = b"correct-horse-battery-staple"  # pragma: allowlist secret
        assert decrypt(key, encrypt(key, plaintext)) == plaintext

    def test_round_trip_sentinel(self) -> None:
        key = self._key()
        assert decrypt(key, encrypt(key, SENTINEL_PLAINTEXT)) == SENTINEL_PLAINTEXT

    def test_wrong_key_raises_decryption_error(self) -> None:
        key1 = self._key()
        key2 = self._key()
        ciphertext = encrypt(key1, b"secret")
        with pytest.raises(DecryptionError):
            decrypt(key2, ciphertext)

    def test_truncated_ciphertext_raises_value_error(self) -> None:
        key = self._key()
        with pytest.raises(ValueError):
            decrypt(key, b"\x00" * 4)  # shorter than NONCE_BYTES

    def test_tampered_ciphertext_raises_decryption_error(self) -> None:
        key = self._key()
        ciphertext = bytearray(encrypt(key, b"secret"))
        ciphertext[-1] ^= 0xFF  # flip last byte of GCM tag
        with pytest.raises(DecryptionError):
            decrypt(key, bytes(ciphertext))


# ---------------------------------------------------------------------------
# AAD (associated data)
# ---------------------------------------------------------------------------


class TestAAD:
    def _key(self) -> bytearray:
        return derive_key(_PASSWORD, generate_salt(), t=1, m=8192, p=1)

    def test_round_trip_with_aad(self) -> None:
        key = self._key()
        plaintext = b"hunter2"  # pragma: allowlist secret
        blob = encrypt(key, plaintext, aad=_AAD)
        assert decrypt(key, blob, aad=_AAD) == plaintext

    def test_wrong_aad_raises_decryption_error(self) -> None:
        key = self._key()
        blob = encrypt(key, b"secret", aad=_AAD)
        with pytest.raises(DecryptionError):
            decrypt(key, blob, aad=b"vault-uuid-1234:username")

    def test_missing_aad_on_decrypt_raises_decryption_error(self) -> None:
        key = self._key()
        blob = encrypt(key, b"secret", aad=_AAD)
        with pytest.raises(DecryptionError):
            decrypt(key, blob)  # aad defaults to None

    def test_unexpected_aad_on_decrypt_raises_decryption_error(self) -> None:
        key = self._key()
        blob = encrypt(key, b"secret")  # no AAD at encrypt time
        with pytest.raises(DecryptionError):
            decrypt(key, blob, aad=_AAD)

    def test_aad_does_not_affect_ciphertext_length(self) -> None:
        key = self._key()
        plaintext = b"hello"
        without_aad = encrypt(key, plaintext)
        with_aad = encrypt(key, plaintext, aad=_AAD)
        assert len(without_aad) == len(with_aad)

    def test_different_aad_values_produce_same_length_output(self) -> None:
        key = self._key()
        plaintext = b"hello"
        blob1 = encrypt(key, plaintext, aad=b"vault-1:password")
        blob2 = encrypt(key, plaintext, aad=b"vault-2:password")
        assert len(blob1) == len(blob2)
