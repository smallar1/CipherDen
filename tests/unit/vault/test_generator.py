"""
tests/unit/vault/test_generator.py — Unit tests for the password generator.

Tests cover:
- Default and custom length
- Symbol/number inclusion and exclusion flags
- Use of secrets.choice (not random) as the entropy source
- Minimum length validation
"""

from __future__ import annotations

import secrets
import string
from unittest.mock import patch

import pytest

from cipherden.vault.generator import DEFAULT_LENGTH, generate_password

_LETTERS = set(string.ascii_letters)
_DIGITS = set(string.digits)


def _is_symbol(char: str) -> bool:
    return char not in _LETTERS and char not in _DIGITS


# ---------------------------------------------------------------------------
# Length
# ---------------------------------------------------------------------------


class TestLength:
    def test_default_length(self) -> None:
        password = generate_password()
        assert len(password) == DEFAULT_LENGTH

    @pytest.mark.parametrize("length", [4, 8, 16, 32, 64])
    def test_custom_length(self, length: int) -> None:
        password = generate_password(length=length)
        assert len(password) == length

    def test_length_too_short_for_categories_raises(self) -> None:
        with pytest.raises(ValueError, match="at least"):
            generate_password(length=1, use_symbols=True, use_numbers=True)

    def test_minimum_length_for_letters_only_succeeds(self) -> None:
        password = generate_password(length=2, use_symbols=False, use_numbers=False)
        assert len(password) == 2


# ---------------------------------------------------------------------------
# Symbol / number flags
# ---------------------------------------------------------------------------


class TestCharacterFlags:
    def test_numbers_included_by_default(self) -> None:
        passwords = [generate_password(length=32) for _ in range(20)]
        assert any(set(p) & _DIGITS for p in passwords)

    def test_symbols_included_by_default(self) -> None:
        passwords = [generate_password(length=32) for _ in range(20)]
        assert any(any(_is_symbol(c) for c in p) for p in passwords)

    def test_no_numbers_excludes_digits(self) -> None:
        for _ in range(20):
            password = generate_password(length=32, use_numbers=False)
            assert not set(password) & _DIGITS

    def test_no_symbols_excludes_symbols(self) -> None:
        for _ in range(20):
            password = generate_password(length=32, use_symbols=False)
            assert not any(_is_symbol(c) for c in password)

    def test_letters_only_password_is_alphabetic(self) -> None:
        for _ in range(20):
            password = generate_password(length=32, use_symbols=False, use_numbers=False)
            assert set(password) <= _LETTERS

    def test_requested_category_always_present(self) -> None:
        # Length 4 is the minimum that fits all four categories at least once.
        for _ in range(50):
            password = generate_password(length=4, use_symbols=True, use_numbers=True)
            chars = set(password)
            assert chars & set(string.ascii_lowercase)
            assert chars & set(string.ascii_uppercase)
            assert chars & _DIGITS
            assert any(_is_symbol(c) for c in password)


# ---------------------------------------------------------------------------
# Entropy source
# ---------------------------------------------------------------------------


class TestEntropySource:
    def test_uses_secrets_choice(self) -> None:
        with patch("cipherden.vault.generator.secrets.choice", wraps=secrets.choice) as mock:
            generate_password(length=16)
        assert mock.called

    def test_does_not_use_random_module(self) -> None:
        with patch("random.choice") as mock_random_choice, patch("random.randint") as mock_randint:
            generate_password(length=16)
        mock_random_choice.assert_not_called()
        mock_randint.assert_not_called()

    def test_passwords_are_not_deterministic(self) -> None:
        passwords = {generate_password(length=16) for _ in range(20)}
        assert len(passwords) > 1
