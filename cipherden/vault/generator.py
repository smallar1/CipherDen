"""
generator.py — CipherDen password generation.

Passwords are built from secrets.choice (a CSPRNG), never the random
module, since generated passwords are used as real credentials.
"""

from __future__ import annotations

import secrets
import string

DEFAULT_LENGTH = 16

_LOWERCASE = string.ascii_lowercase
_UPPERCASE = string.ascii_uppercase
_DIGITS = string.digits
_SYMBOLS = "!@#$%^&*()-_=+[]{};:,.<>?"


def generate_password(
    length: int = DEFAULT_LENGTH,
    use_symbols: bool = True,
    use_numbers: bool = True,
) -> str:
    """
    Generate a random password of *length* characters.

    Always draws from both letter cases. Digits and symbols are included
    if their respective flags are True. At least one character from each
    requested category is guaranteed to appear, with the remaining
    characters drawn from the full combined alphabet and the result
    shuffled so the guaranteed characters aren't predictably positioned.

    Raises:
        ValueError: If length is too short to fit one character from
                    each requested category.
    """
    categories = [_LOWERCASE, _UPPERCASE]
    if use_numbers:
        categories.append(_DIGITS)
    if use_symbols:
        categories.append(_SYMBOLS)

    if length < len(categories):
        msg = (
            f"Password length must be at least {len(categories)} to include "
            f"one character from each requested category, got {length}."
        )
        raise ValueError(msg)

    alphabet = "".join(categories)
    password_chars = [secrets.choice(category) for category in categories]
    password_chars.extend(secrets.choice(alphabet) for _ in range(length - len(categories)))

    for i in range(len(password_chars) - 1, 0, -1):
        j = secrets.randbelow(i + 1)
        password_chars[i], password_chars[j] = password_chars[j], password_chars[i]

    return "".join(password_chars)
