"""
exceptions.py — CipherDen application exceptions.

All custom exceptions raised by CipherDen modules are defined here.
Callers (CLI, API, browser extension bridge) should import from this
module rather than from cryptography.exceptions or other third-party
packages, keeping the public error surface stable and independent of
implementation details.
"""

from __future__ import annotations


class CipherDenError(Exception):
    """Base class for all CipherDen exceptions."""


class DecryptionError(CipherDenError):
    """
    Raised when AES-256-GCM decryption fails due to an authentication tag
    mismatch.

    This covers two distinct failure cases:
    - Wrong key supplied (e.g. incorrect master password)
    - Ciphertext has been tampered with or is corrupt

    GCM authentication is not separable from decryption, so both cases are
    indistinguishable by design. Callers must not attempt to distinguish them.

    Never log or expose the raw ciphertext or key material in the message.
    """
