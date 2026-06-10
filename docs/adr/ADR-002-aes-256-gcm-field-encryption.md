# ADR-002: AES-256-GCM for Vault Field Encryption

- **Status:** Accepted
- **Date:** 2026-06-09
- **Project:** CipherDen
- **Deciders:** Samuel-Evan Mallari

---

## Context

Each vault field (password, username, notes, URL) is encrypted at rest. The scheme must provide:

1. Confidentiality — ciphertext reveals nothing about plaintext
2. Integrity and authenticity — tampering must be detectable
3. Availability in browser (Web Crypto API) and Node.js (`crypto` module) without third-party libraries
4. A standard, well-analyzed construction

The encryption key is derived from the master password via Argon2id (see ADR-001). Each field is encrypted independently so partial vault reads are possible without decrypting the entire vault.

---

## Options Considered

### AES-256-CBC (no MAC)
- Does not provide authentication. Vulnerable to padding oracle and bit-flipping attacks.
- Ruled out immediately — unauthenticated encryption is unacceptable for a vault.

### AES-256-CBC + HMAC-SHA256 (Encrypt-then-MAC)
- Provides authentication when composed correctly.
- Error-prone — incorrect MAC key separation, MAC-before-encrypt mistakes are common implementation bugs.
- Superseded by AEAD constructions that integrate authentication by design.

### ChaCha20-Poly1305 / XChaCha20-Poly1305
- Excellent algorithm. Preferred by WireGuard, TLS 1.3, libsodium.
- ChaCha20-Poly1305 is in TLS 1.3 and IETF RFC 8439.
- **Not available in the Web Crypto API (as of 2026).** Would require a JavaScript polyfill or WebAssembly, introducing supply-chain risk and bundle overhead in the extension.
- XChaCha20-Poly1305 extends the nonce to 192 bits, eliminating nonce-reuse risk — but has the same unavailability problem in Web Crypto.

### AES-256-GCM
- AEAD: authenticated encryption with associated data. Authentication is intrinsic, not bolted on.
- Natively available in `SubtleCrypto.encrypt()` (Web Crypto) and `crypto.createCipheriv()` (Node.js).
- NIST SP 800-38D standard. Used in TLS 1.3, IPsec, SSH.
- 128-bit authentication tag.

---

## Decision

**Use AES-256-GCM for all vault field encryption.**

Implementation constraints:

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| Key size | 256 bits | Maximum AES key size; sourced from Argon2id output |
| IV (nonce) | 96 bits (12 bytes), random per encryption | GCM spec recommendation; Web Crypto requires 96-bit IV |
| Auth tag | 128 bits | Maximum tag length; mandatory minimum per NIST |
| AAD | `fieldName + vaultId` | Binds ciphertext to its position; prevents field swapping attacks |

**Nonce reuse is the critical failure mode for GCM.** A repeated nonce under the same key recovers the keystream and destroys both confidentiality and authentication. Mitigation: every encryption call generates a fresh random nonce via `crypto.getRandomValues()`. The nonce is stored prepended to the ciphertext (first 12 bytes). Nonce collision probability under random generation is negligible at vault scale (birthday bound: 2^32 operations for a 2^(-32) collision probability with 96-bit nonces — vault fields will never approach this).

Associated data binds each field's ciphertext to its semantic position in the vault, preventing an attacker from copying a ciphertext from one field to another.

---

## Consequences

**Positive:**
- Zero external cryptographic dependencies in browser — uses native Web Crypto API
- Authentication is intrinsic; no MAC composition errors possible
- NIST-standardized; well-understood by security reviewers
- 128-bit authentication tag provides strong tamper detection

**Negative:**
- GCM nonce reuse is catastrophically exploitable. Requires strict per-encryption random nonce generation — enforced in implementation, documented here for reviewers
- AES hardware acceleration (AES-NI) means performance is not an issue in practice, but this also means the choice is not distinguishable from AES-128-GCM on performance grounds alone
- Not natively available in some older embedded/mobile environments (not a concern for CipherDen's target platforms)

**Future consideration:**
- If CipherDen adds a React Native mobile client, re-evaluate XChaCha20-Poly1305 via libsodium — mobile Web Crypto support varies. This would be a separate ADR.

---

## References

- [NIST SP 800-38D — GCM Mode](https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf)
- [Web Crypto API — SubtleCrypto.encrypt()](https://developer.mozilla.org/en-US/docs/Web/API/SubtleCrypto/encrypt)
- [RFC 8439 — ChaCha20-Poly1305](https://datatracker.ietf.org/doc/html/rfc8439) (for comparison)
- [Natashenka & Joux, "Authentication Failures in NIST version of GCM"](https://csrc.nist.gov/csrc/media/projects/block-cipher-techniques/documents/bcm/comments/cwc-gcm/ferguson2.pdf)
