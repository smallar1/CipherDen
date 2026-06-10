# ADR-001: Argon2id for Master Password Key Derivation

- **Status:** Accepted
- **Date:** 2026-06-09
- **Project:** CipherDen
- **Deciders:** Samuel-Evan Mallari

---

## Context

CipherDen derives an encryption key from the user's master password. This key directly protects the vault. The KDF must be:

1. Resistant to brute-force attacks using GPUs and ASICs
2. Configurable in memory and CPU cost
3. Well-audited and standardized

The KDF is invoked once per unlock and never stored. The derived key is held in memory and wiped on lock.

---

## Options Considered

### bcrypt
- Max input length of 72 bytes — silently truncates longer passwords. Unacceptable for a vault.
- Memory-hard by design year (1999) standards, but not tunable beyond work factor.
- No memory-hardness against modern GPU attacks.

### scrypt
- Memory-hard, tunable. Winner of the 2009 Password Hashing Competition precursor work.
- Complex parameter interaction: N, r, p. Easy to misconfigure (e.g. low N + high p gives false confidence).
- No side-channel resistance guarantees in the spec.
- RFC 7914 but not a NIST recommendation.

### PBKDF2
- NIST-approved, FIPS-compliant, widely available.
- Not memory-hard — GPU parallelism is trivially effective. Unacceptable as the sole KDF for a password manager vault key.

### Argon2id
- Won the Password Hashing Competition (2015). RFC 9106 (2021).
- Three variants: Argon2d (GPU resistance), Argon2i (side-channel resistance), Argon2id (hybrid — both).
- Tunable on: time cost (t), memory cost (m, in KiB), parallelism (p).
- Argon2id is the PHC winner's recommended default for password hashing.

---

## Decision

**Use Argon2id with the following parameters:**

| Parameter | Value | Rationale |
|-----------|-------|-----------|
| `t` (iterations) | 3 | RFC 9106 minimum recommended for interactive use |
| `m` (memory) | 65536 KiB (64 MiB) | RFC 9106 recommendation for non-memory-constrained systems |
| `p` (parallelism) | 4 | Matches expected hardware; RFC 9106 recommended value |
| Output length | 32 bytes | AES-256 key size (see ADR-002) |
| Salt | 16 bytes cryptographically random per vault | Prevents precomputation attacks |

RFC 9106 §4 explicitly recommends Argon2id as the default when no specific threat model demands one variant over the other. These parameters are the RFC's "first recommended option" for interactive logins and are appropriate for a desktop/extension context.

---

## Consequences

**Positive:**
- Strong GPU and ASIC resistance through combined data- and time-dependent memory access
- Standardized — RFC 9106, PHC winner
- Parameters are future-adjustable without breaking existing vaults (salt + params stored in vault header)

**Negative:**
- 64 MiB RAM usage per unlock. Acceptable on desktop/laptop; would need re-evaluation for mobile or resource-constrained environments
- Unlock latency ~300–500ms on modern hardware at these parameters. This is intentional and documented

**Risks:**
- Nonce (salt) must be generated fresh per vault creation, never reused. Handled by `crypto.getRandomValues()` (browser) / `crypto.randomBytes()` (Node.js)
- Parameters must be stored alongside the encrypted vault so future unlocks use the same values

---

## References

- [RFC 9106 — Argon2 Memory-Hard Function](https://datatracker.ietf.org/doc/html/rfc9106)
- [Password Hashing Competition Results](https://www.password-hashing.net/)
- [OWASP Password Storage Cheat Sheet](https://cheatsheetseries.owasp.org/cheatsheets/Password_Storage_Cheat_Sheet.html)
