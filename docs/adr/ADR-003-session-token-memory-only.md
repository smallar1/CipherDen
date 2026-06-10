# ADR-003: Session Token Held in Memory Only — No Disk Persistence

- **Status:** Accepted
- **Date:** 2026-06-09
- **Project:** CipherDen
- **Deciders:** Samuel-Evan Mallari

---

## Context

After a successful vault unlock (master password verified, Argon2id key derived), CipherDen needs a way to authorize subsequent vault operations within a session without re-deriving the key on every action. A session token represents this authorization.

The question: where should this token (and the derived encryption key) live during an active session?

Available persistence options in a browser extension context:
- `chrome.storage.local` / `chrome.storage.session` — persisted to disk (local), or retained across service worker restarts (session)
- `localStorage` / `sessionStorage` — disk-backed, accessible from content scripts if misconfigured
- In-memory JavaScript variable — lost on extension unload / service worker termination

---

## Options Considered

### chrome.storage.local (disk persistence)
- Survives browser restart, extension reload, OS sleep.
- Written to the user's file system in plaintext (Chrome extension storage is not encrypted by Chrome itself on most OS configurations).
- Any process or malware with file system read access to the Chrome profile directory can read `chrome.storage.local` values without needing the master password.
- **Unacceptable for a vault session token or derived key.**

### chrome.storage.session (MV3 session storage)
- Introduced in MV3. Cleared when the browser session ends (browser close, not tab close).
- Not written to disk; held in browser process memory.
- Shared across all extension contexts (background service worker, popup, content scripts) — reduces re-auth friction.
- Not cleared on screen lock or user-defined idle timeout without explicit logic.
- Closer to acceptable, but the extension cannot control when the browser process flushes this to a swap file on low-memory systems.

### In-memory JavaScript variable (service worker / background script scope)
- Lives only in the extension's background service worker memory.
- Cleared automatically when the service worker terminates (MV3 service workers terminate after ~30 seconds of inactivity).
- No file system exposure.
- Cannot be accessed by content scripts, other extensions, or external processes.
- UX trade-off: user must re-enter master password after service worker termination (typically on browser restart, or after idle timeout).

### localStorage / sessionStorage
- Accessible from any same-origin context. In an extension, this includes content scripts injected into web pages — a significant attack surface.
- `localStorage` is disk-backed.
- **Ruled out immediately.**

---

## Decision

**Hold the session token and derived encryption key exclusively in an in-memory JavaScript variable within the extension's background service worker. No disk write of any kind.**

Specific implementation rules:

1. On successful unlock: derive key via Argon2id, store in a module-level variable in the background service worker. Never pass it to `chrome.storage` of any kind.
2. On lock (user action, idle timeout, or service worker termination): zero-fill the variable before releasing the reference. Use `crypto.getRandomValues()` to overwrite if a TypedArray is used, ensuring the GC cannot retain a copy in unzeroable string allocations.
3. Idle auto-lock: a configurable timer (default 5 minutes) explicitly clears the key and token. This is necessary because MV3 service workers may remain alive longer than the 30-second idle termination in active-use scenarios.
4. The UX consequence — requiring re-unlock after browser restart or idle timeout — is intentional and disclosed in the UI.

---

## Consequences

**Positive:**
- Eliminates file system as an attack vector for session token theft
- No dependency on OS-level encryption of browser profile directories (which varies by OS and configuration)
- Token is automatically wiped on browser close — no manual cleanup required
- Aligns with the principle of least persistence

**Negative:**
- User must re-unlock after browser restart or service worker termination
- MV3 service worker lifecycle is not fully under developer control — the token may be wiped unexpectedly during prolonged inactivity, even mid-session
- Mitigation: `chrome.storage.session` is used to store a non-sensitive session flag (vault is unlocked: true/false) so the UI can show the correct lock state; the actual key is never in storage

**Deferred:**
- `chrome.storage.session` as a future option for the key warrants re-evaluation if Chrome guarantees no swap/disk flush for session storage values. As of 2026, no such guarantee exists in the Chrome extension documentation.

---

## References

- [Chrome Extensions — chrome.storage.session](https://developer.chrome.com/docs/extensions/reference/api/storage#property-session)
- [MV3 Service Worker Lifecycle](https://developer.chrome.com/docs/extensions/develop/concepts/service-workers/lifecycle)
- [OWASP — Sensitive Data Exposure](https://owasp.org/www-project-top-ten/2017/A3_2017-Sensitive_Data_Exposure)
