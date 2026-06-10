# ADR-004: Manifest V3 over Manifest V2 for Browser Extension

- **Status:** Accepted
- **Date:** 2026-06-09
- **Project:** CipherDen
- **Deciders:** Samuel-Evan Mallari

---

## Context

CipherDen includes a browser extension for autofill. Browser extensions are built against a manifest version that governs available APIs, permission model, and background script architecture. Two versions are relevant: Manifest V2 (MV2) and Manifest V3 (MV3).

Google deprecated MV2 in Chrome. The extension must be forward-compatible and publishable to the Chrome Web Store. Firefox support is secondary but desirable.

---

## Options Considered

### Manifest V2
- Background scripts run as persistent background pages — full, long-lived JavaScript context.
- `chrome.webRequest` blocking API available — allows request interception before they complete.
- `eval()` and remotely hosted code permitted.
- **Chrome Web Store stopped accepting new MV2 extensions in June 2024. Existing MV2 extensions were disabled in Chrome in June 2025.**
- Not viable for a new extension in 2026.

### Manifest V3
- Required for all new Chrome Web Store submissions as of 2024.
- Background scripts replaced with **service workers** — ephemeral, terminate after ~30 seconds of inactivity.
- `chrome.webRequest` blocking replaced by `chrome.declarativeNetRequest` — rule-based, not imperative.
- Stricter CSP: no `eval()`, no remotely hosted scripts.
- `chrome.storage.session` introduced in MV3 for cross-context in-memory storage.
- Firefox supports MV3 (with minor API differences) as of Firefox 109+.

---

## Decision

**Build CipherDen's browser extension exclusively against Manifest V3.**

MV2 is not a viable option — new submissions are rejected and existing extensions were force-disabled. This is not a trade-off decision; it is a hard constraint.

The consequential MV3 architectural decisions this imposes:

### Service Worker Lifecycle (impacts ADR-003)
MV3 service workers terminate after ~30 seconds of inactivity. The vault session token cannot survive this termination. See ADR-003 for the full treatment. The extension UI detects service worker termination and prompts re-unlock when needed.

To keep the service worker alive during active use (e.g., while the popup is open), the extension uses `chrome.alarms` to fire a keep-alive alarm every 20 seconds. This is a documented MV3 workaround, not a hack — it is the pattern recommended by Google's extension team for extensions requiring continuity. The alarm is cleared when the vault is locked.

### No Blocking webRequest
CipherDen does not use `chrome.webRequest` blocking. The autofill feature operates via content scripts injected into pages — `declarativeNetRequest` is irrelevant to this use case. No functionality is lost.

### CSP Strictness
No `eval()` or dynamic code execution is used anywhere in the extension. This aligns with CipherDen's security requirements independently of MV3's mandate.

### Firefox Compatibility
Firefox supports MV3 with the following known differences:
- `browser.*` namespace vs `chrome.*` — handled via the `webextension-polyfill` library
- `chrome.storage.session` not available in all Firefox versions — the extension degrades gracefully (session flag omitted; lock state derived from in-memory key presence instead)

---

## Consequences

**Positive:**
- Chrome Web Store publishable
- Stricter CSP is a security benefit — no eval, no remote scripts
- MV3's restricted permission model reduces the extension's attack surface
- Future-proof: MV3 is the only supported path forward

**Negative:**
- Service worker termination requires keep-alive logic and UX handling for re-unlock — see ADR-003
- `chrome.storage.session` unavailable in older Firefox — acceptable degradation for the current scope
- Debugging service worker lifecycle issues is more complex than persistent background pages

**Workarounds in use:**
- `chrome.alarms` keep-alive (20-second interval when popup is open or autofill is active)
- Lock state stored as a boolean in `chrome.storage.session` (non-sensitive); actual key is in-memory only

---

## References

- [Chrome — Manifest V3 Migration Guide](https://developer.chrome.com/docs/extensions/develop/migrate)
- [Chrome Web Store — MV2 Deprecation Timeline](https://developer.chrome.com/docs/extensions/develop/migrate/mv2-deprecation-timeline)
- [MDN — Browser Extensions: MV3](https://developer.mozilla.org/en-US/docs/Mozilla/Add-ons/WebExtensions/manifest.json)
- [Google — Service Worker Keep-Alive Patterns](https://developer.chrome.com/docs/extensions/develop/concepts/service-workers/lifecycle#keep-alive-for-service-workers)
