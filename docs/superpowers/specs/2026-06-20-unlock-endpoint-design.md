# Design: POST /unlock + POST /lock — FastAPI Backend Session Auth (SCRUM-14)

**Date:** 2026-06-20
**Ticket:** SCRUM-14 / KC-008
**Status:** Approved

---

## Overview

Implements the first two endpoints of the CipherDen FastAPI backend: `POST /unlock` (derive key, issue session token) and `POST /lock` (revoke token, zero key). Also establishes the auth dependency that all future entry endpoints will use.

The derived AES-256-GCM key is held in memory only, as a `bytearray`, and zeroed on revocation — consistent with ADR-003 and the existing `VaultSession` contract.

---

## Architecture

Four new files inside `cipherden/backend/`:

| File | Responsibility |
|---|---|
| `session_store.py` | `SessionStore` class — token lifecycle and key zeroing |
| `models.py` | Pydantic request/response schemas |
| `app.py` | FastAPI app, lifespan, routes, auth dependency |
| `server.py` | uvicorn entry point bound to `127.0.0.1` |

The vault layer (`cipherden/vault/`) is called directly — no new abstraction between backend and vault. `cipherden/backend/__init__.py` remains empty.

---

## SessionStore (`session_store.py`)

```
class SessionStore
├── _sessions: dict[str, VaultSession]   # private
├── create(session: VaultSession) → str  # generates and stores token
├── get(token: str) → VaultSession | None
├── revoke(token: str) → bool
└── revoke_all() → None
```

**Token generation:** `secrets.token_urlsafe(32)` — 256 bits of entropy.

**`get()`:** Iterates `_sessions` with `hmac.compare_digest` rather than a direct dict key lookup. Eliminates timing side-channels on token comparison. O(n) over active sessions — negligible for a local server with a handful of concurrent sessions.

**`revoke()`:** Pops the token from `_sessions`, calls `session.lock()` to zero the `bytearray` key. Returns `False` if the token was not found.

**`revoke_all()`:** Called by the FastAPI lifespan on server shutdown. Iterates every live session, calls `lock()` on each, clears the dict. Ensures no keys linger in memory after the process exits.

**Concurrency:** No locks required. uvicorn runs single-worker for this local server; asyncio's event loop is single-threaded.

The `SessionStore` is instantiated once at module level in `app.py`:

```python
store = SessionStore()
```

---

## Pydantic Models (`models.py`)

```python
class UnlockRequest(BaseModel):
    master_password: str

class UnlockResponse(BaseModel):
    token: str
```

No response model for `POST /lock` — returns `204 No Content`.

---

## API Routes + Auth Dependency (`app.py`)

### Lifespan

```python
@asynccontextmanager
async def lifespan(app: FastAPI):
    yield
    store.revoke_all()
```

Zeros all live session keys on shutdown.

### `POST /unlock`

- **Request:** `UnlockRequest` body
- **Calls:** `VaultSession.unlock(master_password)` with the vault's default path
- **Success:** `200 OK` → `UnlockResponse(token=...)`
- **Errors:**
  - `VaultNotInitialisedError` → `400 Bad Request` `{ "detail": "Vault not initialised. Run 'cipherden vault init' first." }`
  - `WrongPasswordError` → `401 Unauthorized` `{ "detail": "Incorrect master password." }`

### Auth dependency (`get_session`)

```python
def get_session(credentials: HTTPAuthorizationCredentials = Depends(HTTPBearer())) -> VaultSession:
    session = store.get(credentials.credentials)
    if session is None:
        raise HTTPException(status_code=401, detail="Invalid or expired session token.")
    return session
```

Applied to all protected routes via `Depends(get_session)`. Future entry endpoints declare the same dependency.

### `POST /lock`

- **Auth:** `Depends(get_session)`
- **Calls:** `store.revoke(token)` — zeros key via `session.lock()` internally
- **Success:** `204 No Content`
- **Errors:**
  - Token not found: `404 Not Found` `{ "detail": "Session not found." }`
  - Note: the auth dependency validates the token first, so a missing token hits `401` before the route handler runs; `404` is only reachable if revocation races (practically impossible in single-threaded asyncio)

### Error shape

FastAPI's default `{ "detail": str }` — no custom error envelope.

---

## Server Entry Point (`server.py`)

```python
uvicorn.run("cipherden.backend.app:app", host="127.0.0.1", port=8765, workers=1)
```

- Binds to `127.0.0.1` only — never exposed to the network.
- Port 8765 avoids conflict with common dev servers.
- Single worker — required for in-process `SessionStore` state to be shared across requests.
- Registered as `cipherden-server` in `pyproject.toml` `[project.scripts]`.

---

## Testing (`tests/integration/test_backend_unlock.py`)

Uses FastAPI's `TestClient` (synchronous, no running server). Real vault layer — no mocking. `tmp_path` fixture redirects vault path via `monkeypatch` (same pattern as CLI tests).

The `SessionStore` is reset between tests by monkeypatching `app_module.store` with a fresh `SessionStore()` instance before each test.

| Test | Expected |
|---|---|
| `POST /unlock` correct password | `200` + token string |
| `POST /unlock` wrong password | `401` |
| `POST /unlock` vault not initialised | `400` |
| `POST /lock` with valid token | `204` |
| Same token used after `POST /lock` | `401` (auth dep rejects revoked token) |
| `POST /lock` with no `Authorization` header | `401` (auth dep rejects missing token) |
| `POST /lock` with malformed/invalid token | `401` (auth dep rejects unknown token) |

---

## Out of Scope

- Token expiry / idle auto-lock (future ticket)
- `GET /status` or health check endpoint (future ticket)
- Multiple vault support
- `POST /lock` returning `404` in practice is unreachable via normal flow — documented but not tested separately
