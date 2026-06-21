# KC-008 / SCRUM-14: POST /unlock + POST /lock Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Implement `POST /unlock` (derives key, issues session token) and `POST /lock` (revokes token, zeros key) as the first two endpoints of the CipherDen FastAPI backend, along with the auth dependency all future entry endpoints will use.

**Architecture:** A module-level `SessionStore` in `app.py` holds `{token → VaultSession}` in memory. Tokens are generated with `secrets.token_urlsafe(32)` (256-bit entropy) and looked up with `hmac.compare_digest` to prevent timing side-channels. The FastAPI lifespan zeroes all live keys on shutdown via `store.revoke_all()`.

**Tech Stack:** FastAPI, Pydantic v2, uvicorn, FastAPI `TestClient` (backed by `httpx`), pytest

---

## File Map

| Action | Path | Responsibility |
|--------|------|----------------|
| Create | `cipherden/backend/session_store.py` | Token lifecycle + key zeroing |
| Create | `cipherden/backend/models.py` | Pydantic request/response schemas |
| Create | `cipherden/backend/app.py` | FastAPI app, lifespan, routes, auth dependency |
| Create | `cipherden/backend/server.py` | uvicorn entry point |
| Modify | `pyproject.toml` | Add `cipherden-server` script entry point |
| Create | `tests/unit/test_session_store.py` | SessionStore unit tests |
| Create | `tests/integration/test_backend_unlock.py` | Endpoint integration tests |

---

## Task 1: SessionStore

**Files:**
- Create: `cipherden/backend/session_store.py`
- Create: `tests/unit/test_session_store.py`

- [ ] **Step 1: Write the failing tests**

Create `tests/unit/test_session_store.py`:

```python
from __future__ import annotations

import pytest

from cipherden.backend.session_store import SessionStore
from cipherden.vault.session import VaultSession


def _fake_session() -> VaultSession:
    """Construct a VaultSession with a 32-byte fake key — no vault file required."""
    return VaultSession(bytearray(32))


class TestSessionStore:
    def test_create_returns_string_token(self) -> None:
        store = SessionStore()
        token = store.create(_fake_session())
        assert isinstance(token, str)
        assert len(token) > 0

    def test_get_returns_session_for_valid_token(self) -> None:
        store = SessionStore()
        session = _fake_session()
        token = store.create(session)
        assert store.get(token) is session

    def test_get_returns_none_for_unknown_token(self) -> None:
        store = SessionStore()
        assert store.get("not-a-real-token") is None

    def test_get_returns_none_after_revoke(self) -> None:
        store = SessionStore()
        session = _fake_session()
        token = store.create(session)
        store.revoke(token)
        assert store.get(token) is None

    def test_revoke_locks_the_session(self) -> None:
        store = SessionStore()
        session = _fake_session()
        token = store.create(session)
        store.revoke(token)
        assert session.is_locked

    def test_revoke_returns_true_for_existing_token(self) -> None:
        store = SessionStore()
        token = store.create(_fake_session())
        assert store.revoke(token) is True

    def test_revoke_returns_false_for_unknown_token(self) -> None:
        store = SessionStore()
        assert store.revoke("ghost-token") is False

    def test_revoke_all_locks_every_session(self) -> None:
        store = SessionStore()
        sessions = [_fake_session() for _ in range(3)]
        for s in sessions:
            store.create(s)
        store.revoke_all()
        assert all(s.is_locked for s in sessions)

    def test_revoke_all_clears_store(self) -> None:
        store = SessionStore()
        token = store.create(_fake_session())
        store.revoke_all()
        assert store.get(token) is None
```

- [ ] **Step 2: Run to verify they fail**

```bash
pytest tests/unit/test_session_store.py -v
```

Expected: `ModuleNotFoundError: No module named 'cipherden.backend.session_store'`

- [ ] **Step 3: Implement `session_store.py`**

Create `cipherden/backend/session_store.py`:

```python
from __future__ import annotations

import hmac
import secrets

from cipherden.vault.session import VaultSession


class SessionStore:
    def __init__(self) -> None:
        self._sessions: dict[str, VaultSession] = {}

    def create(self, session: VaultSession) -> str:
        token = secrets.token_urlsafe(32)
        self._sessions[token] = session
        return token

    def get(self, token: str) -> VaultSession | None:
        for stored_token, session in self._sessions.items():
            if hmac.compare_digest(stored_token, token):
                return session
        return None

    def revoke(self, token: str) -> bool:
        session = self._sessions.pop(token, None)
        if session is None:
            return False
        if not session.is_locked:
            session.lock()
        return True

    def revoke_all(self) -> None:
        for session in self._sessions.values():
            if not session.is_locked:
                session.lock()
        self._sessions.clear()
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
pytest tests/unit/test_session_store.py -v
```

Expected: all 9 tests PASS

- [ ] **Step 5: Commit**

```bash
git add cipherden/backend/session_store.py tests/unit/test_session_store.py
git commit -m "feat: add SessionStore with constant-time token lookup and key zeroing — KC-008"
```

---

## Task 2: Pydantic models + app scaffold + test fixture

**Files:**
- Create: `cipherden/backend/models.py`
- Create: `cipherden/backend/app.py`
- Create: `tests/integration/test_backend_unlock.py`

- [ ] **Step 1: Create `models.py`**

Create `cipherden/backend/models.py`:

```python
from __future__ import annotations

from pydantic import BaseModel


class UnlockRequest(BaseModel):
    master_password: str


class UnlockResponse(BaseModel):
    token: str
```

- [ ] **Step 2: Create `app.py` scaffold**

Create `cipherden/backend/app.py`:

```python
from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI

from cipherden.backend.session_store import SessionStore

store = SessionStore()


@asynccontextmanager
async def lifespan(app: FastAPI):
    yield
    store.revoke_all()


app = FastAPI(title="CipherDen", lifespan=lifespan)
```

- [ ] **Step 3: Create the integration test file with fixtures**

Create `tests/integration/test_backend_unlock.py`:

```python
from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from typer.testing import CliRunner

import cipherden.backend.app as app_module
import cipherden.vault.init as init_module
import cipherden.vault.session as session_module
from cipherden.backend.app import app
from cipherden.backend.session_store import SessionStore
from cipherden.cli.main import app as cli_app

client = TestClient(app, raise_server_exceptions=True)
cli_runner = CliRunner()

_PASSWORD = "correct-horse-battery-staple"  # pragma: allowlist secret


@pytest.fixture(autouse=True)
def reset_store(monkeypatch: pytest.MonkeyPatch) -> None:
    """Replace the module-level store with a fresh instance before each test."""
    monkeypatch.setattr(app_module, "store", SessionStore())


@pytest.fixture
def initialised_vault(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Path:
    """Create a real vault in tmp_path and redirect unlock to it."""
    vault_path = tmp_path / "cipherden.db"
    monkeypatch.setattr(init_module.vault_init, "__defaults__", (vault_path,))
    monkeypatch.setattr(session_module.VaultSession.unlock.__func__, "__defaults__", (vault_path,))
    cli_runner.invoke(cli_app, ["vault", "init"], input=f"{_PASSWORD}\n{_PASSWORD}\n")
    return vault_path
```

- [ ] **Step 4: Verify the file is importable with no test collection errors**

```bash
pytest tests/integration/test_backend_unlock.py -v
```

Expected: `no tests ran` (0 collected, 0 errors)

- [ ] **Step 5: Commit**

```bash
git add cipherden/backend/models.py cipherden/backend/app.py tests/integration/test_backend_unlock.py
git commit -m "feat: scaffold FastAPI app with SessionStore lifespan and test fixtures — KC-008"
```

---

## Task 3: POST /unlock route

**Files:**
- Modify: `cipherden/backend/app.py`
- Modify: `tests/integration/test_backend_unlock.py`

- [ ] **Step 1: Write the failing tests**

Append to `tests/integration/test_backend_unlock.py`:

```python
class TestUnlock:
    def test_correct_password_returns_200_with_token(self, initialised_vault: Path) -> None:
        response = client.post("/unlock", json={"master_password": _PASSWORD})
        assert response.status_code == 200
        body = response.json()
        assert "token" in body
        assert isinstance(body["token"], str)
        assert len(body["token"]) > 0

    def test_wrong_password_returns_401(self, initialised_vault: Path) -> None:
        response = client.post("/unlock", json={"master_password": "wrong-password-here"})
        assert response.status_code == 401
        assert "Incorrect master password" in response.json()["detail"]

    def test_vault_not_initialised_returns_400(
        self, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
    ) -> None:
        vault_path = tmp_path / "nonexistent.db"
        monkeypatch.setattr(
            session_module.VaultSession.unlock.__func__, "__defaults__", (vault_path,)
        )
        response = client.post("/unlock", json={"master_password": _PASSWORD})
        assert response.status_code == 400
        assert "Vault not initialised" in response.json()["detail"]
```

- [ ] **Step 2: Run to verify they fail**

```bash
pytest tests/integration/test_backend_unlock.py::TestUnlock -v
```

Expected: all 3 tests FAIL with `404 Not Found`

- [ ] **Step 3: Implement POST /unlock in `app.py`**

Replace `cipherden/backend/app.py` with:

```python
from __future__ import annotations

from contextlib import asynccontextmanager

from fastapi import FastAPI, HTTPException

from cipherden.backend.models import UnlockRequest, UnlockResponse
from cipherden.backend.session_store import SessionStore
from cipherden.vault.session import VaultNotInitialisedError, VaultSession, WrongPasswordError

store = SessionStore()


@asynccontextmanager
async def lifespan(app: FastAPI):
    yield
    store.revoke_all()


app = FastAPI(title="CipherDen", lifespan=lifespan)


@app.post("/unlock", response_model=UnlockResponse)
def unlock(body: UnlockRequest) -> UnlockResponse:
    try:
        session = VaultSession.unlock(body.master_password)
    except VaultNotInitialisedError:
        raise HTTPException(
            status_code=400,
            detail="Vault not initialised. Run 'cipherden vault init' first.",
        )
    except WrongPasswordError:
        raise HTTPException(status_code=401, detail="Incorrect master password.")
    token = store.create(session)
    return UnlockResponse(token=token)
```

- [ ] **Step 4: Run tests to verify they pass**

```bash
pytest tests/integration/test_backend_unlock.py::TestUnlock -v
```

Expected: all 3 tests PASS

- [ ] **Step 5: Commit**

```bash
git add cipherden/backend/app.py tests/integration/test_backend_unlock.py
git commit -m "feat: implement POST /unlock endpoint — KC-008"
```

---

## Task 4: Auth dependency + POST /lock route

**Files:**
- Modify: `cipherden/backend/app.py`
- Modify: `tests/integration/test_backend_unlock.py`

- [ ] **Step 1: Write the failing tests**

Append to `tests/integration/test_backend_unlock.py`:

```python
class TestLock:
    def test_valid_token_returns_204(self, initialised_vault: Path) -> None:
        token = client.post("/unlock", json={"master_password": _PASSWORD}).json()["token"]
        response = client.post("/lock", headers={"Authorization": f"Bearer {token}"})
        assert response.status_code == 204

    def test_revoked_token_is_rejected_with_401(self, initialised_vault: Path) -> None:
        token = client.post("/unlock", json={"master_password": _PASSWORD}).json()["token"]
        client.post("/lock", headers={"Authorization": f"Bearer {token}"})
        # Second lock attempt with the same token must be rejected
        response = client.post("/lock", headers={"Authorization": f"Bearer {token}"})
        assert response.status_code == 401

    def test_invalid_token_returns_401(self, initialised_vault: Path) -> None:
        response = client.post("/lock", headers={"Authorization": "Bearer not-a-real-token"})
        assert response.status_code == 401

    def test_missing_authorization_header_returns_403(self, initialised_vault: Path) -> None:
        # FastAPI's HTTPBearer returns 403 when the Authorization header is absent entirely.
        # 403 = no credentials provided; 401 = credentials provided but invalid.
        response = client.post("/lock")
        assert response.status_code == 403
```

- [ ] **Step 2: Run to verify they fail**

```bash
pytest tests/integration/test_backend_unlock.py::TestLock -v
```

Expected: all 4 tests FAIL with `404 Not Found`

- [ ] **Step 3: Implement auth dependency and POST /lock in `app.py`**

Replace `cipherden/backend/app.py` with:

```python
from __future__ import annotations

from contextlib import asynccontextmanager
from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from cipherden.backend.models import UnlockRequest, UnlockResponse
from cipherden.backend.session_store import SessionStore
from cipherden.vault.session import VaultNotInitialisedError, VaultSession, WrongPasswordError

store = SessionStore()
_bearer = HTTPBearer()


@asynccontextmanager
async def lifespan(app: FastAPI):
    yield
    store.revoke_all()


app = FastAPI(title="CipherDen", lifespan=lifespan)


def get_session(
    credentials: Annotated[HTTPAuthorizationCredentials, Depends(_bearer)],
) -> VaultSession:
    session = store.get(credentials.credentials)
    if session is None:
        raise HTTPException(status_code=401, detail="Invalid or expired session token.")
    return session


@app.post("/unlock", response_model=UnlockResponse)
def unlock(body: UnlockRequest) -> UnlockResponse:
    try:
        session = VaultSession.unlock(body.master_password)
    except VaultNotInitialisedError:
        raise HTTPException(
            status_code=400,
            detail="Vault not initialised. Run 'cipherden vault init' first.",
        )
    except WrongPasswordError:
        raise HTTPException(status_code=401, detail="Incorrect master password.")
    token = store.create(session)
    return UnlockResponse(token=token)


@app.post("/lock", status_code=204)
def lock(
    credentials: Annotated[HTTPAuthorizationCredentials, Depends(_bearer)],
    _session: Annotated[VaultSession, Depends(get_session)],
) -> None:
    # get_session already validated the token; revoke it to zero the key.
    store.revoke(credentials.credentials)
```

- [ ] **Step 4: Run all backend tests**

```bash
pytest tests/integration/test_backend_unlock.py -v
```

Expected: all 7 tests PASS

- [ ] **Step 5: Run the full suite**

```bash
pytest -v
```

Expected: all tests PASS (unit + CLI integration + backend integration)

- [ ] **Step 6: Commit**

```bash
git add cipherden/backend/app.py tests/integration/test_backend_unlock.py
git commit -m "feat: add get_session auth dependency and POST /lock endpoint — KC-008"
```

---

## Task 5: Server entry point

**Files:**
- Create: `cipherden/backend/server.py`
- Modify: `pyproject.toml`

- [ ] **Step 1: Create `server.py`**

Create `cipherden/backend/server.py`:

```python
from __future__ import annotations

import uvicorn


def main() -> None:
    uvicorn.run(
        "cipherden.backend.app:app",
        host="127.0.0.1",
        port=8765,
        workers=1,
    )


if __name__ == "__main__":
    main()
```

- [ ] **Step 2: Add the script entry point to `pyproject.toml`**

Find the `[project.scripts]` section in `pyproject.toml` and add the second entry:

```toml
[project.scripts]
cipherden = "cipherden.cli.main:app"
cipherden-server = "cipherden.backend.server:main"
```

- [ ] **Step 3: Re-install to register the new entry point**

```bash
pip install -e ".[dev]"
```

Expected: installs cleanly with no errors.

- [ ] **Step 4: Smoke test the server**

In one terminal:

```bash
cipherden-server
```

Expected output includes:
```
INFO:     Started server process [...]
INFO:     Uvicorn running on http://127.0.0.1:8765 (Press CTRL+C to quit)
```

In a second terminal, verify the routes are registered:

```bash
curl -s http://127.0.0.1:8765/openapi.json | python3 -c "import sys,json; print(list(json.load(sys.stdin)['paths'].keys()))"
```

Expected: `['/unlock', '/lock']`

Stop the server with `Ctrl+C`.

- [ ] **Step 5: Run the full suite with coverage**

```bash
pytest -v --cov
```

Expected: all tests PASS, coverage ≥ 85%.

- [ ] **Step 6: Commit**

```bash
git add cipherden/backend/server.py pyproject.toml
git commit -m "feat: add cipherden-server entry point bound to 127.0.0.1:8765 — KC-008"
```
