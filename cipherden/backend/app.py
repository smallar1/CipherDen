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
        ) from None
    except WrongPasswordError:
        raise HTTPException(
            status_code=401,
            detail="Incorrect master password.",
            headers={"WWW-Authenticate": 'Bearer realm="CipherDen"'},
        ) from None
    token = store.create(session)
    return UnlockResponse(token=token)
