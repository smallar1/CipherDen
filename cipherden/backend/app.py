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
        ) from None
    except WrongPasswordError:
        raise HTTPException(
            status_code=401,
            detail="Incorrect master password.",
            headers={"WWW-Authenticate": 'Bearer realm="CipherDen"'},
        ) from None
    token = store.create(session)
    return UnlockResponse(token=token)


@app.post("/lock", status_code=204)
def lock(
    credentials: Annotated[HTTPAuthorizationCredentials, Depends(_bearer)],
    _session: Annotated[VaultSession, Depends(get_session)],
) -> None:
    # get_session already validated the token; revoke it to zero the key.
    store.revoke(credentials.credentials)
