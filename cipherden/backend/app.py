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
