from __future__ import annotations

from pydantic import BaseModel


class UnlockRequest(BaseModel):
    master_password: str


class UnlockResponse(BaseModel):
    token: str
