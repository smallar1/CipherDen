from __future__ import annotations

from pydantic import BaseModel, ConfigDict


class UnlockRequest(BaseModel):
    model_config = ConfigDict(hide_input_in_errors=True)
    master_password: str

    def __repr__(self) -> str:
        return "UnlockRequest(master_password='[REDACTED]')"


class UnlockResponse(BaseModel):
    token: str


class GenerateResponse(BaseModel):
    password: str
