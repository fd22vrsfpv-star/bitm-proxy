"""Saved browser sessions — reusable login profiles."""

import uuid
import time
from fastapi import APIRouter
from pydantic import BaseModel

from backend.store import JsonStore

router = APIRouter()
store = JsonStore("sessions")


class SessionCreate(BaseModel):
    name: str
    login_url: str
    notes: str = ""


class SessionUpdate(BaseModel):
    name: str | None = None
    login_url: str | None = None
    notes: str | None = None
    jwt_token: str | None = None
    cookies: list[dict] | None = None


@router.get("")
async def list_sessions():
    return store.list_all()


@router.post("")
async def create_session(body: SessionCreate):
    session_id = str(uuid.uuid4())[:8]
    data = {
        "id": session_id,
        "name": body.name,
        "login_url": body.login_url,
        "notes": body.notes,
        "jwt_token": None,
        "cookies": [],
        "created_at": time.time(),
    }
    store.put(session_id, data)
    return data


@router.get("/{session_id}")
async def get_session(session_id: str):
    data = store.get(session_id)
    if not data:
        return {"error": "Not found"}
    return data


@router.patch("/{session_id}")
async def update_session(session_id: str, body: SessionUpdate):
    data = store.get(session_id)
    if not data:
        return {"error": "Not found"}
    for field, val in body.model_dump(exclude_none=True).items():
        data[field] = val
    store.put(session_id, data)
    return data


@router.delete("/{session_id}")
async def delete_session(session_id: str):
    store.delete(session_id)
    return {"deleted": session_id}
