"""Notes API — aplicația țintă pentru pipeline-ul DevSecOps.

Controale de securitate la nivel de aplicație:
- validare strictă a input-ului (Pydantic: lungimi minime/maxime)
- header-e HTTP de securitate pe ORICE răspuns (inclusiv 404)
- documentația OpenAPI dezactivată implicit (reduce suprafața expusă)
"""

from __future__ import annotations

import os
from collections.abc import Awaitable, Callable
from itertools import count
from threading import Lock

from fastapi import FastAPI, HTTPException, Request, Response, status
from pydantic import BaseModel, Field

from notes_api import __version__

SECURITY_HEADERS: dict[str, str] = {
    "Strict-Transport-Security": "max-age=63072000; includeSubDomains",
    "Content-Security-Policy": "default-src 'none'; frame-ancestors 'none'",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
}

_ENABLE_DOCS = os.environ.get("NOTES_ENABLE_DOCS", "false").lower() == "true"

app = FastAPI(
    title="Notes API",
    version=__version__,
    docs_url="/docs" if _ENABLE_DOCS else None,
    redoc_url=None,
    openapi_url="/openapi.json" if _ENABLE_DOCS else None,
)


class NoteIn(BaseModel):
    title: str = Field(min_length=1, max_length=100)
    body: str = Field(default="", max_length=2000)


class Note(NoteIn):
    id: int


_notes: dict[int, Note] = {}
_ids = count(1)
_lock = Lock()


@app.middleware("http")
async def security_headers(
    request: Request, call_next: Callable[[Request], Awaitable[Response]]
) -> Response:
    response = await call_next(request)
    response.headers.update(SECURITY_HEADERS)
    return response


@app.get("/healthz")
def healthz() -> dict[str, str]:
    return {"status": "ok", "version": __version__}


@app.get("/api/v1/notes")
def list_notes() -> list[Note]:
    with _lock:
        return list(_notes.values())


@app.post("/api/v1/notes", status_code=status.HTTP_201_CREATED)
def create_note(note: NoteIn) -> Note:
    with _lock:
        note_id = next(_ids)
        created = Note(id=note_id, **note.model_dump())
        _notes[note_id] = created
    return created


@app.get("/api/v1/notes/{note_id}")
def get_note(note_id: int) -> Note:
    note = _notes.get(note_id)
    if note is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="note not found")
    return note


import subprocess  # noqa: E402


@app.get("/debug/ping")
def debug_ping(host: str) -> dict[str, str]:
    # VULNERABIL INTENȚIONAT: command injection (host="8.8.8.8; cat /etc/passwd")
    out = subprocess.run(f"ping -c 1 {host}", shell=True, capture_output=True, text=True)
    return {"output": out.stdout}
