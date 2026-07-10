"""Length-prefixed msgpack framing over asyncio streams.

Each frame:
    4 bytes — unsigned big-endian length
    N bytes — msgpack payload (a dict)

Every payload has a {"type": "..."} key. That's the only requirement the
wire format imposes; dispatcher and worker agree on the type vocabulary.

Bidirectional: both parent → worker and worker → parent share the same
framing. The caller owns the StreamReader/StreamWriter pair.
"""
from __future__ import annotations

import asyncio
import struct
from typing import Any, AsyncIterator

import msgpack


_HEADER = struct.Struct(">I")


async def send_frame(w: asyncio.StreamWriter, obj: dict[str, Any]) -> None:
    """Serialize obj and write a length-prefixed frame. No-op on closed writer."""
    if w.is_closing():
        return
    body = msgpack.packb(obj, use_bin_type=True)
    w.write(_HEADER.pack(len(body)) + body)
    try:
        await w.drain()
    except (ConnectionResetError, BrokenPipeError):
        pass


async def recv_frame(r: asyncio.StreamReader) -> dict[str, Any] | None:
    """Read one frame. Returns None on clean EOF. Raises on framing error."""
    try:
        hdr = await r.readexactly(_HEADER.size)
    except asyncio.IncompleteReadError:
        return None
    (n,) = _HEADER.unpack(hdr)
    if n <= 0 or n > 128 * 1024 * 1024:  # 128 MB cap — screenshots are the biggest
        raise ValueError(f"rpc: bad frame length {n}")
    body = await r.readexactly(n)
    return msgpack.unpackb(body, raw=False)


async def iter_frames(r: asyncio.StreamReader) -> AsyncIterator[dict[str, Any]]:
    """Async iterator over frames until EOF."""
    while True:
        f = await recv_frame(r)
        if f is None:
            return
        yield f
