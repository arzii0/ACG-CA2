"""Small length-prefixed JSON protocol used by the client and server."""

from __future__ import annotations

import json
import socket
import struct
from typing import Any

MAX_FRAME_BYTES = 50 * 1024 * 1024


def _read_exact(sock: socket.socket, size: int) -> bytes:
    chunks: list[bytes] = []
    remaining = size
    while remaining:
        chunk = sock.recv(remaining)
        if not chunk:
            raise ConnectionError("Connection closed while reading a frame")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def send_json(sock: socket.socket, message: dict[str, Any]) -> None:
    body = json.dumps(message, separators=(",", ":"), sort_keys=True).encode("utf-8")
    if len(body) > MAX_FRAME_BYTES:
        raise ValueError("Message is too large for one protocol frame")
    sock.sendall(struct.pack("!I", len(body)) + body)


def recv_json(sock: socket.socket) -> dict[str, Any]:
    header = _read_exact(sock, 4)
    (size,) = struct.unpack("!I", header)
    if size > MAX_FRAME_BYTES:
        raise ValueError("Protocol frame is too large")
    return json.loads(_read_exact(sock, size).decode("utf-8"))

