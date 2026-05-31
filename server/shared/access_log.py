"""Small helpers for human-readable stdout access logs."""

from __future__ import annotations

import time
from typing import Any


def log_event(component: str, message: str) -> None:
    print(f"{_timestamp()} [{component}] {message}", flush=True)


def log_access(
    component: str,
    client: Any,
    method: str,
    target: str,
    status: int | str,
    duration_ms: int,
    extra: str = "",
) -> None:
    line = (
        f'{_timestamp()} [{component}] {peer_label(client)} '
        f'"{method} {target}" -> {status} {duration_ms}ms'
    )
    if extra:
        line = f"{line} {extra}"
    print(line, flush=True)


def peer_label(peer: Any) -> str:
    if isinstance(peer, tuple):
        if len(peer) >= 2:
            return f"{peer[0]}:{peer[1]}"
        if len(peer) == 1:
            return str(peer[0])
    return str(peer or "-")


def request_line_from_raw(raw_request: bytes) -> tuple[str, str]:
    if not raw_request:
        return "-", "-"
    first_line = raw_request.split(b"\r\n", 1)[0].split(b"\n", 1)[0]
    line = first_line.decode("iso-8859-1", errors="replace").strip()
    if not line:
        return "-", "-"
    parts = line.split()
    method = parts[0] if len(parts) >= 1 else "-"
    target = parts[1] if len(parts) >= 2 else "-"
    return method, target


def _timestamp() -> str:
    return time.strftime("%H:%M:%S")
