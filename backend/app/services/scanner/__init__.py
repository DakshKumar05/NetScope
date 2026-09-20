from __future__ import annotations

import asyncio

from app.services.scanner.base import HostResult, PortResult, Scanner
from app.services.scanner.nmap_scanner import NmapScanner, nmap_available
from app.services.scanner.socket_scanner import SocketScanner, service_hint


def build_scanner(
    engine: str = "auto",
    *,
    timeout: float | None = None,
    concurrency: int | None = None,
    cancel_event: asyncio.Event | None = None,
) -> Scanner:
    """Pick an engine. Falls back to sockets whenever Nmap is unavailable."""
    if engine == "nmap" and nmap_available():
        return NmapScanner(timeout=timeout, concurrency=concurrency, cancel_event=cancel_event)
    return SocketScanner(timeout=timeout, concurrency=concurrency, cancel_event=cancel_event)


__all__ = [
    "HostResult",
    "NmapScanner",
    "PortResult",
    "Scanner",
    "SocketScanner",
    "build_scanner",
    "nmap_available",
    "service_hint",
]
