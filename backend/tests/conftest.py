from __future__ import annotations

import asyncio
import socket
import threading
from collections.abc import Iterator

import pytest


@pytest.fixture
def tcp_server() -> Iterator[tuple[str, int]]:
    """A local TCP listener that sends a fixed banner on connect.

    Tests never touch an external host: everything they probe is started here.
    """
    banner = b"SSH-2.0-OpenSSH_9.6p1 Test\r\n"
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(("127.0.0.1", 0))
    server.listen(8)
    host, port = server.getsockname()
    stop = threading.Event()

    def serve() -> None:
        server.settimeout(0.3)
        while not stop.is_set():
            try:
                conn, _ = server.accept()
            except (TimeoutError, OSError):
                continue
            try:
                conn.sendall(banner)
            except OSError:
                pass
            finally:
                conn.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    try:
        yield host, port
    finally:
        stop.set()
        thread.join(timeout=2)
        server.close()


@pytest.fixture
def closed_port() -> int:
    """A port number nothing is listening on."""
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.bind(("127.0.0.1", 0))
    port = probe.getsockname()[1]
    probe.close()
    return port


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"


def run(coro):
    """Small helper so tests can call async code without a plugin dependency."""
    return asyncio.run(coro)
