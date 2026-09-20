from __future__ import annotations

import abc
import asyncio
import contextlib
from dataclasses import dataclass, field
from typing import Any

from app.config import settings
from app.core.enums import Confidence


@dataclass(slots=True)
class ServiceInfo:
    name: str = "unknown"
    product: str | None = None
    version: str | None = None
    banner: str | None = None
    confidence: str = Confidence.POSSIBLE
    details: dict[str, Any] = field(default_factory=dict)

    @property
    def identified(self) -> bool:
        return self.name != "unknown"


class ServiceDetector(abc.ABC):
    """One protocol's worth of safe, read-only identification logic."""

    name: str = "generic"
    # Ports this detector volunteers for. Empty means "offer on any port".
    ports: tuple[int, ...] = ()

    def handles(self, port: int, hint: str | None) -> bool:
        return port in self.ports

    @abc.abstractmethod
    async def detect(self, host: str, port: int) -> ServiceInfo | None: ...


async def read_banner(
    host: str,
    port: int,
    *,
    timeout: float,
    send: bytes | None = None,
    limit: int | None = None,
) -> str | None:
    """Open a connection, optionally send one benign probe, read what comes back."""
    limit = limit or settings.banner_read_bytes
    writer = None
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout
        )
        if send:
            writer.write(send)
            await asyncio.wait_for(writer.drain(), timeout=timeout)
        data = await asyncio.wait_for(reader.read(limit), timeout=timeout)
        if not data:
            return None
        return data.decode("utf-8", errors="replace").strip()
    except (asyncio.TimeoutError, OSError, ConnectionResetError):
        return None
    finally:
        if writer is not None:
            writer.close()
            with contextlib.suppress(Exception):
                await writer.wait_closed()
