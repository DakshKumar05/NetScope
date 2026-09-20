from __future__ import annotations

import abc
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field

from app.core.enums import PortState, Protocol


@dataclass(slots=True)
class PortResult:
    host: str
    port: int
    protocol: str = Protocol.TCP
    state: str = PortState.CLOSED
    latency_ms: float | None = None
    service_hint: str | None = None

    @property
    def is_open(self) -> bool:
        return self.state in (PortState.OPEN, PortState.OPEN_FILTERED)


@dataclass(slots=True)
class HostResult:
    ip: str
    hostname: str | None = None
    status: str = "unknown"
    ports: list[PortResult] = field(default_factory=list)

    @property
    def open_ports(self) -> list[PortResult]:
        return [p for p in self.ports if p.is_open]


ProgressCallback = Callable[[int, int], Awaitable[None]]


class Scanner(abc.ABC):
    """Port-scanning engine interface.

    The pipeline only ever talks to this surface, so the socket engine can be
    swapped for Nmap - or later a raw SYN engine - without touching callers.
    """

    name: str = "base"

    @abc.abstractmethod
    async def scan_host(
        self,
        host: str,
        ports: list[int],
        *,
        protocol: str = Protocol.TCP,
        on_progress: ProgressCallback | None = None,
    ) -> HostResult: ...

    @abc.abstractmethod
    async def scan_network(
        self,
        hosts: list[str],
        ports: list[int],
        *,
        protocol: str = Protocol.TCP,
        on_progress: ProgressCallback | None = None,
    ) -> list[HostResult]: ...

    async def discover(self, hosts: list[str], *, probe_ports: list[int]) -> list[str]:
        """Return the subset of hosts that answer on at least one probe port."""
        results = await self.scan_network(hosts, probe_ports)
        return [r.ip for r in results if r.open_ports]
