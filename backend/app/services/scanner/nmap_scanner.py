"""Optional Nmap-backed engine.

Used only when system Nmap is present. Arguments are built as a list and
handed to ``python-nmap`` as separate tokens - no shell string is ever
constructed from a user-supplied target.
"""

from __future__ import annotations

import asyncio
import shutil
from functools import lru_cache

from app.config import settings
from app.core.enums import HostStatus, PortState, Protocol
from app.services.scanner.base import HostResult, PortResult, ProgressCallback, Scanner


@lru_cache(maxsize=1)
def nmap_available() -> bool:
    if shutil.which("nmap") is None:
        return False
    try:
        import nmap  # noqa: F401
    except ImportError:
        return False
    return True


class NmapScanner(Scanner):
    name = "nmap"

    def __init__(
        self,
        *,
        timeout: float | None = None,
        concurrency: int | None = None,
        cancel_event: asyncio.Event | None = None,
    ) -> None:
        if not nmap_available():
            raise RuntimeError(
                "Nmap engine requested but system nmap or the python-nmap package is missing."
            )
        self.timeout = float(timeout or settings.default_timeout)
        self.concurrency = int(concurrency or settings.default_concurrency)
        self._cancel = cancel_event or asyncio.Event()

    def cancel(self) -> None:
        self._cancel.set()

    def _arguments(self, protocol: str) -> str:
        # -sT connect scan needs no privileges; -sV reads service banners.
        # -T3 keeps timing polite. No evasion or decoy flags, by design.
        base = ["-sV", "--version-intensity", "2", "-T3", "-Pn", "--open"]
        base.append("-sU" if protocol == Protocol.UDP else "-sT")
        return " ".join(base)

    def _run_sync(self, hosts: list[str], ports: list[int], protocol: str) -> list[HostResult]:
        import nmap

        scanner = nmap.PortScanner()
        port_spec = ",".join(str(p) for p in ports)
        scanner.scan(
            hosts=" ".join(hosts),
            ports=port_spec,
            arguments=self._arguments(protocol),
        )

        results: list[HostResult] = []
        for ip in hosts:
            if ip not in scanner.all_hosts():
                results.append(HostResult(ip=ip, status=HostStatus.DOWN))
                continue
            entry = scanner[ip]
            hostname = entry.hostname() or None
            port_results: list[PortResult] = []
            proto_key = "udp" if protocol == Protocol.UDP else "tcp"
            discovered = entry[proto_key] if proto_key in entry.all_protocols() else {}
            for port, info in discovered.items():
                state = info.get("state", "unknown")
                mapped = {
                    "open": PortState.OPEN,
                    "closed": PortState.CLOSED,
                    "filtered": PortState.FILTERED,
                    "open|filtered": PortState.OPEN_FILTERED,
                }.get(state, PortState.UNKNOWN)
                if mapped not in (PortState.OPEN, PortState.OPEN_FILTERED):
                    continue
                port_results.append(
                    PortResult(
                        host=ip,
                        port=int(port),
                        protocol=protocol,
                        state=mapped,
                        service_hint=info.get("name") or None,
                    )
                )
            results.append(
                HostResult(
                    ip=ip,
                    hostname=hostname,
                    status=HostStatus.UP if port_results else HostStatus.DOWN,
                    ports=sorted(port_results, key=lambda r: r.port),
                )
            )
        return results

    async def scan_network(
        self,
        hosts: list[str],
        ports: list[int],
        *,
        protocol: str = Protocol.TCP,
        on_progress: ProgressCallback | None = None,
    ) -> list[HostResult]:
        if on_progress is not None:
            await on_progress(0, len(hosts))
        results = await asyncio.to_thread(self._run_sync, hosts, ports, protocol)
        if on_progress is not None:
            await on_progress(len(hosts), len(hosts))
        return results

    async def scan_host(
        self,
        host: str,
        ports: list[int],
        *,
        protocol: str = Protocol.TCP,
        on_progress: ProgressCallback | None = None,
    ) -> HostResult:
        results = await self.scan_network([host], ports, protocol=protocol, on_progress=on_progress)
        return results[0] if results else HostResult(ip=host, status=HostStatus.DOWN)
