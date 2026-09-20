"""TCP connect + conservative UDP scanning built on asyncio.

TCP uses a full connect() rather than a raw SYN probe: it needs no elevated
privileges and leaves a normal, honest connection in the target's logs. The
interface is shaped so a SYN engine can replace it later.
"""

from __future__ import annotations

import asyncio
import contextlib
import socket
import time

from app.config import settings
from app.core.enums import HostStatus, PortState, Protocol
from app.core.ratelimit import RateLimiter
from app.services.scanner.base import HostResult, PortResult, ProgressCallback, Scanner

# Ports whose UDP services reliably answer a well-formed, read-only probe.
# Each payload is an ordinary protocol question, not a malformed or amplifying one.
_UDP_PROBES: dict[int, bytes] = {
    # DNS query for the root zone, NS record - a normal resolver question.
    53: bytes.fromhex("abcd" "0100" "0001" "0000" "0000" "0000" "00" "0002" "0001"),
    # NTP v3 client request.
    123: b"\x1b" + b"\0" * 47,
    # SNMPv1 get-request for sysDescr.0 with the default "public" community.
    # Reading sysDescr is a query, not an authentication attempt.
    161: bytes.fromhex(
        "3027" "020100" "0406" "7075626c6963" "a01a"
        "02020001" "020100" "020100"
        "300e" "300c" "0608" "2b06010201010100" "0500"
    ),
    # SSDP discovery (M-SEARCH) - the standard UPnP discovery message.
    1900: (
        b"M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\n"
        b'MAN: "ssdp:discover"\r\nMX: 1\r\nST: ssdp:all\r\n\r\n'
    ),
}

_SERVICE_HINTS: dict[int, str] = {
    21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns", 67: "dhcp",
    68: "dhcp", 80: "http", 110: "pop3", 111: "rpcbind", 123: "ntp",
    135: "msrpc", 139: "netbios-ssn", 143: "imap", 161: "snmp", 389: "ldap",
    443: "https", 445: "smb", 465: "smtps", 500: "isakmp", 587: "smtp",
    636: "ldaps", 993: "imaps", 995: "pop3s", 1433: "mssql", 1521: "oracle",
    1900: "ssdp", 3000: "http", 3306: "mysql", 3389: "rdp", 5000: "http",
    5432: "postgresql", 5601: "kibana", 5672: "amqp", 5900: "vnc",
    6379: "redis", 8000: "http", 8080: "http", 8443: "https", 8888: "http",
    9000: "http", 9090: "http", 9200: "elasticsearch", 11211: "memcached",
    15672: "rabbitmq-mgmt", 27017: "mongodb",
}


def service_hint(port: int) -> str | None:
    return _SERVICE_HINTS.get(port)


class SocketScanner(Scanner):
    name = "socket"

    def __init__(
        self,
        *,
        timeout: float | None = None,
        concurrency: int | None = None,
        rate_per_second: int | None = None,
        cancel_event: asyncio.Event | None = None,
    ) -> None:
        self.timeout = float(timeout or settings.default_timeout)
        requested = int(concurrency or settings.default_concurrency)
        self.concurrency = max(1, min(requested, settings.max_concurrency))
        self._sem = asyncio.Semaphore(self.concurrency)
        self._limiter = RateLimiter(rate_per_second or settings.rate_limit_per_second)
        self._cancel = cancel_event or asyncio.Event()

    @property
    def cancelled(self) -> bool:
        return self._cancel.is_set()

    def cancel(self) -> None:
        self._cancel.set()

    async def _probe_tcp(self, host: str, port: int) -> PortResult:
        if self.cancelled:
            return PortResult(host=host, port=port, state=PortState.UNKNOWN)

        await self._limiter.acquire()
        async with self._sem:
            if self.cancelled:
                return PortResult(host=host, port=port, state=PortState.UNKNOWN)
            started = time.perf_counter()
            writer = None
            try:
                _, writer = await asyncio.wait_for(
                    asyncio.open_connection(host, port), timeout=self.timeout
                )
                latency = (time.perf_counter() - started) * 1000
                return PortResult(
                    host=host,
                    port=port,
                    protocol=Protocol.TCP,
                    state=PortState.OPEN,
                    latency_ms=round(latency, 2),
                    service_hint=service_hint(port),
                )
            except asyncio.TimeoutError:
                return PortResult(
                    host=host, port=port, protocol=Protocol.TCP, state=PortState.FILTERED
                )
            except (ConnectionRefusedError, OSError):
                return PortResult(
                    host=host, port=port, protocol=Protocol.TCP, state=PortState.CLOSED
                )
            finally:
                if writer is not None:
                    writer.close()
                    with contextlib.suppress(Exception):
                        await writer.wait_closed()

    async def _probe_udp(self, host: str, port: int) -> PortResult:
        """UDP is inferential, never definitive.

        Silence means "open or filtered" - it is not evidence of a service.
        An ICMP port-unreachable surfaces as a connection error, which is the
        only signal that reliably means closed.
        """
        if self.cancelled:
            return PortResult(host=host, port=port, protocol=Protocol.UDP, state=PortState.UNKNOWN)

        await self._limiter.acquire()
        async with self._sem:
            payload = _UDP_PROBES.get(port, b"\x00")
            loop = asyncio.get_running_loop()
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.setblocking(False)
            started = time.perf_counter()
            try:
                await loop.sock_connect(sock, (host, port))
                await loop.sock_sendall(sock, payload)
                data = await asyncio.wait_for(loop.sock_recv(sock, 1024), timeout=self.timeout)
                latency = (time.perf_counter() - started) * 1000
                state = PortState.OPEN if data else PortState.OPEN_FILTERED
                return PortResult(
                    host=host,
                    port=port,
                    protocol=Protocol.UDP,
                    state=state,
                    latency_ms=round(latency, 2),
                    service_hint=service_hint(port),
                )
            except asyncio.TimeoutError:
                return PortResult(
                    host=host,
                    port=port,
                    protocol=Protocol.UDP,
                    state=PortState.OPEN_FILTERED,
                    service_hint=service_hint(port),
                )
            except ConnectionRefusedError:
                return PortResult(
                    host=host, port=port, protocol=Protocol.UDP, state=PortState.CLOSED
                )
            except OSError:
                return PortResult(
                    host=host, port=port, protocol=Protocol.UDP, state=PortState.UNKNOWN
                )
            finally:
                sock.close()

    async def scan_host(
        self,
        host: str,
        ports: list[int],
        *,
        protocol: str = Protocol.TCP,
        on_progress: ProgressCallback | None = None,
    ) -> HostResult:
        results = await self._run_probes([(host, p) for p in ports], protocol, on_progress)
        return self._collect(host, results)

    async def scan_network(
        self,
        hosts: list[str],
        ports: list[int],
        *,
        protocol: str = Protocol.TCP,
        on_progress: ProgressCallback | None = None,
    ) -> list[HostResult]:
        pairs = [(h, p) for h in hosts for p in ports]
        results = await self._run_probes(pairs, protocol, on_progress)
        by_host: dict[str, list[PortResult]] = {h: [] for h in hosts}
        for r in results:
            by_host.setdefault(r.host, []).append(r)
        return [self._collect(h, by_host.get(h, [])) for h in hosts]

    async def _run_probes(
        self,
        pairs: list[tuple[str, int]],
        protocol: str,
        on_progress: ProgressCallback | None,
    ) -> list[PortResult]:
        total = len(pairs)
        if total == 0:
            return []
        probe = self._probe_udp if protocol == Protocol.UDP else self._probe_tcp
        results: list[PortResult] = []
        done = 0

        tasks = [asyncio.create_task(probe(h, p)) for h, p in pairs]
        try:
            for coro in asyncio.as_completed(tasks):
                results.append(await coro)
                done += 1
                if on_progress is not None and (done % 25 == 0 or done == total):
                    await on_progress(done, total)
        except asyncio.CancelledError:
            for t in tasks:
                t.cancel()
            raise
        return results

    @staticmethod
    def _collect(host: str, results: list[PortResult]) -> HostResult:
        ordered = sorted(results, key=lambda r: (r.protocol, r.port))
        # Any definite response - open or a refusal - proves the host is alive.
        responsive = any(
            r.state in (PortState.OPEN, PortState.CLOSED, PortState.OPEN_FILTERED)
            for r in ordered
        )
        has_open = any(r.is_open for r in ordered)
        status = HostStatus.UP if (has_open or responsive) else HostStatus.DOWN
        # Only open results are persisted. A /24 of timed-out ports is noise,
        # not evidence, and storing it would bury the real findings.
        return HostResult(ip=host, status=status, ports=[r for r in ordered if r.is_open])
