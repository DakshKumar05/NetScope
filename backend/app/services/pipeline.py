"""The scan pipeline.

    validate -> discover -> port scan -> fingerprint -> vuln lookup
    -> misconfiguration checks -> risk -> persist

Each stage reports progress through a callback so the API can stream it, and
every stage checks for cancellation so a stopped scan actually stops.
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field

from app.core.enums import HostStatus, Protocol, ScanPhase
from app.core.findings import FindingDraft
from app.core.targets import ResolvedTarget, parse_ports, parse_target, parse_udp_ports
from app.services.fingerprinting.base import ServiceInfo
from app.services.fingerprinting.registry import registry
from app.services.misconfiguration.checks import run_checks
from app.services.risk import RiskBreakdown, score_findings
from app.services.scanner import build_scanner
from app.services.scanner.base import HostResult, PortResult
from app.services.vulnerability.service import VulnerabilityService

logger = logging.getLogger(__name__)

ProgressHook = Callable[[str, float, str], Awaitable[None]]


@dataclass(slots=True)
class PortFinding:
    port: PortResult
    service: ServiceInfo
    findings: list[FindingDraft] = field(default_factory=list)


@dataclass(slots=True)
class HostOutcome:
    ip: str
    hostname: str | None
    status: str
    ports: list[PortFinding] = field(default_factory=list)
    risk: RiskBreakdown | None = None

    @property
    def findings(self) -> list[FindingDraft]:
        return [f for p in self.ports for f in p.findings]


@dataclass(slots=True)
class ScanOutcome:
    target: ResolvedTarget
    hosts: list[HostOutcome]
    risk: RiskBreakdown
    engine: str
    cancelled: bool = False

    @property
    def findings(self) -> list[FindingDraft]:
        return [f for h in self.hosts for f in h.findings]


class ScanCancelled(Exception):
    """Raised when a scan is stopped before completion."""


@dataclass(slots=True)
class ScanRequest:
    target: str
    profile: str = "quick"
    ports: str | None = None
    udp: bool = False
    udp_ports: str | None = None
    timeout: float | None = None
    concurrency: int | None = None
    engine: str = "auto"


class ScanPipeline:
    def __init__(
        self,
        request: ScanRequest,
        *,
        on_progress: ProgressHook | None = None,
        cancel_event: asyncio.Event | None = None,
        vulnerability_service: VulnerabilityService | None = None,
    ) -> None:
        self.request = request
        self._on_progress = on_progress
        self._cancel = cancel_event or asyncio.Event()
        self._vulns = vulnerability_service or VulnerabilityService()

    def cancel(self) -> None:
        self._cancel.set()

    async def close(self) -> None:
        """Release the HTTP clients held by the vulnerability providers."""
        await self._vulns.close()

    def _check_cancelled(self) -> None:
        if self._cancel.is_set():
            raise ScanCancelled()

    async def _report(self, phase: str, progress: float, message: str = "") -> None:
        if self._on_progress is not None:
            await self._on_progress(phase, max(0.0, min(1.0, progress)), message)

    async def run(self) -> ScanOutcome:
        req = self.request

        # --- validate -------------------------------------------------------
        await self._report(ScanPhase.VALIDATION, 0.0, f"Validating target {req.target}")
        target = parse_target(req.target)
        tcp_ports = parse_ports(req.ports, profile=req.profile)
        udp_ports = parse_udp_ports(req.udp_ports) if req.udp else []
        await self._report(
            ScanPhase.VALIDATION,
            1.0,
            f"{target.count} host(s), {len(tcp_ports)} TCP port(s)"
            + (f", {len(udp_ports)} UDP port(s)" if udp_ports else ""),
        )
        self._check_cancelled()

        scanner = build_scanner(
            req.engine,
            timeout=req.timeout,
            concurrency=req.concurrency,
            cancel_event=self._cancel,
        )

        # --- discover -------------------------------------------------------
        # A single host is scanned directly; sweeping a range first avoids
        # spending the full port list on addresses nobody is using.
        if target.count > 1:
            await self._report(
                ScanPhase.DISCOVERY, 0.0, f"Probing {target.count} addresses for liveness"
            )
            probe_ports = sorted({80, 443, 22, 445, 3389} & set(tcp_ports)) or tcp_ports[:5]
            sweep = await scanner.scan_network(
                target.addresses,
                probe_ports,
                on_progress=lambda done, total: self._report(
                    ScanPhase.DISCOVERY, done / total, f"{done}/{total} probes"
                ),
            )
            live = [h.ip for h in sweep if h.status == HostStatus.UP]
            await self._report(
                ScanPhase.DISCOVERY, 1.0, f"{len(live)} of {target.count} addresses responded"
            )
        else:
            live = list(target.addresses)
            await self._report(ScanPhase.DISCOVERY, 1.0, "Single host - discovery skipped")

        self._check_cancelled()

        if not live:
            empty = score_findings([])
            return ScanOutcome(target=target, hosts=[], risk=empty, engine=scanner.name)

        # --- port scan ------------------------------------------------------
        await self._report(ScanPhase.PORT_SCAN, 0.0, f"Scanning {len(tcp_ports)} TCP ports")
        host_results = await scanner.scan_network(
            live,
            tcp_ports,
            on_progress=lambda done, total: self._report(
                ScanPhase.PORT_SCAN, done / total, f"{done}/{total} TCP probes"
            ),
        )
        self._check_cancelled()

        if udp_ports:
            await self._report(ScanPhase.PORT_SCAN, 1.0, "Scanning UDP ports")
            udp_results = await scanner.scan_network(
                live,
                udp_ports,
                protocol=Protocol.UDP,
                on_progress=lambda done, total: self._report(
                    ScanPhase.PORT_SCAN, done / total, f"{done}/{total} UDP probes"
                ),
            )
            merged = {h.ip: h for h in host_results}
            for udp_host in udp_results:
                existing = merged.get(udp_host.ip)
                if existing is None:
                    merged[udp_host.ip] = udp_host
                else:
                    existing.ports.extend(udp_host.ports)
                    if udp_host.open_ports:
                        existing.status = HostStatus.UP
            host_results = list(merged.values())

        await self._report(ScanPhase.PORT_SCAN, 1.0, "Port scanning complete")
        self._check_cancelled()

        for result in host_results:
            result.hostname = target.hostnames.get(result.ip)

        # --- fingerprint + vuln + misconfig ---------------------------------
        outcomes = await self._analyse(host_results)

        # --- risk -----------------------------------------------------------
        await self._report(ScanPhase.RISK, 0.5, "Calculating risk")
        for host in outcomes:
            host.risk = score_findings(host.findings)
        all_findings = [f for h in outcomes for f in h.findings]
        overall = score_findings(all_findings)
        await self._report(
            ScanPhase.RISK, 1.0, f"{len(all_findings)} finding(s), risk score {overall.score}"
        )

        return ScanOutcome(
            target=target, hosts=outcomes, risk=overall, engine=scanner.name
        )

    async def _analyse(self, host_results: list[HostResult]) -> list[HostOutcome]:
        open_pairs = [(h, p) for h in host_results for p in h.open_ports]
        total = len(open_pairs)
        outcomes = {
            h.ip: HostOutcome(ip=h.ip, hostname=h.hostname, status=h.status)
            for h in host_results
        }

        if total == 0:
            await self._report(ScanPhase.FINGERPRINT, 1.0, "No open ports to fingerprint")
            return list(outcomes.values())

        await self._report(ScanPhase.FINGERPRINT, 0.0, f"Fingerprinting {total} open port(s)")

        # Fingerprinting is I/O bound but touches live services; keep it modest.
        semaphore = asyncio.Semaphore(20)
        completed = 0
        lock = asyncio.Lock()

        async def analyse_port(host: HostResult, port: PortResult) -> tuple[str, PortFinding]:
            nonlocal completed
            async with semaphore:
                self._check_cancelled()
                if port.protocol == Protocol.UDP:
                    # UDP responses are too thin to fingerprint honestly.
                    service = ServiceInfo(name=port.service_hint or "unknown")
                else:
                    service = await registry.identify(host.ip, port.port, port.service_hint)

                findings = await run_checks(host.ip, port.port, port.protocol, service)
            async with lock:
                completed += 1
                await self._report(
                    ScanPhase.FINGERPRINT, completed / total, f"{completed}/{total} services"
                )
            return host.ip, PortFinding(port=port, service=service, findings=findings)

        results = await asyncio.gather(
            *(analyse_port(h, p) for h, p in open_pairs), return_exceptions=True
        )

        collected: list[tuple[str, PortFinding]] = []
        for item in results:
            if isinstance(item, ScanCancelled):
                raise item
            if isinstance(item, BaseException):
                logger.debug("port analysis failed", exc_info=item)
                continue
            collected.append(item)

        self._check_cancelled()

        # --- vulnerability lookup ------------------------------------------
        identified = [
            (ip, pf) for ip, pf in collected if pf.service.product and pf.service.version
        ]
        lookup_total = len(identified) or 1
        await self._report(
            ScanPhase.VULN_LOOKUP,
            0.0,
            f"Checking {len(identified)} identified service(s) against vulnerability feeds",
        )

        for index, (_, port_finding) in enumerate(identified, start=1):
            self._check_cancelled()
            try:
                vuln_findings = await self._vulns.build_findings(
                    port_finding.port.port,
                    port_finding.port.protocol,
                    port_finding.service,
                )
                port_finding.findings.extend(vuln_findings)
            except Exception:  # noqa: BLE001 - feeds are best-effort
                logger.debug("vulnerability lookup failed", exc_info=True)
            await self._report(
                ScanPhase.VULN_LOOKUP,
                index / lookup_total,
                f"{index}/{len(identified)} services checked",
            )

        await self._report(ScanPhase.VULN_LOOKUP, 1.0, "Vulnerability lookup complete")

        for ip, port_finding in collected:
            outcomes[ip].ports.append(port_finding)
        for outcome in outcomes.values():
            outcome.ports.sort(key=lambda pf: (pf.port.protocol, pf.port.port))

        return list(outcomes.values())
