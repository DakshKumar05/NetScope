"""Model -> schema conversion, kept out of the route handlers."""

from __future__ import annotations

from app.core.enums import PortState, Severity
from app.models import Finding, Host, Port, Scan
from app.schemas.scan import (
    FindingRead,
    HostDetail,
    HostRead,
    PortRead,
    ScanDetail,
    ScanRead,
    ServiceRead,
)


def severity_counts(findings: list[Finding]) -> dict[str, int]:
    counts = {level.value: 0 for level in Severity}
    for finding in findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1
    return counts


def _open_ports(host: Host) -> list[Port]:
    return [p for p in host.ports if p.state in (PortState.OPEN, PortState.OPEN_FILTERED)]


def serialize_port(port: Port) -> PortRead:
    return PortRead(
        id=port.id,
        port=port.port,
        protocol=port.protocol,
        state=port.state,
        service_name=port.service_name,
        latency_ms=port.latency_ms,
        service=ServiceRead.model_validate(port.service) if port.service else None,
    )


def serialize_host(host: Host, *, detail: bool = False) -> HostRead | HostDetail:
    base = {
        "id": host.id,
        "scan_id": host.scan_id,
        "ip": host.ip,
        "hostname": host.hostname,
        "status": host.status,
        "risk_score": host.risk_score,
        "open_port_count": len(_open_ports(host)),
    }
    if not detail:
        return HostRead(**base)
    return HostDetail(**base, ports=[serialize_port(p) for p in host.ports])


def serialize_finding(finding: Finding) -> FindingRead:
    return FindingRead(
        id=finding.id,
        scan_id=finding.scan_id,
        host_id=finding.host_id,
        port_id=finding.port_id,
        type=finding.type,
        severity=finding.severity,
        title=finding.title,
        description=finding.description,
        reason=finding.reason,
        evidence=finding.evidence,
        recommendation=finding.recommendation,
        cve_id=finding.cve_id,
        cvss=finding.cvss,
        confidence=finding.confidence,
        references=list(finding.references or []),
        extra=dict(finding.extra or {}),
        created_at=finding.created_at,
        host_ip=finding.host.ip if finding.host else None,
        port_number=_port_number(finding),
    )


def _port_number(finding: Finding) -> int | None:
    if finding.port_id is None or finding.host is None:
        return None
    for port in finding.host.ports:
        if port.id == finding.port_id:
            return port.port
    return None


def serialize_scan(scan: Scan, *, detail: bool = False) -> ScanRead | ScanDetail:
    open_ports = sum(len(_open_ports(h)) for h in scan.hosts)
    base = {
        "id": scan.id,
        "target": scan.target,
        "scan_type": scan.scan_type,
        "status": scan.status,
        "engine": scan.engine,
        "started_at": scan.started_at,
        "completed_at": scan.completed_at,
        "duration_seconds": scan.duration_seconds,
        "risk_score": scan.risk_score,
        "error": scan.error,
        "udp_enabled": scan.udp_enabled,
        "host_count": len(scan.hosts),
        "open_port_count": open_ports,
        "finding_count": len(scan.findings),
        "severity_counts": severity_counts(scan.findings),
    }
    if not detail:
        return ScanRead(**base)
    return ScanDetail(
        **base,
        hosts=[serialize_host(h, detail=True) for h in scan.hosts],
        findings=[serialize_finding(f) for f in scan.findings],
    )
