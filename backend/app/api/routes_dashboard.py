from __future__ import annotations

from fastapi import APIRouter, Depends, Query
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from app.api.deps import get_session
from app.api.serializers import serialize_scan
from app.core.enums import PortState, ScanStatus, Severity
from app.models import Finding, Host, Port, Scan, Service
from app.schemas.dashboard import (
    DashboardSummary,
    ExposedHost,
    SeverityCount,
    TrendPoint,
    TrendResponse,
)

router = APIRouter(prefix="/api/dashboard", tags=["dashboard"])

_OPEN_STATES = (PortState.OPEN, PortState.OPEN_FILTERED)


@router.get("/summary", response_model=DashboardSummary)
def summary(session: Session = Depends(get_session)) -> DashboardSummary:
    total_scans = session.scalar(select(func.count()).select_from(Scan)) or 0
    hosts_discovered = session.scalar(select(func.count()).select_from(Host)) or 0
    open_ports = (
        session.scalar(
            select(func.count()).select_from(Port).where(Port.state.in_(_OPEN_STATES))
        )
        or 0
    )
    services_detected = (
        session.scalar(
            select(func.count()).select_from(Service).where(Service.name != "unknown")
        )
        or 0
    )

    severity_rows = session.execute(
        select(Finding.severity, func.count()).group_by(Finding.severity)
    ).all()
    counts = SeverityCount(
        **{
            str(level): count
            for level, count in severity_rows
            if str(level) in SeverityCount.model_fields
        }
    )

    recent = session.scalars(
        select(Scan).order_by(Scan.started_at.desc()).limit(5)
    ).all()

    latest_completed = session.scalars(
        select(Scan)
        .where(Scan.status == ScanStatus.COMPLETED)
        .order_by(Scan.started_at.desc())
        .limit(1)
    ).first()

    exposed = _most_exposed(session)

    return DashboardSummary(
        total_scans=total_scans,
        hosts_discovered=hosts_discovered,
        open_ports=open_ports,
        services_detected=services_detected,
        findings=counts,
        latest_risk_score=latest_completed.risk_score if latest_completed else 0.0,
        recent_scans=[serialize_scan(s) for s in recent],
        most_exposed_hosts=exposed,
    )


def _most_exposed(session: Session, limit: int = 5) -> list[ExposedHost]:
    hosts = session.scalars(
        select(Host).order_by(Host.risk_score.desc()).limit(limit * 3)
    ).all()

    rows: list[ExposedHost] = []
    for host in hosts:
        open_count = len([p for p in host.ports if p.state in _OPEN_STATES])
        if open_count == 0 and host.risk_score == 0:
            continue
        critical = sum(1 for f in host.findings if f.severity == Severity.CRITICAL)
        high = sum(1 for f in host.findings if f.severity == Severity.HIGH)
        rows.append(
            ExposedHost(
                host_id=host.id,
                ip=host.ip,
                hostname=host.hostname,
                open_ports=open_count,
                risk_score=host.risk_score,
                critical=critical,
                high=high,
            )
        )
    rows.sort(key=lambda r: (-r.risk_score, -r.open_ports))
    return rows[:limit]


@router.get("/trends", response_model=TrendResponse)
def trends(
    limit: int = Query(default=20, ge=1, le=100),
    session: Session = Depends(get_session),
) -> TrendResponse:
    scans = session.scalars(
        select(Scan)
        .where(Scan.status == ScanStatus.COMPLETED)
        .order_by(Scan.started_at.desc())
        .limit(limit)
    ).all()

    points: list[TrendPoint] = []
    for scan in reversed(scans):  # oldest first, so charts read left to right
        open_ports = sum(
            len([p for p in h.ports if p.state in _OPEN_STATES]) for h in scan.hosts
        )
        services = sum(
            1
            for h in scan.hosts
            for p in h.ports
            if p.service is not None and p.service.name != "unknown"
        )
        counts = {level.value: 0 for level in Severity}
        for finding in scan.findings:
            counts[finding.severity] = counts.get(finding.severity, 0) + 1

        points.append(
            TrendPoint(
                scan_id=scan.id,
                timestamp=scan.started_at,
                target=scan.target,
                hosts=len(scan.hosts),
                open_ports=open_ports,
                services=services,
                risk_score=scan.risk_score,
                critical=counts[Severity.CRITICAL],
                high=counts[Severity.HIGH],
                medium=counts[Severity.MEDIUM],
                low=counts[Severity.LOW],
                info=counts[Severity.INFO],
            )
        )

    return TrendResponse(points=points)
