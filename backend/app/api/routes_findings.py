from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import get_session
from app.api.serializers import serialize_finding
from app.core.enums import SEVERITY_ORDER, Severity
from app.models import Finding, Host
from app.schemas.scan import FindingRead

router = APIRouter(prefix="/api/findings", tags=["findings"])


@router.get("", response_model=list[FindingRead])
def list_findings(
    scan_id: int | None = None,
    host_id: int | None = None,
    severity: Severity | None = None,
    finding_type: str | None = Query(default=None, max_length=48),
    service: str | None = Query(default=None, max_length=64),
    cve: str | None = Query(default=None, max_length=32),
    search: str | None = Query(default=None, max_length=128),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
    session: Session = Depends(get_session),
) -> list[FindingRead]:
    stmt = select(Finding)

    if scan_id is not None:
        stmt = stmt.where(Finding.scan_id == scan_id)
    if host_id is not None:
        stmt = stmt.where(Finding.host_id == host_id)
    if severity is not None:
        stmt = stmt.where(Finding.severity == severity.value)
    if finding_type:
        stmt = stmt.where(Finding.type == finding_type)
    if cve:
        stmt = stmt.where(Finding.cve_id.ilike(f"%{cve}%"))
    if search:
        stmt = stmt.where(Finding.title.ilike(f"%{search}%"))
    if service:
        stmt = stmt.join(Host, Finding.host_id == Host.id).where(
            Finding.title.ilike(f"%{service}%")
        )

    findings = session.scalars(stmt.limit(limit).offset(offset)).all()

    # Severity is stored as text, so ordering happens here rather than in SQL.
    ordered = sorted(
        findings,
        key=lambda f: (-SEVERITY_ORDER.get(f.severity, 0), -(f.cvss or 0.0), f.id),
    )
    return [serialize_finding(f) for f in ordered]


@router.get("/{finding_id}", response_model=FindingRead)
def get_finding(finding_id: int, session: Session = Depends(get_session)) -> FindingRead:
    finding = session.get(Finding, finding_id)
    if finding is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"Finding {finding_id} not found.")
    return serialize_finding(finding)
