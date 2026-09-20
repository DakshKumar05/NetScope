from __future__ import annotations

from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.orm import Session

from app.api.deps import get_session
from app.api.serializers import serialize_finding, serialize_host, serialize_port
from app.models import Host
from app.schemas.scan import FindingRead, HostDetail, PortRead

router = APIRouter(prefix="/api/hosts", tags=["hosts"])


def _load_host(session: Session, host_id: int) -> Host:
    host = session.get(Host, host_id)
    if host is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"Host {host_id} not found.")
    return host


@router.get("/{host_id}", response_model=HostDetail)
def get_host(host_id: int, session: Session = Depends(get_session)) -> HostDetail:
    return serialize_host(_load_host(session, host_id), detail=True)


@router.get("/{host_id}/ports", response_model=list[PortRead])
def get_host_ports(host_id: int, session: Session = Depends(get_session)) -> list[PortRead]:
    host = _load_host(session, host_id)
    return [serialize_port(p) for p in host.ports]


@router.get("/{host_id}/findings", response_model=list[FindingRead])
def get_host_findings(host_id: int, session: Session = Depends(get_session)) -> list[FindingRead]:
    host = _load_host(session, host_id)
    return [serialize_finding(f) for f in host.findings]
