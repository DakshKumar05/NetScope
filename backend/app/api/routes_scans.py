from __future__ import annotations

import asyncio
import json
import logging

from fastapi import APIRouter, Depends, HTTPException, Query, Request, status
from fastapi.responses import StreamingResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.deps import get_session, manager_dep
from app.api.serializers import serialize_host, serialize_scan
from app.core.enums import PortState, ScanStatus, Severity
from app.core.targets import TargetValidationError, parse_ports, parse_target, parse_udp_ports
from app.models import Scan
from app.schemas.scan import (
    HostDetail,
    ScanCreate,
    ScanDetail,
    ScanRead,
    TopologyNode,
    TopologyResponse,
)
from app.services.scan_manager import ScanManager, scan_request_from_row

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/api/scans", tags=["scans"])


def _load_scan(session: Session, scan_id: int) -> Scan:
    scan = session.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, f"Scan {scan_id} not found.")
    return scan


@router.post("", response_model=ScanRead, status_code=status.HTTP_201_CREATED)
async def create_scan(
    payload: ScanCreate,
    session: Session = Depends(get_session),
    manager: ScanManager = Depends(manager_dep),
) -> ScanRead:
    if not payload.authorized:
        raise HTTPException(
            status.HTTP_400_BAD_REQUEST,
            "Scanning requires confirming that you own or are authorised to test this target.",
        )

    try:
        target = parse_target(payload.target)
        ports = parse_ports(payload.ports, profile=payload.profile)
        if payload.udp:
            parse_udp_ports(payload.udp_ports)
    except TargetValidationError as exc:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc)) from exc

    scan = Scan(
        target=target.raw,
        scan_type=payload.profile,
        status=ScanStatus.QUEUED,
        engine=payload.engine,
        ports_spec=payload.ports or ",".join(str(p) for p in ports),
        udp_enabled=payload.udp,
        timeout=payload.timeout,
        concurrency=payload.concurrency,
    )
    session.add(scan)
    session.commit()
    session.refresh(scan)

    request = scan_request_from_row(scan)
    request.udp_ports = payload.udp_ports
    await manager.start(scan.id, request)

    return serialize_scan(scan)


@router.get("", response_model=list[ScanRead])
def list_scans(
    limit: int = Query(default=25, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
    session: Session = Depends(get_session),
) -> list[ScanRead]:
    scans = session.scalars(
        select(Scan).order_by(Scan.started_at.desc()).offset(offset).limit(limit)
    ).all()
    return [serialize_scan(s) for s in scans]


@router.get("/{scan_id}", response_model=ScanDetail)
def get_scan(scan_id: int, session: Session = Depends(get_session)) -> ScanDetail:
    return serialize_scan(_load_scan(session, scan_id), detail=True)


@router.delete("/{scan_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_scan(
    scan_id: int,
    session: Session = Depends(get_session),
    manager: ScanManager = Depends(manager_dep),
) -> None:
    scan = _load_scan(session, scan_id)
    await manager.cancel(scan_id)
    session.delete(scan)
    session.commit()


@router.post("/{scan_id}/cancel", response_model=ScanRead)
async def cancel_scan(
    scan_id: int,
    session: Session = Depends(get_session),
    manager: ScanManager = Depends(manager_dep),
) -> ScanRead:
    scan = _load_scan(session, scan_id)
    cancelled = await manager.cancel(scan_id)
    if not cancelled:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            f"Scan {scan_id} is {scan.status} and cannot be cancelled.",
        )
    session.refresh(scan)
    return serialize_scan(scan)


@router.get("/{scan_id}/hosts", response_model=list[HostDetail])
def scan_hosts(scan_id: int, session: Session = Depends(get_session)) -> list[HostDetail]:
    scan = _load_scan(session, scan_id)
    return [serialize_host(h, detail=True) for h in scan.hosts]


@router.get("/{scan_id}/topology", response_model=TopologyResponse)
def scan_topology(scan_id: int, session: Session = Depends(get_session)) -> TopologyResponse:
    """Discovered relationships: scanner -> hosts -> open ports.

    This is a picture of what the scan found, not a routing or packet map.
    """
    scan = _load_scan(session, scan_id)
    nodes: list[TopologyNode] = [
        TopologyNode(
            id="scanner",
            label="Scanner",
            kind="scanner",
            meta={"target": scan.target, "engine": scan.engine},
        )
    ]

    worst_by_host = {h.id: Severity.INFO for h in scan.hosts}
    rank = {Severity.CRITICAL: 5, Severity.HIGH: 4, Severity.MEDIUM: 3, Severity.LOW: 2, Severity.INFO: 1}
    for finding in scan.findings:
        if finding.host_id is None:
            continue
        current = worst_by_host.get(finding.host_id, Severity.INFO)
        if rank.get(finding.severity, 0) > rank.get(current, 0):
            worst_by_host[finding.host_id] = finding.severity

    for host in scan.hosts:
        host_node = f"host-{host.id}"
        open_ports = [
            p for p in host.ports if p.state in (PortState.OPEN, PortState.OPEN_FILTERED)
        ]
        nodes.append(
            TopologyNode(
                id=host_node,
                label=host.hostname or host.ip,
                kind="host",
                severity=worst_by_host.get(host.id, Severity.INFO),
                parent="scanner",
                meta={
                    "ip": host.ip,
                    "risk_score": host.risk_score,
                    "open_ports": len(open_ports),
                },
            )
        )
        for port in open_ports:
            nodes.append(
                TopologyNode(
                    id=f"port-{port.id}",
                    label=f"{port.port}/{port.protocol}",
                    kind="port",
                    parent=host_node,
                    meta={
                        "service": port.service_name,
                        "product": port.service.product if port.service else None,
                        "version": port.service.version if port.service else None,
                    },
                )
            )

    return TopologyResponse(scan_id=scan.id, nodes=nodes)


@router.get("/{scan_id}/stream")
async def stream_scan(
    scan_id: int,
    request: Request,
    session: Session = Depends(get_session),
    manager: ScanManager = Depends(manager_dep),
) -> StreamingResponse:
    """Server-Sent Events carrying live progress for one scan."""
    scan = _load_scan(session, scan_id)
    terminal = {ScanStatus.COMPLETED, ScanStatus.FAILED, ScanStatus.CANCELLED}
    finished_status = scan.status if scan.status in terminal else None

    async def event_stream():
        if finished_status is not None and manager.get(scan_id) is None:
            # Nothing is running; tell the client where things landed and stop.
            payload = {
                "scan_id": scan_id,
                "status": finished_status,
                "phase": "storing_results",
                "progress": 1.0,
                "message": f"Scan already {finished_status}",
                "phases": {},
            }
            yield f"event: progress\ndata: {json.dumps(payload)}\n\n"
            yield "event: end\ndata: {}\n\n"
            return

        queue = manager.subscribe(scan_id)
        try:
            while True:
                if await request.is_disconnected():
                    break
                try:
                    event = await asyncio.wait_for(queue.get(), timeout=15.0)
                except asyncio.TimeoutError:
                    # Keep-alive so proxies do not close an idle stream.
                    yield ": keep-alive\n\n"
                    continue
                if event is None:
                    yield "event: end\ndata: {}\n\n"
                    break
                yield f"event: progress\ndata: {json.dumps(event)}\n\n"
        finally:
            manager.unsubscribe(scan_id, queue)

    return StreamingResponse(
        event_stream(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no",
        },
    )
