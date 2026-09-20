"""Background scan execution.

Scans run as asyncio tasks owned by this manager rather than inside the
request that started them, so the HTTP call returns immediately and the work
survives the client disconnecting. Progress is fanned out to any number of
SSE subscribers through per-subscriber queues.

No Celery, no Redis: a single-process task registry is enough for the number
of concurrent scans this tool is meant to run.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
from dataclasses import dataclass, field
from datetime import UTC, datetime

from sqlalchemy.orm import Session

from app.core.enums import ScanPhase, ScanStatus
from app.database.session import SessionLocal
from app.models import Finding, Host, Port, Scan, Service
from app.services.pipeline import ScanCancelled, ScanOutcome, ScanPipeline, ScanRequest

logger = logging.getLogger(__name__)

PHASE_ORDER: tuple[str, ...] = (
    ScanPhase.VALIDATION,
    ScanPhase.DISCOVERY,
    ScanPhase.PORT_SCAN,
    ScanPhase.FINGERPRINT,
    ScanPhase.VULN_LOOKUP,
    ScanPhase.RISK,
    ScanPhase.PERSIST,
)

MAX_CONCURRENT_SCANS = 4


@dataclass
class ScanJob:
    scan_id: int
    status: str = ScanStatus.QUEUED
    phase: str = ScanPhase.VALIDATION
    progress: float = 0.0
    message: str = ""
    phases: dict[str, float] = field(default_factory=lambda: {p: 0.0 for p in PHASE_ORDER})
    task: asyncio.Task | None = None
    cancel_event: asyncio.Event = field(default_factory=asyncio.Event)
    subscribers: list[asyncio.Queue] = field(default_factory=list)

    def snapshot(self) -> dict:
        return {
            "scan_id": self.scan_id,
            "status": self.status,
            "phase": self.phase,
            "progress": round(self.progress, 4),
            "message": self.message,
            "phases": {k: round(v, 4) for k, v in self.phases.items()},
        }


class ScanManager:
    def __init__(self) -> None:
        self._jobs: dict[int, ScanJob] = {}
        self._semaphore = asyncio.Semaphore(MAX_CONCURRENT_SCANS)
        self._lock = asyncio.Lock()

    # ------------------------------------------------------------------ jobs

    def get(self, scan_id: int) -> ScanJob | None:
        return self._jobs.get(scan_id)

    def active_ids(self) -> list[int]:
        return [
            job.scan_id
            for job in self._jobs.values()
            if job.status in (ScanStatus.QUEUED, ScanStatus.RUNNING)
        ]

    async def start(self, scan_id: int, request: ScanRequest) -> ScanJob:
        async with self._lock:
            existing = self._jobs.get(scan_id)
            if existing is not None and existing.status in (
                ScanStatus.QUEUED,
                ScanStatus.RUNNING,
            ):
                return existing
            job = ScanJob(scan_id=scan_id)
            self._jobs[scan_id] = job

        job.task = asyncio.create_task(self._run(job, request), name=f"scan-{scan_id}")
        return job

    async def cancel(self, scan_id: int) -> bool:
        job = self._jobs.get(scan_id)
        if job is None or job.status not in (ScanStatus.QUEUED, ScanStatus.RUNNING):
            return False
        job.cancel_event.set()
        await self._publish(job, message="Cancellation requested")
        return True

    async def shutdown(self) -> None:
        for job in list(self._jobs.values()):
            job.cancel_event.set()
        tasks = [j.task for j in self._jobs.values() if j.task is not None and not j.task.done()]
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)

    # ------------------------------------------------------- event streaming

    def subscribe(self, scan_id: int) -> asyncio.Queue:
        job = self._jobs.get(scan_id)
        queue: asyncio.Queue = asyncio.Queue(maxsize=200)
        if job is None:
            queue.put_nowait(None)
            return queue
        job.subscribers.append(queue)
        queue.put_nowait(job.snapshot())
        return queue

    def unsubscribe(self, scan_id: int, queue: asyncio.Queue) -> None:
        job = self._jobs.get(scan_id)
        if job is not None and queue in job.subscribers:
            job.subscribers.remove(queue)

    async def _publish(self, job: ScanJob, *, message: str | None = None) -> None:
        if message is not None:
            job.message = message
        snapshot = job.snapshot()
        for queue in list(job.subscribers):
            try:
                queue.put_nowait(snapshot)
            except asyncio.QueueFull:
                # A subscriber that cannot keep up is dropped rather than
                # allowed to stall the scan.
                logger.debug("dropping slow SSE subscriber for scan %s", job.scan_id)
                with contextlib.suppress(ValueError):
                    job.subscribers.remove(queue)

    async def _close_subscribers(self, job: ScanJob) -> None:
        for queue in list(job.subscribers):
            with contextlib.suppress(asyncio.QueueFull):
                queue.put_nowait(None)

    # --------------------------------------------------------------- running

    async def _run(self, job: ScanJob, request: ScanRequest) -> None:
        async with self._semaphore:
            if job.cancel_event.is_set():
                await self._finish(job, ScanStatus.CANCELLED)
                return

            job.status = ScanStatus.RUNNING
            await self._set_status(job.scan_id, ScanStatus.RUNNING)
            await self._publish(job, message="Scan started")

            async def on_progress(phase: str, progress: float, message: str) -> None:
                job.phase = phase
                job.phases[phase] = progress
                # Overall progress is the mean of all phases, so the bar moves
                # monotonically rather than resetting at each stage.
                job.progress = sum(job.phases.values()) / len(job.phases)
                await self._publish(job, message=message)

            pipeline = ScanPipeline(
                request, on_progress=on_progress, cancel_event=job.cancel_event
            )

            try:
                outcome = await pipeline.run()
            except ScanCancelled:
                await self._finish(job, ScanStatus.CANCELLED)
                return
            except asyncio.CancelledError:
                await self._finish(job, ScanStatus.CANCELLED)
                raise
            except ValueError as exc:
                logger.warning("scan %s rejected: %s", job.scan_id, exc)
                await self._finish(job, ScanStatus.FAILED, error=str(exc))
                return
            except Exception as exc:  # noqa: BLE001 - surface the failure, keep serving
                logger.exception("scan %s failed", job.scan_id)
                await self._finish(job, ScanStatus.FAILED, error=str(exc))
                return
            finally:
                with contextlib.suppress(Exception):
                    await pipeline.close()

            job.phase = ScanPhase.PERSIST
            job.phases[ScanPhase.PERSIST] = 0.5
            await self._publish(job, message="Storing results")

            try:
                await asyncio.to_thread(self._persist, job.scan_id, outcome)
            except Exception as exc:  # noqa: BLE001
                logger.exception("persisting scan %s failed", job.scan_id)
                await self._finish(job, ScanStatus.FAILED, error=f"Could not store results: {exc}")
                return

            job.phases[ScanPhase.PERSIST] = 1.0
            await self._finish(
                job,
                ScanStatus.COMPLETED,
                message=(
                    f"Completed: {len(outcome.hosts)} host(s), "
                    f"{len(outcome.findings)} finding(s), risk {outcome.risk.score}"
                ),
            )

    async def _finish(
        self,
        job: ScanJob,
        status: str,
        *,
        error: str | None = None,
        message: str | None = None,
    ) -> None:
        job.status = status
        if status == ScanStatus.COMPLETED:
            job.progress = 1.0
            job.phases = {k: 1.0 for k in job.phases}
        await self._set_status(job.scan_id, status, error=error)
        await self._publish(job, message=message or error or f"Scan {status}")
        await self._close_subscribers(job)

    async def _set_status(self, scan_id: int, status: str, *, error: str | None = None) -> None:
        def _update() -> None:
            with SessionLocal() as session:
                scan = session.get(Scan, scan_id)
                if scan is None:
                    return
                scan.status = status
                if error:
                    scan.error = error[:2000]
                if status in (ScanStatus.COMPLETED, ScanStatus.FAILED, ScanStatus.CANCELLED):
                    scan.completed_at = datetime.now(UTC)
                session.commit()

        await asyncio.to_thread(_update)

    # ------------------------------------------------------------ persistence

    @staticmethod
    def _persist(scan_id: int, outcome: ScanOutcome) -> None:
        with SessionLocal() as session:
            scan = session.get(Scan, scan_id)
            if scan is None:
                raise RuntimeError(f"Scan {scan_id} vanished before results could be stored.")

            scan.engine = outcome.engine
            scan.risk_score = outcome.risk.score

            for host_outcome in outcome.hosts:
                host = Host(
                    scan_id=scan.id,
                    ip=host_outcome.ip,
                    hostname=host_outcome.hostname,
                    status=host_outcome.status,
                    risk_score=host_outcome.risk.score if host_outcome.risk else 0.0,
                )
                session.add(host)
                session.flush()

                for port_finding in host_outcome.ports:
                    port_row = Port(
                        host_id=host.id,
                        port=port_finding.port.port,
                        protocol=port_finding.port.protocol,
                        state=port_finding.port.state,
                        service_name=port_finding.service.name,
                        latency_ms=port_finding.port.latency_ms,
                    )
                    session.add(port_row)
                    session.flush()

                    info = port_finding.service
                    session.add(
                        Service(
                            port_id=port_row.id,
                            name=info.name,
                            product=info.product,
                            version=info.version,
                            banner=info.banner,
                            confidence=info.confidence,
                            details=_json_safe(info.details),
                        )
                    )

                    for draft in port_finding.findings:
                        session.add(
                            Finding(
                                scan_id=scan.id,
                                host_id=host.id,
                                port_id=port_row.id,
                                type=draft.type,
                                severity=draft.severity,
                                title=draft.title[:255],
                                description=draft.description,
                                reason=draft.reason,
                                evidence=draft.evidence,
                                recommendation=draft.recommendation,
                                cve_id=draft.cve_id,
                                cvss=draft.cvss,
                                confidence=draft.confidence,
                                references=list(draft.references),
                                extra=_json_safe(draft.extra),
                            )
                        )

            session.commit()


def _json_safe(value: object) -> dict:
    """SQLite's JSON column needs plain types; drop anything that will not encode."""
    if not isinstance(value, dict):
        return {}
    safe: dict = {}
    for key, item in value.items():
        if isinstance(item, (str, int, float, bool, type(None))):
            safe[str(key)] = item
        elif isinstance(item, (list, tuple)):
            safe[str(key)] = [
                i for i in item if isinstance(i, (str, int, float, bool, type(None)))
            ]
        elif isinstance(item, dict):
            safe[str(key)] = _json_safe(item)
    return safe


manager = ScanManager()


def get_manager() -> ScanManager:
    return manager


def scan_request_from_row(scan: Scan) -> ScanRequest:
    return ScanRequest(
        target=scan.target,
        profile=scan.scan_type,
        ports=scan.ports_spec,
        udp=scan.udp_enabled,
        timeout=scan.timeout,
        concurrency=scan.concurrency,
        engine=scan.engine if scan.engine in ("auto", "socket", "nmap") else "auto",
    )


def session_scope() -> Session:
    return SessionLocal()
