"""Cancellation and background-task lifecycle.

A cancel button that only stops the UI updating is worse than no cancel button,
so these tests assert that the work actually stops and that the scan lands in a
terminal state in the database.
"""

from __future__ import annotations

import asyncio

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.core.enums import ScanStatus
from app.database.session import Base
from app.models import Scan
from app.services import scan_manager as scan_manager_module
from app.services.pipeline import ScanCancelled, ScanPipeline, ScanRequest
from app.services.scan_manager import ScanManager
from tests.conftest import run


@pytest.fixture
def session_factory(monkeypatch):
    """Point the manager's module-level session factory at an in-memory DB."""
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    factory = sessionmaker(bind=engine, autoflush=False, autocommit=False)
    monkeypatch.setattr(scan_manager_module, "SessionLocal", factory)
    return factory


def make_scan_row(factory, **overrides) -> int:
    session = factory()
    scan = Scan(
        target=overrides.get("target", "127.0.0.1"),
        scan_type="custom",
        status=ScanStatus.QUEUED,
        engine="socket",
        ports_spec=overrides.get("ports_spec", "1-400"),
        timeout=overrides.get("timeout", 2.0),
        concurrency=overrides.get("concurrency", 4),
    )
    session.add(scan)
    session.commit()
    scan_id = scan.id
    session.close()
    return scan_id


class TestPipelineCancellation:
    def test_cancelled_before_start_raises(self) -> None:
        cancel = asyncio.Event()
        cancel.set()
        pipeline = ScanPipeline(
            ScanRequest(target="127.0.0.1", profile="custom", ports="80"),
            cancel_event=cancel,
        )
        with pytest.raises(ScanCancelled):
            run(pipeline.run())

    def test_cancelling_mid_scan_stops_the_run(self) -> None:
        """Set the flag while the scan is in flight and confirm it gives up."""

        async def scenario() -> None:
            cancel = asyncio.Event()
            pipeline = ScanPipeline(
                # A dark address with a long timeout: every probe blocks, so
                # the scan is guaranteed to still be running when we cancel.
                ScanRequest(
                    target="192.168.255.254",
                    profile="custom",
                    ports="1-600",
                    timeout=5.0,
                    concurrency=4,
                ),
                cancel_event=cancel,
            )
            task = asyncio.create_task(pipeline.run())
            await asyncio.sleep(0.4)
            assert not task.done(), "scan finished before it could be cancelled"
            pipeline.cancel()
            with pytest.raises(ScanCancelled):
                await asyncio.wait_for(task, timeout=20)
            await pipeline.close()

        run(scenario())


class TestManagerLifecycle:
    def test_running_scan_can_be_cancelled(self, session_factory) -> None:
        scan_id = make_scan_row(
            session_factory, target="192.168.255.254", ports_spec="1-600", timeout=5.0
        )

        async def scenario() -> None:
            manager = ScanManager()
            job = await manager.start(
                scan_id,
                ScanRequest(
                    target="192.168.255.254",
                    profile="custom",
                    ports="1-600",
                    timeout=5.0,
                    concurrency=4,
                ),
            )
            await asyncio.sleep(0.5)
            assert job.status == ScanStatus.RUNNING

            assert await manager.cancel(scan_id) is True
            await asyncio.wait_for(job.task, timeout=25)
            assert job.status == ScanStatus.CANCELLED

        run(scenario())

        session = session_factory()
        scan = session.get(Scan, scan_id)
        assert scan.status == ScanStatus.CANCELLED
        # A terminal scan must be stamped, or the UI shows it running forever.
        assert scan.completed_at is not None
        session.close()

    def test_cancelling_an_unknown_scan_reports_false(self, session_factory) -> None:
        async def scenario() -> bool:
            return await ScanManager().cancel(4242)

        assert run(scenario()) is False

    def test_completed_scan_is_persisted_with_results(self, session_factory) -> None:
        scan_id = make_scan_row(session_factory, ports_spec="1", timeout=0.4)

        async def scenario() -> str:
            manager = ScanManager()
            job = await manager.start(
                scan_id,
                ScanRequest(
                    target="127.0.0.1", profile="custom", ports="1", timeout=0.4
                ),
            )
            await asyncio.wait_for(job.task, timeout=40)
            return job.status

        assert run(scenario()) == ScanStatus.COMPLETED

        session = session_factory()
        scan = session.get(Scan, scan_id)
        assert scan.status == ScanStatus.COMPLETED
        assert scan.completed_at is not None
        assert scan.engine == "socket"
        session.close()

    def test_invalid_target_marks_the_scan_failed(self, session_factory) -> None:
        scan_id = make_scan_row(session_factory)

        async def scenario() -> str:
            manager = ScanManager()
            job = await manager.start(
                scan_id,
                # Rejected during validation, inside the background task.
                ScanRequest(target="8.8.8.8", profile="quick"),
            )
            await asyncio.wait_for(job.task, timeout=20)
            return job.status

        assert run(scenario()) == ScanStatus.FAILED

        session = session_factory()
        scan = session.get(Scan, scan_id)
        assert scan.status == ScanStatus.FAILED
        assert scan.error and "public address" in scan.error
        session.close()

    def test_shutdown_stops_in_flight_scans(self, session_factory) -> None:
        scan_id = make_scan_row(
            session_factory, target="192.168.255.254", ports_spec="1-600", timeout=5.0
        )

        async def scenario() -> None:
            manager = ScanManager()
            await manager.start(
                scan_id,
                ScanRequest(
                    target="192.168.255.254",
                    profile="custom",
                    ports="1-600",
                    timeout=5.0,
                    concurrency=4,
                ),
            )
            await asyncio.sleep(0.4)
            await asyncio.wait_for(manager.shutdown(), timeout=25)
            assert manager.active_ids() == []

        run(scenario())


class TestProgressFanOut:
    def test_subscriber_receives_a_snapshot_immediately(self, session_factory) -> None:
        scan_id = make_scan_row(session_factory, ports_spec="1", timeout=0.4)

        async def scenario() -> list:
            manager = ScanManager()
            await manager.start(
                scan_id,
                ScanRequest(target="127.0.0.1", profile="custom", ports="1", timeout=0.4),
            )
            queue = manager.subscribe(scan_id)
            first = await asyncio.wait_for(queue.get(), timeout=10)

            events = [first]
            # Drain until the stream closes, which the manager signals with None.
            while True:
                event = await asyncio.wait_for(queue.get(), timeout=40)
                if event is None:
                    break
                events.append(event)
            return events

        events = run(scenario())
        assert events, "no progress events were published"
        assert all("phases" in e for e in events)
        assert events[-1]["status"] in (ScanStatus.COMPLETED, ScanStatus.RUNNING)

    def test_unknown_scan_subscription_closes_at_once(self, session_factory) -> None:
        manager = ScanManager()
        queue = manager.subscribe(9999)
        assert queue.get_nowait() is None


class TestJsonSafety:
    def test_non_serialisable_values_are_dropped(self) -> None:
        safe = scan_manager_module._json_safe(
            {
                "keep": "text",
                "number": 1,
                "nested": {"ok": True, "bad": object()},
                "list": [1, "two", object()],
                "drop": object(),
            }
        )
        assert safe["keep"] == "text"
        assert safe["nested"] == {"ok": True}
        assert safe["list"] == [1, "two"]
        assert "drop" not in safe

    def test_non_dict_becomes_empty(self) -> None:
        assert scan_manager_module._json_safe(["not", "a", "dict"]) == {}
