from __future__ import annotations

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.api.deps import get_session
from app.core.enums import ScanStatus, Severity
from app.database.session import Base
from app.main import app
from app.models import Finding, Host, Port, Scan, Service


@pytest.fixture
def client():
    """An app wired to an in-memory database - no scans are ever launched."""
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    TestingSession = sessionmaker(bind=engine, autoflush=False, autocommit=False)

    def override():
        session = TestingSession()
        try:
            yield session
        finally:
            session.close()

    app.dependency_overrides[get_session] = override
    with TestClient(app) as test_client:
        test_client.session_factory = TestingSession  # type: ignore[attr-defined]
        yield test_client
    app.dependency_overrides.clear()


def seed(client) -> int:
    session = client.session_factory()
    scan = Scan(
        target="192.168.1.10",
        scan_type="quick",
        status=ScanStatus.COMPLETED,
        engine="socket",
        risk_score=42.0,
    )
    session.add(scan)
    session.flush()

    host = Host(scan_id=scan.id, ip="192.168.1.10", status="up", risk_score=42.0)
    session.add(host)
    session.flush()

    port = Port(host_id=host.id, port=22, protocol="tcp", state="open", service_name="ssh")
    session.add(port)
    session.flush()

    session.add(
        Service(
            port_id=port.id,
            name="ssh",
            product="OpenSSH",
            version="9.6",
            banner="SSH-2.0-OpenSSH_9.6",
            confidence="confirmed",
            details={},
        )
    )
    session.add(
        Finding(
            scan_id=scan.id,
            host_id=host.id,
            port_id=port.id,
            type="sensitive_service",
            severity=Severity.HIGH,
            title="SSH exposed",
            description="",
            reason="reachable",
            evidence="banner",
            recommendation="restrict",
            confidence="confirmed",
            references=[],
            extra={},
        )
    )
    session.commit()
    scan_id = scan.id
    session.close()
    return scan_id


class TestHealth:
    def test_reports_engines(self, client) -> None:
        response = client.get("/api/health")
        assert response.status_code == 200
        body = response.json()
        assert body["status"] == "ok"
        assert body["engines"]["socket"] is True


class TestScanCreationGuards:
    def test_requires_authorisation_flag(self, client) -> None:
        response = client.post("/api/scans", json={"target": "127.0.0.1", "authorized": False})
        assert response.status_code == 400
        assert "authorised" in response.json()["error"]["message"]

    def test_rejects_public_target(self, client) -> None:
        response = client.post("/api/scans", json={"target": "8.8.8.8", "authorized": True})
        assert response.status_code == 422

    def test_rejects_injection_in_target(self, client) -> None:
        response = client.post(
            "/api/scans", json={"target": "127.0.0.1; rm -rf /", "authorized": True}
        )
        assert response.status_code == 422

    def test_rejects_bad_port_spec(self, client) -> None:
        response = client.post(
            "/api/scans",
            json={
                "target": "127.0.0.1",
                "profile": "custom",
                "ports": "22; ls",
                "authorized": True,
            },
        )
        assert response.status_code == 422

    def test_rejects_out_of_band_concurrency(self, client) -> None:
        response = client.post(
            "/api/scans",
            json={"target": "127.0.0.1", "concurrency": 99999, "authorized": True},
        )
        assert response.status_code == 422

    def test_error_envelope_shape(self, client) -> None:
        body = client.post("/api/scans", json={"target": "8.8.8.8", "authorized": True}).json()
        assert "error" in body
        assert {"message", "status"} <= set(body["error"])


class TestScanReads:
    def test_list_and_detail(self, client) -> None:
        scan_id = seed(client)

        listing = client.get("/api/scans")
        assert listing.status_code == 200
        assert len(listing.json()) == 1

        detail = client.get(f"/api/scans/{scan_id}")
        assert detail.status_code == 200
        body = detail.json()
        assert body["host_count"] == 1
        assert body["open_port_count"] == 1
        assert body["severity_counts"]["high"] == 1
        assert body["hosts"][0]["ports"][0]["service"]["product"] == "OpenSSH"

    def test_missing_scan_is_404(self, client) -> None:
        assert client.get("/api/scans/9999").status_code == 404

    def test_hosts_endpoint(self, client) -> None:
        scan_id = seed(client)
        response = client.get(f"/api/scans/{scan_id}/hosts")
        assert response.status_code == 200
        assert response.json()[0]["ip"] == "192.168.1.10"

    def test_topology_structure(self, client) -> None:
        scan_id = seed(client)
        nodes = client.get(f"/api/scans/{scan_id}/topology").json()["nodes"]
        kinds = [n["kind"] for n in nodes]
        assert kinds.count("scanner") == 1
        assert "host" in kinds and "port" in kinds
        host_node = next(n for n in nodes if n["kind"] == "host")
        assert host_node["parent"] == "scanner"
        assert host_node["severity"] == "high"

    def test_delete(self, client) -> None:
        scan_id = seed(client)
        assert client.delete(f"/api/scans/{scan_id}").status_code == 204
        assert client.get(f"/api/scans/{scan_id}").status_code == 404

    def test_cancel_completed_scan_conflicts(self, client) -> None:
        scan_id = seed(client)
        assert client.post(f"/api/scans/{scan_id}/cancel").status_code == 409


class TestFindings:
    def test_list_and_filter(self, client) -> None:
        scan_id = seed(client)

        assert len(client.get("/api/findings").json()) == 1
        assert len(client.get("/api/findings", params={"severity": "high"}).json()) == 1
        assert len(client.get("/api/findings", params={"severity": "critical"}).json()) == 0
        assert len(client.get("/api/findings", params={"scan_id": scan_id}).json()) == 1
        assert len(client.get("/api/findings", params={"search": "SSH"}).json()) == 1
        assert len(client.get("/api/findings", params={"search": "nope"}).json()) == 0

    def test_finding_exposes_its_reasoning(self, client) -> None:
        seed(client)
        finding = client.get("/api/findings").json()[0]
        for field in ("reason", "evidence", "recommendation", "confidence"):
            assert field in finding

    def test_missing_finding_is_404(self, client) -> None:
        assert client.get("/api/findings/4242").status_code == 404

    def test_invalid_severity_is_rejected(self, client) -> None:
        assert client.get("/api/findings", params={"severity": "bogus"}).status_code == 422


class TestDashboard:
    def test_summary(self, client) -> None:
        seed(client)
        body = client.get("/api/dashboard/summary").json()
        assert body["total_scans"] == 1
        assert body["hosts_discovered"] == 1
        assert body["open_ports"] == 1
        assert body["findings"]["high"] == 1
        assert body["most_exposed_hosts"][0]["ip"] == "192.168.1.10"

    def test_trends_are_oldest_first(self, client) -> None:
        seed(client)
        seed(client)
        points = client.get("/api/dashboard/trends").json()["points"]
        assert len(points) == 2
        assert points[0]["scan_id"] < points[1]["scan_id"]

    def test_empty_database_summary(self, client) -> None:
        body = client.get("/api/dashboard/summary").json()
        assert body["total_scans"] == 0
        assert body["most_exposed_hosts"] == []
