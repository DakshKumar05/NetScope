from __future__ import annotations

import asyncio

from app.core.enums import HostStatus, PortState
from app.services.scanner import SocketScanner, build_scanner, service_hint
from app.services.scanner.base import PortResult
from tests.conftest import run


class TestSocketScanner:
    def test_detects_open_port(self, tcp_server: tuple[str, int]) -> None:
        host, port = tcp_server
        scanner = SocketScanner(timeout=1.0)
        result = run(scanner.scan_host(host, [port]))
        assert result.status == HostStatus.UP
        assert len(result.open_ports) == 1
        assert result.open_ports[0].port == port
        assert result.open_ports[0].state == PortState.OPEN

    def test_closed_port_is_not_reported_as_open(self, closed_port: int) -> None:
        scanner = SocketScanner(timeout=1.0)
        result = run(scanner.scan_host("127.0.0.1", [closed_port]))
        assert result.open_ports == []

    def test_only_open_ports_are_retained(
        self, tcp_server: tuple[str, int], closed_port: int
    ) -> None:
        host, port = tcp_server
        scanner = SocketScanner(timeout=1.0)
        result = run(scanner.scan_host(host, [port, closed_port]))
        # Closed and filtered results are dropped so they cannot bury findings.
        assert [p.port for p in result.ports] == [port]

    def test_latency_is_recorded(self, tcp_server: tuple[str, int]) -> None:
        host, port = tcp_server
        result = run(SocketScanner(timeout=1.0).scan_host(host, [port]))
        assert result.open_ports[0].latency_ms is not None
        assert result.open_ports[0].latency_ms >= 0

    def test_progress_callback_reaches_total(self, tcp_server: tuple[str, int]) -> None:
        host, port = tcp_server
        seen: list[tuple[int, int]] = []

        async def on_progress(done: int, total: int) -> None:
            seen.append((done, total))

        run(SocketScanner(timeout=0.5).scan_host(host, [port], on_progress=on_progress))
        assert seen
        assert seen[-1][0] == seen[-1][1]

    def test_cancellation_stops_probing(self, closed_port: int) -> None:
        cancel = asyncio.Event()
        cancel.set()
        scanner = SocketScanner(timeout=1.0, cancel_event=cancel)
        result = run(scanner.scan_host("127.0.0.1", list(range(1, 50))))
        assert result.open_ports == []

    def test_concurrency_is_capped(self) -> None:
        scanner = SocketScanner(concurrency=100_000)
        assert scanner.concurrency <= 500

    def test_scan_network_returns_one_result_per_host(self, closed_port: int) -> None:
        scanner = SocketScanner(timeout=0.4)
        results = run(scanner.scan_network(["127.0.0.1"], [closed_port]))
        assert len(results) == 1
        assert results[0].ip == "127.0.0.1"


class TestEngineSelection:
    def test_falls_back_to_socket_without_nmap(self) -> None:
        # Nmap is not installed in CI; the app must still work.
        assert build_scanner("nmap").name == "socket"

    def test_auto_returns_a_working_engine(self) -> None:
        assert build_scanner("auto").name in ("socket", "nmap")


class TestServiceHints:
    def test_known_ports_have_hints(self) -> None:
        assert service_hint(22) == "ssh"
        assert service_hint(443) == "https"
        assert service_hint(3306) == "mysql"

    def test_unknown_port_has_no_hint(self) -> None:
        assert service_hint(64999) is None


class TestPortResult:
    def test_open_filtered_counts_as_open(self) -> None:
        assert PortResult(host="h", port=1, state=PortState.OPEN_FILTERED).is_open

    def test_filtered_is_not_open(self) -> None:
        assert not PortResult(host="h", port=1, state=PortState.FILTERED).is_open
