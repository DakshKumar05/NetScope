from __future__ import annotations

import pytest

from app.core.enums import Confidence
from app.services.fingerprinting import SSHDetector, registry
from app.services.fingerprinting.http_detector import (
    SECURITY_HEADERS,
    _detect_admin_interface,
    _parse_server_header,
)
from app.services.fingerprinting.tls_detector import _hostname_matches
from tests.conftest import run


class TestSSHDetector:
    def test_parses_openssh_banner(self, tcp_server: tuple[str, int]) -> None:
        host, port = tcp_server
        info = run(SSHDetector().detect(host, port))
        assert info is not None
        assert info.name == "ssh"
        assert info.product == "OpenSSH"
        assert info.version == "9.6p1"
        assert info.confidence == Confidence.CONFIRMED

    def test_returns_none_on_silence(self, closed_port: int) -> None:
        assert run(SSHDetector().detect("127.0.0.1", closed_port)) is None

    def test_handles_matches_hint_on_odd_port(self) -> None:
        assert SSHDetector().handles(2200, "ssh")
        assert not SSHDetector().handles(2200, None)


class TestRegistry:
    def test_identifies_ssh_through_the_chain(self, tcp_server: tuple[str, int]) -> None:
        host, port = tcp_server
        info = run(registry.identify(host, port, "ssh"))
        assert info.product == "OpenSSH"

    def test_unknown_service_degrades_gracefully(self, closed_port: int) -> None:
        info = run(registry.identify("127.0.0.1", closed_port))
        assert info.name == "unknown"
        assert info.confidence == Confidence.POSSIBLE


class TestServerHeaderParsing:
    @pytest.mark.parametrize(
        ("header", "product", "version"),
        [
            ("nginx/1.24.0", "nginx", "1.24.0"),
            ("Apache/2.4.58 (Ubuntu)", "Apache", "2.4.58"),
            ("nginx", "nginx", None),
            ("Microsoft-IIS/10.0", "Microsoft-IIS", "10.0"),
        ],
    )
    def test_parses(self, header: str, product: str, version: str | None) -> None:
        assert _parse_server_header(header) == (product, version)


class TestAdminInterfaceDetection:
    def test_detects_from_title(self) -> None:
        assert _detect_admin_interface("Grafana Login", "", {}) == "Grafana"

    def test_detects_from_body(self) -> None:
        assert _detect_admin_interface("", "<div>phpMyAdmin 5.2</div>", {}) == "phpMyAdmin"

    def test_no_false_positive_on_plain_page(self) -> None:
        assert _detect_admin_interface("Welcome", "<p>hello world</p>", {}) is None

    def test_security_header_list_is_lowercase(self) -> None:
        # The detector lowercases response headers before comparing.
        assert all(h == h.lower() for h in SECURITY_HEADERS)


class TestHostnameMatching:
    def test_exact_match(self) -> None:
        assert _hostname_matches("example.com", {"example.com"})

    def test_wildcard_matches_one_label(self) -> None:
        assert _hostname_matches("api.example.com", {"*.example.com"})

    def test_wildcard_does_not_match_two_labels(self) -> None:
        assert not _hostname_matches("a.b.example.com", {"*.example.com"})

    def test_mismatch(self) -> None:
        assert not _hostname_matches("evil.com", {"example.com"})

    def test_empty_name_set_is_a_mismatch(self) -> None:
        assert not _hostname_matches("example.com", set())
