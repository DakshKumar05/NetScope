"""Target and port parsing.

Every value that reaches the scanner passes through here first. Targets are
resolved to ``ipaddress`` objects rather than strings so that nothing
shell-like or protocol-like can survive parsing.
"""

from __future__ import annotations

import ipaddress
import re
import socket
from dataclasses import dataclass, field

from app.config import settings

# RFC 1123 hostname label rules. Anchored, so anything with a space, slash,
# semicolon, quote or shell metacharacter fails outright.
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?!-)[A-Za-z0-9-]{1,63}(?<!-)(\.(?!-)[A-Za-z0-9-]{1,63}(?<!-))*\.?$"
)

QUICK_PORTS: tuple[int, ...] = (
    21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 445, 993, 995,
    1433, 1521, 3306, 3389, 5432, 5900, 6379, 8080, 8443, 9200, 27017,
)

STANDARD_PORTS: tuple[int, ...] = tuple(
    sorted(
        set(QUICK_PORTS)
        | {
            20, 69, 88, 123, 137, 161, 389, 427, 465, 514, 587, 631, 636, 873,
            1080, 1194, 2049, 2181, 2375, 2376, 3000, 3128, 4444, 5000, 5060,
            5601, 5672, 5671, 5985, 5986, 6000, 6443, 7001, 8000, 8008, 8081,
            8086, 8088, 8181, 8888, 9000, 9090, 9092, 9300, 11211, 15672,
            25565, 27018, 50000,
        }
    )
)

COMMON_UDP_PORTS: tuple[int, ...] = (53, 67, 68, 123, 161, 500, 1900)

MAX_CIDR_HOSTS = settings.max_hosts_per_scan


class TargetValidationError(ValueError):
    """Raised when a target or port specification cannot be safely parsed."""


@dataclass(slots=True)
class ResolvedTarget:
    raw: str
    kind: str  # "ip" | "cidr" | "hostname"
    addresses: list[str]
    hostnames: dict[str, str] = field(default_factory=dict)

    @property
    def count(self) -> int:
        return len(self.addresses)


def _is_private(addr: ipaddress.IPv4Address) -> bool:
    return (
        addr.is_private
        or addr.is_loopback
        or addr.is_link_local
        or addr.is_unspecified
    )


def _guard_public(addr: ipaddress.IPv4Address, raw: str) -> None:
    if settings.allow_public_targets:
        return
    if not _is_private(addr):
        raise TargetValidationError(
            f"'{raw}' resolves to the public address {addr}. Scanning public hosts is "
            "disabled by default. Only enable NES_ALLOW_PUBLIC_TARGETS for systems you "
            "own or are explicitly authorised to test."
        )


def _resolve_hostname(name: str) -> list[str]:
    try:
        infos = socket.getaddrinfo(name, None, family=socket.AF_INET, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise TargetValidationError(f"Hostname '{name}' could not be resolved: {exc.strerror}")
    seen: list[str] = []
    for info in infos:
        ip = info[4][0]
        if ip not in seen:
            seen.append(ip)
    if not seen:
        raise TargetValidationError(f"Hostname '{name}' resolved to no IPv4 addresses.")
    return seen


def parse_target(raw: str) -> ResolvedTarget:
    """Validate and expand a target into concrete IPv4 addresses."""
    target = (raw or "").strip()
    if not target:
        raise TargetValidationError("Target must not be empty.")
    if len(target) > 255:
        raise TargetValidationError("Target is too long.")

    if "/" in target:
        try:
            network = ipaddress.ip_network(target, strict=False)
        except ValueError as exc:
            raise TargetValidationError(f"Invalid CIDR range: {exc}")
        if network.version != 4:
            raise TargetValidationError("Only IPv4 targets are supported in this release.")
        hosts = list(network.hosts()) or [network.network_address]
        if len(hosts) > MAX_CIDR_HOSTS:
            raise TargetValidationError(
                f"CIDR range expands to {len(hosts)} hosts, above the limit of {MAX_CIDR_HOSTS}. "
                "Use a smaller prefix."
            )
        for host in hosts:
            _guard_public(host, target)  # type: ignore[arg-type]
        return ResolvedTarget(raw=target, kind="cidr", addresses=[str(h) for h in hosts])

    try:
        addr = ipaddress.ip_address(target)
    except ValueError:
        addr = None

    if addr is not None:
        if addr.version != 4:
            raise TargetValidationError("Only IPv4 targets are supported in this release.")
        _guard_public(addr, target)  # type: ignore[arg-type]
        return ResolvedTarget(raw=target, kind="ip", addresses=[str(addr)])

    if not _HOSTNAME_RE.match(target):
        raise TargetValidationError(
            f"'{target}' is not a valid IPv4 address, CIDR range or hostname."
        )

    addresses = _resolve_hostname(target)
    for ip in addresses:
        _guard_public(ipaddress.IPv4Address(ip), target)
    return ResolvedTarget(
        raw=target,
        kind="hostname",
        addresses=addresses,
        hostnames={ip: target.rstrip(".") for ip in addresses},
    )


def parse_ports(spec: str | None, *, profile: str = "quick") -> list[int]:
    """Parse a port specification such as ``22,80,443`` or ``1-1024``."""
    if spec is None or not spec.strip():
        if profile == "standard":
            return list(STANDARD_PORTS)
        if profile == "custom":
            raise TargetValidationError("A custom scan requires an explicit port specification.")
        return list(QUICK_PORTS)

    text = spec.strip()
    if len(text) > 512:
        raise TargetValidationError("Port specification is too long.")
    if not re.fullmatch(r"[0-9,\s-]+", text):
        raise TargetValidationError(
            "Port specification may only contain digits, commas and hyphens."
        )

    ports: set[int] = set()
    for chunk in (c.strip() for c in text.split(",")):
        if not chunk:
            continue
        if "-" in chunk:
            parts = chunk.split("-")
            if len(parts) != 2 or not all(p.strip().isdigit() for p in parts):
                raise TargetValidationError(f"Invalid port range: '{chunk}'.")
            start, end = int(parts[0]), int(parts[1])
            if start > end:
                start, end = end, start
            _check_port(start)
            _check_port(end)
            if end - start + 1 > settings.max_ports_per_scan:
                raise TargetValidationError(
                    f"Port range '{chunk}' covers more than {settings.max_ports_per_scan} ports."
                )
            ports.update(range(start, end + 1))
        else:
            if not chunk.isdigit():
                raise TargetValidationError(f"Invalid port: '{chunk}'.")
            value = int(chunk)
            _check_port(value)
            ports.add(value)

    if not ports:
        raise TargetValidationError("No valid ports were provided.")
    if len(ports) > settings.max_ports_per_scan:
        raise TargetValidationError(
            f"{len(ports)} ports requested, above the limit of {settings.max_ports_per_scan}."
        )
    return sorted(ports)


def _check_port(value: int) -> None:
    if not 1 <= value <= 65535:
        raise TargetValidationError(f"Port {value} is outside the valid range 1-65535.")


def parse_udp_ports(spec: str | None) -> list[int]:
    if spec is None or not spec.strip():
        return list(COMMON_UDP_PORTS)
    ports = parse_ports(spec)
    if len(ports) > 64:
        raise TargetValidationError(
            "UDP scanning is deliberately conservative; request at most 64 UDP ports."
        )
    return ports
