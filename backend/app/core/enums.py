from __future__ import annotations

from enum import StrEnum


class ScanStatus(StrEnum):
    QUEUED = "queued"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    CANCELLED = "cancelled"


class ScanProfile(StrEnum):
    QUICK = "quick"
    STANDARD = "standard"
    CUSTOM = "custom"


class HostStatus(StrEnum):
    UP = "up"
    DOWN = "down"
    UNKNOWN = "unknown"


class PortState(StrEnum):
    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"
    OPEN_FILTERED = "open|filtered"
    UNKNOWN = "unknown"


class Protocol(StrEnum):
    TCP = "tcp"
    UDP = "udp"


class Severity(StrEnum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


SEVERITY_ORDER: dict[str, int] = {
    Severity.CRITICAL: 5,
    Severity.HIGH: 4,
    Severity.MEDIUM: 3,
    Severity.LOW: 2,
    Severity.INFO: 1,
}

SEVERITY_WEIGHT: dict[str, float] = {
    Severity.CRITICAL: 40.0,
    Severity.HIGH: 20.0,
    Severity.MEDIUM: 8.0,
    Severity.LOW: 3.0,
    Severity.INFO: 0.0,
}


class Confidence(StrEnum):
    """How sure we are that a finding applies to the observed service."""

    CONFIRMED = "confirmed"
    PROBABLE = "probable"
    POSSIBLE = "possible"


class FindingType(StrEnum):
    EXPOSED_SERVICE = "exposed_service"
    SENSITIVE_SERVICE = "sensitive_service"
    KNOWN_VULNERABILITY = "known_vulnerability"
    TLS_ISSUE = "tls_issue"
    HTTP_ISSUE = "http_issue"
    FTP_ISSUE = "ftp_issue"
    ADMIN_INTERFACE = "admin_interface"
    CREDENTIAL_REVIEW = "credential_review"


class ScanPhase(StrEnum):
    VALIDATION = "target_validation"
    DISCOVERY = "host_discovery"
    PORT_SCAN = "port_scanning"
    FINGERPRINT = "service_fingerprinting"
    VULN_LOOKUP = "vulnerability_lookup"
    MISCONFIG = "misconfiguration_checks"
    RISK = "risk_calculation"
    PERSIST = "storing_results"
