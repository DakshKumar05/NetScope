from __future__ import annotations

from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.core.enums import ScanProfile
from app.core.targets import TargetValidationError, parse_ports, parse_target


class ScanCreate(BaseModel):
    target: str = Field(..., min_length=1, max_length=255, examples=["192.168.1.0/24"])
    profile: ScanProfile = ScanProfile.QUICK
    ports: str | None = Field(default=None, max_length=512, examples=["22,80,443"])
    udp: bool = False
    udp_ports: str | None = Field(default=None, max_length=256)
    timeout: float = Field(default=1.0, ge=0.1, le=10.0)
    concurrency: int = Field(default=100, ge=1, le=500)
    engine: str = Field(default="auto", pattern="^(auto|socket|nmap)$")
    authorized: bool = Field(
        default=False,
        description="Caller confirms they own or are authorised to scan this target.",
    )

    @field_validator("target")
    @classmethod
    def _validate_target(cls, value: str) -> str:
        try:
            parse_target(value)
        except TargetValidationError as exc:
            raise ValueError(str(exc)) from exc
        return value.strip()

    @field_validator("ports")
    @classmethod
    def _validate_ports(cls, value: str | None) -> str | None:
        if value:
            try:
                parse_ports(value)
            except TargetValidationError as exc:
                raise ValueError(str(exc)) from exc
        return value


class ServiceRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    product: str | None
    version: str | None
    banner: str | None
    confidence: str
    details: dict[str, Any] = Field(default_factory=dict)


class PortRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    port: int
    protocol: str
    state: str
    service_name: str | None
    latency_ms: float | None
    service: ServiceRead | None = None


class HostRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    scan_id: int
    ip: str
    hostname: str | None
    status: str
    risk_score: float
    open_port_count: int = 0


class HostDetail(HostRead):
    ports: list[PortRead] = Field(default_factory=list)


class FindingRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    scan_id: int
    host_id: int | None
    port_id: int | None
    type: str
    severity: str
    title: str
    description: str
    reason: str
    evidence: str
    recommendation: str
    cve_id: str | None
    cvss: float | None
    confidence: str
    references: list[str] = Field(default_factory=list)
    extra: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime
    host_ip: str | None = None
    port_number: int | None = None


class ScanRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    target: str
    scan_type: str
    status: str
    engine: str
    started_at: datetime
    completed_at: datetime | None
    duration_seconds: float | None = None
    risk_score: float
    error: str | None
    udp_enabled: bool
    host_count: int = 0
    open_port_count: int = 0
    finding_count: int = 0
    severity_counts: dict[str, int] = Field(default_factory=dict)


class ScanDetail(ScanRead):
    hosts: list[HostDetail] = Field(default_factory=list)
    findings: list[FindingRead] = Field(default_factory=list)


class ScanProgressEvent(BaseModel):
    scan_id: int
    status: str
    phase: str
    progress: float
    message: str = ""
    phases: dict[str, float] = Field(default_factory=dict)


class TopologyNode(BaseModel):
    id: str
    label: str
    kind: str  # "scanner" | "host" | "port"
    severity: str | None = None
    parent: str | None = None
    meta: dict[str, Any] = Field(default_factory=dict)


class TopologyResponse(BaseModel):
    scan_id: int
    nodes: list[TopologyNode]
