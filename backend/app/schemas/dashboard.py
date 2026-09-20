from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, Field

from app.schemas.scan import ScanRead


class SeverityCount(BaseModel):
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0


class ExposedHost(BaseModel):
    host_id: int
    ip: str
    hostname: str | None = None
    open_ports: int
    risk_score: float
    critical: int = 0
    high: int = 0


class DashboardSummary(BaseModel):
    total_scans: int = 0
    hosts_discovered: int = 0
    open_ports: int = 0
    services_detected: int = 0
    findings: SeverityCount = Field(default_factory=SeverityCount)
    latest_risk_score: float = 0.0
    recent_scans: list[ScanRead] = Field(default_factory=list)
    most_exposed_hosts: list[ExposedHost] = Field(default_factory=list)


class TrendPoint(BaseModel):
    scan_id: int
    timestamp: datetime
    target: str
    hosts: int = 0
    open_ports: int = 0
    services: int = 0
    risk_score: float = 0.0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0


class TrendResponse(BaseModel):
    points: list[TrendPoint] = Field(default_factory=list)
