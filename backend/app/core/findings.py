from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from app.core.enums import Confidence, Severity


@dataclass(slots=True)
class FindingDraft:
    """A finding before it is attached to database rows.

    Every field that justifies the severity is mandatory in spirit: a finding
    without a reason and evidence is an assertion, not a result.
    """

    type: str
    severity: str
    title: str
    reason: str
    evidence: str
    recommendation: str
    description: str = ""
    confidence: str = Confidence.PROBABLE
    cve_id: str | None = None
    cvss: float | None = None
    references: list[str] = field(default_factory=list)
    extra: dict[str, Any] = field(default_factory=dict)
    port: int | None = None
    protocol: str | None = None

    def __post_init__(self) -> None:
        if self.severity not in set(Severity):
            raise ValueError(f"Unknown severity: {self.severity}")
        if self.confidence not in set(Confidence):
            raise ValueError(f"Unknown confidence: {self.confidence}")
