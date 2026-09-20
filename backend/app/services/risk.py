"""Transparent risk scoring.

The score is a bounded sum of severity weights, discounted by confidence.
It is deliberately simple so that any number shown in the UI can be traced
back to the findings that produced it.
"""

from __future__ import annotations

from dataclasses import dataclass

from app.core.enums import SEVERITY_WEIGHT, Confidence, Severity
from app.core.findings import FindingDraft

# A POSSIBLE finding should nudge the score, not dominate it.
CONFIDENCE_FACTOR: dict[str, float] = {
    Confidence.CONFIRMED: 1.0,
    Confidence.PROBABLE: 0.7,
    Confidence.POSSIBLE: 0.35,
}


@dataclass(slots=True)
class RiskBreakdown:
    score: float
    level: str
    counts: dict[str, int]
    contributions: list[tuple[str, float]]

    def as_dict(self) -> dict:
        return {
            "score": self.score,
            "level": self.level,
            "counts": self.counts,
            "contributions": [{"title": t, "points": p} for t, p in self.contributions],
        }


def level_for_score(score: float) -> str:
    if score >= 75:
        return Severity.CRITICAL
    if score >= 50:
        return Severity.HIGH
    if score >= 25:
        return Severity.MEDIUM
    if score > 0:
        return Severity.LOW
    return Severity.INFO


def score_findings(findings: list[FindingDraft]) -> RiskBreakdown:
    counts = {level: 0 for level in Severity}
    contributions: list[tuple[str, float]] = []
    total = 0.0

    for finding in findings:
        counts[finding.severity] = counts.get(finding.severity, 0) + 1
        weight = SEVERITY_WEIGHT.get(finding.severity, 0.0)
        points = weight * CONFIDENCE_FACTOR.get(finding.confidence, 0.5)
        if points > 0:
            total += points
            contributions.append((finding.title, round(points, 2)))

    # Saturating curve: ten mediums should not outrank one critical outright,
    # and the score must stay inside 0-100 however many findings arrive.
    score = round(100.0 * (1.0 - pow(2.71828, -total / 60.0)), 1)
    contributions.sort(key=lambda c: c[1], reverse=True)

    return RiskBreakdown(
        score=score,
        level=level_for_score(score),
        counts={k: v for k, v in counts.items() if v},
        contributions=contributions[:10],
    )
