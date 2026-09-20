from __future__ import annotations

from datetime import UTC, datetime, timedelta

from app.core.enums import Confidence, FindingType, Severity
from app.core.findings import FindingDraft
from app.services.fingerprinting.base import ServiceInfo
from app.services.misconfiguration.checks import (
    check_exposed_service,
    check_http,
    check_tls,
)
from app.services.risk import level_for_score, score_findings


def draft(severity: str, confidence: str = Confidence.CONFIRMED) -> FindingDraft:
    return FindingDraft(
        type=FindingType.EXPOSED_SERVICE,
        severity=severity,
        title=f"{severity} finding",
        reason="test",
        evidence="test",
        recommendation="test",
        confidence=confidence,
    )


class TestRiskScoring:
    def test_no_findings_scores_zero(self) -> None:
        result = score_findings([])
        assert result.score == 0.0
        assert result.level == Severity.INFO

    def test_score_is_bounded(self) -> None:
        result = score_findings([draft(Severity.CRITICAL) for _ in range(100)])
        assert 0 <= result.score <= 100

    def test_critical_outranks_a_single_medium(self) -> None:
        assert score_findings([draft(Severity.CRITICAL)]).score > (
            score_findings([draft(Severity.MEDIUM)]).score
        )

    def test_confidence_discounts_the_contribution(self) -> None:
        confirmed = score_findings([draft(Severity.HIGH, Confidence.CONFIRMED)]).score
        possible = score_findings([draft(Severity.HIGH, Confidence.POSSIBLE)]).score
        assert possible < confirmed

    def test_info_findings_do_not_move_the_score(self) -> None:
        assert score_findings([draft(Severity.INFO) for _ in range(5)]).score == 0.0

    def test_counts_are_reported(self) -> None:
        result = score_findings([draft(Severity.HIGH), draft(Severity.HIGH), draft(Severity.LOW)])
        assert result.counts[Severity.HIGH] == 2
        assert result.counts[Severity.LOW] == 1

    def test_contributions_are_ranked(self) -> None:
        result = score_findings([draft(Severity.LOW), draft(Severity.CRITICAL)])
        assert result.contributions[0][1] >= result.contributions[-1][1]

    def test_levels(self) -> None:
        assert level_for_score(0) == Severity.INFO
        assert level_for_score(10) == Severity.LOW
        assert level_for_score(30) == Severity.MEDIUM
        assert level_for_score(60) == Severity.HIGH
        assert level_for_score(90) == Severity.CRITICAL


class TestExposedServiceChecks:
    def test_every_open_port_yields_an_info_finding(self) -> None:
        findings = check_exposed_service(8080, "tcp", ServiceInfo(name="http"))
        assert any(f.type == FindingType.EXPOSED_SERVICE for f in findings)

    def test_database_port_is_flagged_sensitive(self) -> None:
        findings = check_exposed_service(3306, "tcp", ServiceInfo(name="mysql"))
        types = {f.type for f in findings}
        assert FindingType.SENSITIVE_SERVICE in types
        assert FindingType.CREDENTIAL_REVIEW in types

    def test_credential_finding_does_not_claim_a_weakness(self) -> None:
        findings = check_exposed_service(5432, "tcp", ServiceInfo(name="postgresql"))
        cred = next(f for f in findings if f.type == FindingType.CREDENTIAL_REVIEW)
        assert cred.confidence == Confidence.POSSIBLE
        assert "does not test credentials" in cred.reason

    def test_ordinary_port_is_not_sensitive(self) -> None:
        findings = check_exposed_service(8080, "tcp", ServiceInfo(name="http"))
        assert all(f.type != FindingType.SENSITIVE_SERVICE for f in findings)

    def test_every_finding_carries_its_justification(self) -> None:
        for finding in check_exposed_service(3306, "tcp", ServiceInfo(name="mysql")):
            assert finding.reason.strip()
            assert finding.evidence.strip()
            assert finding.recommendation.strip()


class TestTlsChecks:
    def base(self, **overrides) -> dict:
        data = {
            "subject_cn": "example.local",
            "issuer_cn": "Test CA",
            "not_after": "2030-01-01T00:00:00+00:00",
            "days_remaining": 800,
            "expired": False,
            "not_yet_valid": False,
            "self_signed": False,
            "hostname_mismatch": False,
            "weak_protocol": False,
            "tls_version": "TLSv1.3",
            "san": ["example.local"],
        }
        data.update(overrides)
        return data

    def test_clean_certificate_produces_no_findings(self) -> None:
        assert check_tls(443, self.base()) == []

    def test_expired_is_high(self) -> None:
        findings = check_tls(443, self.base(expired=True))
        assert findings[0].severity == Severity.HIGH

    def test_self_signed_is_medium(self) -> None:
        findings = check_tls(443, self.base(self_signed=True))
        assert any(f.severity == Severity.MEDIUM for f in findings)

    def test_expiring_soon_is_low(self) -> None:
        soon = (datetime.now(UTC) + timedelta(days=10)).isoformat()
        findings = check_tls(443, self.base(days_remaining=10, not_after=soon))
        assert findings[0].severity == Severity.LOW

    def test_obsolete_protocol_is_high(self) -> None:
        findings = check_tls(443, self.base(weak_protocol=True, tls_version="TLSv1"))
        assert any(f.severity == Severity.HIGH for f in findings)

    def test_self_signed_suppresses_duplicate_mismatch_finding(self) -> None:
        findings = check_tls(443, self.base(self_signed=True, hostname_mismatch=True))
        titles = [f.title for f in findings]
        assert not any("hostname mismatch" in t for t in titles)


class TestHttpChecks:
    def test_cleartext_http_is_flagged(self) -> None:
        findings = check_http(80, {"scheme": "http", "status_code": 200, "url": "http://h/"})
        assert any("Unencrypted" in f.title for f in findings)

    def test_https_is_not_flagged_as_cleartext(self) -> None:
        findings = check_http(443, {"scheme": "https", "status_code": 200, "url": "https://h/"})
        assert not any("Unencrypted" in f.title for f in findings)

    def test_missing_security_headers_is_low(self) -> None:
        findings = check_http(
            443,
            {
                "scheme": "https",
                "status_code": 200,
                "url": "https://h/",
                "missing_security_headers": ["content-security-policy"],
            },
        )
        assert any(f.severity == Severity.LOW for f in findings)

    def test_unauthenticated_admin_interface_is_high(self) -> None:
        findings = check_http(
            8080,
            {
                "scheme": "http",
                "status_code": 200,
                "url": "http://h/",
                "admin_interface": "Jenkins",
                "requires_auth": False,
            },
        )
        admin = next(f for f in findings if f.type == FindingType.ADMIN_INTERFACE)
        assert admin.severity == Severity.HIGH

    def test_gated_admin_interface_is_downgraded(self) -> None:
        findings = check_http(
            8080,
            {
                "scheme": "https",
                "status_code": 401,
                "url": "https://h/",
                "admin_interface": "Jenkins",
                "requires_auth": True,
            },
        )
        admin = next(f for f in findings if f.type == FindingType.ADMIN_INTERFACE)
        assert admin.severity == Severity.MEDIUM
        assert "No login was attempted" in admin.reason
