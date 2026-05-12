"""Tests for IntelligentReporter all-findings with verification_status."""
from __future__ import annotations
import pytest
from backend.intelligence.intelligent_reporter import IntelligentReporter


@pytest.fixture
def reporter():
    return IntelligentReporter()


class TestReporterVerificationStatus:
    @pytest.mark.asyncio
    async def test_finding_created_sets_unverified_status(self, reporter):
        await reporter._on_finding_event({
            "event_type": "FINDING_CREATED",
            "payload": {"finding_id": "f-001", "title": "Open port 80", "severity": "info"},
        })
        findings = reporter.get_findings_for_report()
        assert len(findings) == 1
        assert findings[0]["verification_status"] == "unverified"

    @pytest.mark.asyncio
    async def test_confirmed_classification_updates_status(self, reporter):
        await reporter._on_finding_event({
            "event_type": "FINDING_CREATED",
            "payload": {"finding_id": "f-001", "title": "Open port 80", "severity": "info"},
        })
        await reporter._on_finding_event({
            "event_type": "FINDING_CLASSIFIED",
            "payload": {"finding_id": "f-001", "classification": "confirmed"},
        })
        findings = reporter.get_findings_for_report()
        assert findings[0]["verification_status"] == "confirmed"

    @pytest.mark.asyncio
    async def test_manual_review_classification_updates_status(self, reporter):
        await reporter._on_finding_event({
            "event_type": "FINDING_CREATED",
            "payload": {"finding_id": "f-002", "title": "SSH exposed", "severity": "medium"},
        })
        await reporter._on_finding_event({
            "event_type": "FINDING_CLASSIFIED",
            "payload": {"finding_id": "f-002", "classification": "manual_review"},
        })
        findings = reporter.get_findings_for_report()
        assert findings[0]["verification_status"] == "manual_review"

    @pytest.mark.asyncio
    async def test_false_positive_classification_updates_status(self, reporter):
        await reporter._on_finding_event({
            "event_type": "FINDING_CREATED",
            "payload": {"finding_id": "f-003", "title": "Ghost port", "severity": "info"},
        })
        await reporter._on_finding_event({
            "event_type": "FINDING_CLASSIFIED",
            "payload": {"finding_id": "f-003", "classification": "false_positive"},
        })
        findings = reporter.get_findings_for_report()
        assert findings[0]["verification_status"] == "false_positive"

    @pytest.mark.asyncio
    async def test_all_findings_returned_regardless_of_status(self, reporter):
        """All 3 findings appear in report — confirmed, manual_review, unverified."""
        for fid, title in [("f-001", "SQLi"), ("f-002", "XSS"), ("f-003", "Open port")]:
            await reporter._on_finding_event({
                "event_type": "FINDING_CREATED",
                "payload": {"finding_id": fid, "title": title, "severity": "high"},
            })
        # Only f-001 gets confirmed
        await reporter._on_finding_event({
            "event_type": "FINDING_CLASSIFIED",
            "payload": {"finding_id": "f-001", "classification": "confirmed"},
        })
        # f-002 gets false_positive
        await reporter._on_finding_event({
            "event_type": "FINDING_CLASSIFIED",
            "payload": {"finding_id": "f-002", "classification": "false_positive"},
        })
        findings = reporter.get_findings_for_report()
        assert len(findings) == 3
        statuses = {f["finding_id"]: f["verification_status"] for f in findings}
        assert statuses["f-001"] == "confirmed"
        assert statuses["f-002"] == "false_positive"
        assert statuses["f-003"] == "unverified"

    @pytest.mark.asyncio
    async def test_report_severity_uses_all_findings(self, reporter):
        """Executive report severity should use all findings, not just confirmed."""
        for fid, sev in [("f-001", "critical"), ("f-002", "high"), ("f-003", "high")]:
            await reporter._on_finding_event({
                "event_type": "FINDING_CREATED",
                "payload": {"finding_id": fid, "title": f"Finding {fid}", "severity": sev},
            })
        # No findings confirmed — all unverified
        report = reporter.generate_report("executive")
        # With 1 critical + 2 high, overall risk must NOT be LOW
        assert report["sections"]["risk_summary"]["overall_risk"] in ("CRITICAL", "HIGH", "MEDIUM")

    def test_generate_report_includes_verification_status_per_finding(self, reporter):
        """Technical report findings all have verification_status field."""
        reporter.add_finding({"finding_id": "f-001", "title": "SQLi", "severity": "critical"})
        report = reporter.generate_report("technical")
        for finding in report["sections"]["detailed_findings"]:
            assert "verification_status" in finding
