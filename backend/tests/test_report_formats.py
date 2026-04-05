"""Tests for IntelligentReporter — 6 formats x 5 frameworks (M3).

Validates all 6 report formats generate correctly across all 5
compliance frameworks. 30 test cases total.
"""

from __future__ import annotations

import pytest

from backend.intelligence.compliance_mapping import (
    ComplianceMappingDB,
    SUPPORTED_FRAMEWORKS,
)
from backend.intelligence.intelligent_reporter import (
    IntelligentReporter,
    REPORT_FORMATS,
)


# ---------------------------------------------------------------------------
# Test findings dataset
# ---------------------------------------------------------------------------

SAMPLE_FINDINGS = [
    {
        "finding_id": "f-001",
        "title": "SQL Injection in login form",
        "severity": "critical",
        "type": "sql_injection",
        "description": "Blind SQL injection via username parameter",
        "target": "10.0.0.1",
        "port": 443,
        "tool": "sqlmap",
        "evidence": "Parameter: username, Payload: ' OR 1=1--",
        "cve_ids": ["CVE-2024-1234"],
    },
    {
        "finding_id": "f-002",
        "title": "Reflected XSS in search",
        "severity": "high",
        "type": "xss",
        "description": "Reflected cross-site scripting in search parameter",
        "target": "10.0.0.1",
        "port": 443,
        "tool": "dalfox",
        "evidence": "<script>alert(1)</script>",
    },
    {
        "finding_id": "f-003",
        "title": "Open port 22 SSH",
        "severity": "medium",
        "type": "open_port",
        "description": "SSH service exposed on port 22",
        "target": "10.0.0.1",
        "port": 22,
        "tool": "nmap",
    },
    {
        "finding_id": "f-004",
        "title": "Expired TLS certificate",
        "severity": "high",
        "type": "tls_issue",
        "description": "TLS certificate expired 30 days ago",
        "target": "api.example.com",
        "port": 443,
        "tool": "testssl",
    },
    {
        "finding_id": "f-005",
        "title": "AWS S3 bucket public",
        "severity": "critical",
        "type": "cloud_misconfiguration",
        "description": "S3 bucket allows public read access",
        "target": "s3.amazonaws.com",
        "tool": "scoutsuite",
    },
    {
        "finding_id": "f-006",
        "title": "Weak JWT signing",
        "severity": "high",
        "type": "jwt_vulnerability",
        "description": "JWT uses weak HS256 with short key",
        "target": "api.example.com",
        "tool": "jwt_tool",
    },
]

PRIOR_FINDINGS = [
    {"title": "SQL Injection in login form", "severity": "critical"},
    {"title": "CSRF on password change", "severity": "medium"},
    {"title": "Directory listing enabled", "severity": "low"},
]


@pytest.fixture
def reporter():
    return IntelligentReporter()


@pytest.fixture
def compliance_db():
    return ComplianceMappingDB()


# ---------------------------------------------------------------------------
# 6 formats x 5 frameworks = 30 test cases
# ---------------------------------------------------------------------------

class TestAllReportFormats:
    """Verify all 6 report formats generate correctly (M3 AC #3)."""

    @pytest.mark.parametrize("fmt", REPORT_FORMATS)
    @pytest.mark.parametrize("framework", SUPPORTED_FRAMEWORKS)
    def test_format_with_framework(self, reporter, fmt, framework):
        """Each format x framework combination generates valid report."""
        report = reporter.generate_report(
            report_format=fmt,
            framework=framework,
            findings=SAMPLE_FINDINGS,
            prior_findings=PRIOR_FINDINGS if fmt == "regression" else None,
        )

        # Common assertions
        assert report["format"] == fmt
        assert report["framework"] == framework
        assert report["finding_count"] == len(SAMPLE_FINDINGS)
        assert "sections" in report
        assert report["generated_at"]

    def test_executive_has_risk_summary(self, reporter):
        report = reporter.generate_report("executive", findings=SAMPLE_FINDINGS)
        sections = report["sections"]
        assert "risk_summary" in sections
        assert "top_findings" in sections
        assert "recommendations" in sections
        assert sections["risk_summary"]["overall_risk"] in ("LOW", "MEDIUM", "HIGH", "CRITICAL")

    def test_technical_has_detailed_findings(self, reporter):
        report = reporter.generate_report("technical", findings=SAMPLE_FINDINGS)
        sections = report["sections"]
        assert "detailed_findings" in sections
        assert len(sections["detailed_findings"]) == len(SAMPLE_FINDINGS)
        assert "severity_breakdown" in sections

    def test_remediation_roadmap_has_priorities(self, reporter):
        report = reporter.generate_report("remediation_roadmap", findings=SAMPLE_FINDINGS)
        sections = report["sections"]
        assert "roadmap" in sections
        assert "timeline_summary" in sections
        assert all("priority" in item for item in sections["roadmap"])

    def test_developer_handoff_has_tickets(self, reporter):
        report = reporter.generate_report("developer_handoff", findings=SAMPLE_FINDINGS)
        sections = report["sections"]
        assert "tickets" in sections
        assert len(sections["tickets"]) == len(SAMPLE_FINDINGS)
        for ticket in sections["tickets"]:
            assert "ticket_title" in ticket
            assert "suggested_fix" in ticket

    def test_compliance_mapping_has_controls(self, reporter):
        report = reporter.generate_report(
            "compliance_mapping", framework="PCI-DSS", findings=SAMPLE_FINDINGS,
        )
        sections = report["sections"]
        assert "control_mapping" in sections
        assert "gap_analysis" in sections
        assert "compliance_score" in sections

    def test_regression_has_delta(self, reporter):
        report = reporter.generate_report(
            "regression",
            findings=SAMPLE_FINDINGS,
            prior_findings=PRIOR_FINDINGS,
        )
        sections = report["sections"]
        summary = sections["summary"]
        assert summary["new_count"] >= 0
        assert summary["resolved_count"] >= 0
        assert summary["persisting_count"] >= 0
        assert sections["trend"] in ("improving", "degrading", "stable")


class TestComplianceMappingDB:
    """Validate compliance mapping and gap analysis."""

    @pytest.mark.parametrize("framework", SUPPORTED_FRAMEWORKS)
    def test_findings_mapped_to_controls(self, compliance_db, framework):
        """Every finding maps to at least 1 control in each framework."""
        mapped = compliance_db.map_findings(SAMPLE_FINDINGS, framework)
        assert len(mapped) > 0, f"No controls mapped for {framework}"

    @pytest.mark.parametrize("framework", SUPPORTED_FRAMEWORKS)
    def test_gap_analysis_all_frameworks(self, compliance_db, framework):
        """Gap analysis runs for each framework."""
        gap = compliance_db.gap_analysis(SAMPLE_FINDINGS, framework)
        assert gap["framework"] == framework
        assert gap["total_controls"] > 0
        assert isinstance(gap["tested_controls"], list)
        assert isinstance(gap["untested_controls"], list)
        assert 0 <= gap["coverage_pct"] <= 100

    def test_sql_injection_maps_to_pci_dss(self, compliance_db):
        sqli = {"title": "SQL Injection", "type": "sql_injection", "tool": "sqlmap"}
        controls = compliance_db.map_finding(sqli, "PCI-DSS")
        control_ids = {c.control_id for c in controls}
        # SQLi should map to PCI-DSS 6.x controls
        assert any("PCI-6" in cid for cid in control_ids)

    def test_credential_maps_to_gdpr(self, compliance_db):
        cred = {"title": "Exposed credential", "type": "credential", "tool": "trufflehog"}
        controls = compliance_db.map_finding(cred, "GDPR")
        assert len(controls) > 0


class TestReportPDFExport:
    """Validate PDF export (mocked)."""

    @pytest.mark.asyncio
    async def test_export_pdf_returns_bytes(self, reporter):
        report = reporter.generate_report("technical", findings=SAMPLE_FINDINGS)
        pdf_bytes = await reporter.export_pdf(report)
        assert isinstance(pdf_bytes, bytes)
        assert len(pdf_bytes) > 0
        assert b"<!DOCTYPE html>" in pdf_bytes  # HTML-based output

    @pytest.mark.asyncio
    async def test_export_pdf_custom_renderer(self):
        async def mock_renderer(data):
            return b"%PDF-1.4 mock pdf content"

        reporter = IntelligentReporter(pdf_renderer=mock_renderer)
        report = reporter.generate_report("executive", findings=SAMPLE_FINDINGS)
        pdf = await reporter.export_pdf(report)
        assert pdf.startswith(b"%PDF")
