"""IntelligentReporter — 6 report formats x 5 compliance frameworks (Section 16).

Subscribes to EventBus findings channel, accumulates CONFIRMED findings,
and generates reports in all 6 formats with compliance mapping.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from backend.intelligence.compliance_mapping import (
    ComplianceMappingDB,
    SUPPORTED_FRAMEWORKS,
)

logger = logging.getLogger(__name__)

# Report format identifiers (Section 16.1)
REPORT_FORMATS = [
    "executive",
    "technical",
    "remediation_roadmap",
    "developer_handoff",
    "compliance_mapping",
    "regression",
]


class IntelligentReporter:
    """Generates comprehensive security assessment reports.

    Supports all 6 report formats (Section 16.1) and all 5
    compliance frameworks (Section 16.2). Subscribes to EventBus
    findings channel to accumulate CONFIRMED findings in real-time.
    """

    def __init__(
        self,
        event_bus: Any = None,
        compliance_db: ComplianceMappingDB | None = None,
        pdf_renderer: Any = None,
    ) -> None:
        self._event_bus = event_bus
        self._compliance = compliance_db or ComplianceMappingDB()
        self._pdf_renderer = pdf_renderer  # WeasyPrint wrapper, mocked in tests
        self._confirmed_findings: list[dict[str, Any]] = []
        # Cache all FINDING_CREATED payloads by finding_id so that when a
        # FINDING_CLASSIFIED event arrives (which only carries the id +
        # classification), we can look up and store the *full* finding dict.
        self._finding_cache: dict[str, dict[str, Any]] = {}
        # All unverified findings — used as fallback when no verification loop ran.
        self._all_findings: list[dict[str, Any]] = []
        self._subscribed = False

    async def subscribe_to_findings(self) -> None:
        """Subscribe to EventBus findings channel to accumulate CONFIRMED findings."""
        if self._event_bus and not self._subscribed:
            self._event_bus.subscribe("findings", self._on_finding_event)
            self._subscribed = True

    async def _on_finding_event(self, event: dict[str, Any]) -> None:
        """Handle incoming finding events.

        Tracks ALL findings with their verification status:
          FINDING_CREATED        → added to _all_findings with status "unverified"
          FINDING_CLASSIFIED     → status updated in _all_findings cache
        """
        event_type = event.get("event_type", "")
        payload = event.get("payload", {})

        if event_type == "FINDING_CREATED":
            fid = payload.get("finding_id") or payload.get("id", "")
            finding = dict(payload)
            finding.setdefault("verification_status", "unverified")
            if fid:
                self._finding_cache[fid] = finding
            self._all_findings.append(finding)

        elif event_type == "FINDING_CLASSIFIED":
            classification = payload.get("classification", "")
            fid = payload.get("finding_id", "")
            if fid and fid in self._finding_cache:
                self._finding_cache[fid]["verification_status"] = classification
                # Also update the entry in _all_findings list (same dict object via cache ref)
            # Legacy: also maintain confirmed list for backwards compat
            if classification == "confirmed":
                if fid and fid in self._finding_cache:
                    full = dict(self._finding_cache[fid])
                    full["classification"] = "confirmed"
                    self._confirmed_findings.append(full)
                else:
                    entry = dict(payload)
                    entry["verification_status"] = "confirmed"
                    self._confirmed_findings.append(entry)

    def add_finding(self, finding: dict[str, Any]) -> None:
        """Manually add a confirmed finding (useful for testing / direct use)."""
        fid = finding.get("finding_id") or finding.get("id", "")
        entry = dict(finding)
        entry.setdefault("verification_status", "confirmed")
        if fid:
            self._finding_cache[fid] = entry
        self._all_findings.append(entry)
        self._confirmed_findings.append(entry)

    @property
    def confirmed_findings(self) -> list[dict[str, Any]]:
        return list(self._confirmed_findings)

    @property
    def all_findings(self) -> list[dict[str, Any]]:
        """All findings seen (confirmed + unverified).

        Use this when you want every finding regardless of verification status.
        """
        return list(self._all_findings)

    def get_findings_for_report(self) -> list[dict[str, Any]]:
        """Return ALL findings for report generation, each with verification_status.

        Returns the complete finding set so the report reflects all discovered
        issues regardless of verification outcome. The verification_status field
        lets operators filter by CONFIRMED / MANUAL_REVIEW / UNVERIFIED / FALSE_POSITIVE.
        """
        findings = []
        for finding in self._all_findings:
            f = dict(finding)
            f.setdefault("verification_status", "unverified")
            findings.append(f)
        if not findings and self._confirmed_findings:
            # Fallback: manually-added findings via add_finding()
            return list(self._confirmed_findings)
        return findings

    # ------------------------------------------------------------------
    # Report Generation
    # ------------------------------------------------------------------

    def generate_report(
        self,
        report_format: str,
        framework: str | None = None,
        findings: list[dict[str, Any]] | None = None,
        client_profile: dict[str, Any] | None = None,
        prior_findings: list[dict[str, Any]] | None = None,
    ) -> dict[str, Any]:
        """Generate a report in the specified format.

        Args:
            report_format: One of REPORT_FORMATS.
            framework: Compliance framework (required for compliance_mapping format).
            findings: Override findings (defaults to accumulated confirmed).
            client_profile: Optional client profile for context.
            prior_findings: Previous engagement findings (for regression format).

        Returns:
            Structured report dict with format-specific sections.
        """
        active_findings = findings if findings is not None else self.get_findings_for_report()
        now = datetime.now(timezone.utc).isoformat()

        base = {
            "format": report_format,
            "generated_at": now,
            "finding_count": len(active_findings),
            "framework": framework,
        }

        generators = {
            "executive": self._gen_executive,
            "technical": self._gen_technical,
            "remediation_roadmap": self._gen_remediation_roadmap,
            "developer_handoff": self._gen_developer_handoff,
            "compliance_mapping": self._gen_compliance_mapping,
            "regression": self._gen_regression,
        }

        gen = generators.get(report_format)
        if gen is None:
            raise ValueError(f"Unknown report format: {report_format}")

        report_data = gen(active_findings, framework, client_profile, prior_findings)
        base.update(report_data)
        return base

    def _severity_counts(self, findings: list[dict[str, Any]]) -> dict[str, int]:
        counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "info": 0}
        for f in findings:
            sev = f.get("severity", "info").lower()
            if sev in counts:
                counts[sev] += 1
            else:
                counts["info"] += 1
        return counts

    def _gen_executive(
        self,
        findings: list[dict[str, Any]],
        framework: str | None,
        client_profile: dict[str, Any] | None,
        prior_findings: list[dict[str, Any]] | None,
    ) -> dict[str, Any]:
        """Executive summary — C-suite / board. No technical jargon."""
        severity = self._severity_counts(findings)
        critical_high = severity["critical"] + severity["high"]

        risk_level = "LOW"
        if critical_high >= 5:
            risk_level = "CRITICAL"
        elif critical_high >= 3:
            risk_level = "HIGH"
        elif critical_high >= 1:
            risk_level = "MEDIUM"

        top_findings = [
            {
                "title": f.get("title", "Unknown"),
                "severity": f.get("severity", "info"),
                "business_impact": f.get("description", "Potential security impact"),
            }
            for f in sorted(findings, key=lambda x: _severity_rank(x.get("severity", "info")))[:3]
        ]

        recommendations = []
        if severity["critical"] > 0:
            recommendations.append("Immediately remediate all critical findings")
        if severity["high"] > 0:
            recommendations.append("Address high-severity findings within 30 days")
        if severity["medium"] > 0:
            recommendations.append("Schedule medium-severity fixes in next sprint")
        if not recommendations:
            recommendations.append("Continue regular security assessments")

        return {
            "sections": {
                "risk_summary": {
                    "overall_risk": risk_level,
                    "severity_breakdown": severity,
                    "total_findings": len(findings),
                },
                "top_findings": top_findings,
                "recommendations": recommendations,
                "business_impact": f"{critical_high} findings pose direct business risk",
            },
        }

    def _gen_technical(
        self,
        findings: list[dict[str, Any]],
        framework: str | None,
        client_profile: dict[str, Any] | None,
        prior_findings: list[dict[str, Any]] | None,
    ) -> dict[str, Any]:
        """Technical report — full finding details, reproduction steps."""
        detailed_findings = []
        for f in findings:
            detailed_findings.append({
                "finding_id": f.get("finding_id", ""),
                "title": f.get("title", "Unknown"),
                "severity": f.get("severity", "info"),
                "verification_status": f.get("verification_status", "unverified"),
                "description": f.get("description", ""),
                "target": f.get("target", ""),
                "port": f.get("port"),
                "tool": f.get("tool", ""),
                "evidence": f.get("evidence", ""),
                "reproduction_steps": f.get("reproduction_steps", "Run tool against target"),
                "cvss_score": f.get("cvss_score"),
                "cve_ids": f.get("cve_ids", []),
                "attack_technique": f.get("attack_technique", ""),
            })

        compliance_summary = None
        if framework:
            gap = self._compliance.gap_analysis(findings, framework)
            compliance_summary = gap

        return {
            "sections": {
                "methodology": "Automated assessment using Optimus Prime v2.0",
                "scope_summary": "As defined in engagement scope configuration",
                "detailed_findings": detailed_findings,
                "severity_breakdown": self._severity_counts(findings),
                "compliance_summary": compliance_summary,
            },
        }

    def _gen_remediation_roadmap(
        self,
        findings: list[dict[str, Any]],
        framework: str | None,
        client_profile: dict[str, Any] | None,
        prior_findings: list[dict[str, Any]] | None,
    ) -> dict[str, Any]:
        """Remediation roadmap — prioritised fix plan with effort estimates."""
        roadmap_items = []
        for idx, f in enumerate(
            sorted(findings, key=lambda x: _severity_rank(x.get("severity", "info")))
        ):
            sev = f.get("severity", "info").lower()
            effort = {"critical": "1-2 days", "high": "3-5 days", "medium": "1-2 weeks", "low": "1 month"}.get(sev, "backlog")
            priority = {"critical": "P0 — Immediate", "high": "P1 — High", "medium": "P2 — Medium", "low": "P3 — Low"}.get(sev, "P4 — Backlog")

            roadmap_items.append({
                "priority": priority,
                "title": f.get("title", "Unknown"),
                "severity": sev,
                "effort_estimate": effort,
                "owner": "Security team",
                "remediation_guidance": f.get("remediation", f"Fix {f.get('title', 'issue')}"),
                "dependencies": [],
            })

        return {
            "sections": {
                "roadmap": roadmap_items,
                "timeline_summary": {
                    "immediate": sum(1 for i in roadmap_items if "P0" in i["priority"]),
                    "short_term": sum(1 for i in roadmap_items if "P1" in i["priority"]),
                    "medium_term": sum(1 for i in roadmap_items if "P2" in i["priority"]),
                    "long_term": sum(1 for i in roadmap_items if "P3" in i["priority"] or "P4" in i["priority"]),
                },
            },
        }

    def _gen_developer_handoff(
        self,
        findings: list[dict[str, Any]],
        framework: str | None,
        client_profile: dict[str, Any] | None,
        prior_findings: list[dict[str, Any]] | None,
    ) -> dict[str, Any]:
        """Developer handoff — per-finding code-level fix suggestions."""
        tickets = []
        for f in findings:
            tickets.append({
                "ticket_title": f"[Security] {f.get('title', 'Unknown')}",
                "severity": f.get("severity", "info"),
                "affected_component": f.get("target", "unknown"),
                "description": f.get("description", ""),
                "code_context": f.get("evidence", "See tool output for details"),
                "suggested_fix": f.get("remediation", "Apply security fix"),
                "testing_guidance": f"Verify fix by re-running {f.get('tool', 'security scan')}",
                "references": f.get("cve_ids", []),
            })

        return {
            "sections": {
                "tickets": tickets,
                "developer_notes": "Each ticket represents a confirmed security finding requiring code-level remediation",
            },
        }

    def _gen_compliance_mapping(
        self,
        findings: list[dict[str, Any]],
        framework: str | None,
        client_profile: dict[str, Any] | None,
        prior_findings: list[dict[str, Any]] | None,
    ) -> dict[str, Any]:
        """Compliance mapping — findings mapped to framework controls."""
        if not framework:
            framework = "NIST-CSF"  # Default framework

        control_map = self._compliance.map_findings(findings, framework)
        gap = self._compliance.gap_analysis(findings, framework)

        control_details = []
        for control_id, mapped_findings in control_map.items():
            control_details.append({
                "control_id": control_id,
                "finding_count": len(mapped_findings),
                "findings": [
                    {"title": f.get("title", ""), "severity": f.get("severity", "info")}
                    for f in mapped_findings
                ],
            })

        return {
            "sections": {
                "framework": framework,
                "control_mapping": control_details,
                "gap_analysis": gap,
                "compliance_score": gap["coverage_pct"],
            },
        }

    def _gen_regression(
        self,
        findings: list[dict[str, Any]],
        framework: str | None,
        client_profile: dict[str, Any] | None,
        prior_findings: list[dict[str, Any]] | None,
    ) -> dict[str, Any]:
        """Regression report — delta vs last engagement."""
        prior = prior_findings or []
        prior_titles = {f.get("title", "") for f in prior}
        current_titles = {f.get("title", "") for f in findings}

        new_findings = [f for f in findings if f.get("title", "") not in prior_titles]
        resolved = [f for f in prior if f.get("title", "") not in current_titles]
        persisting = [f for f in findings if f.get("title", "") in prior_titles]

        return {
            "sections": {
                "summary": {
                    "new_count": len(new_findings),
                    "resolved_count": len(resolved),
                    "persisting_count": len(persisting),
                    "total_current": len(findings),
                    "total_prior": len(prior),
                },
                "new_findings": [
                    {"title": f.get("title", ""), "severity": f.get("severity", "info")}
                    for f in new_findings
                ],
                "resolved_findings": [
                    {"title": f.get("title", ""), "severity": f.get("severity", "info")}
                    for f in resolved
                ],
                "persisting_findings": [
                    {"title": f.get("title", ""), "severity": f.get("severity", "info")}
                    for f in persisting
                ],
                "trend": (
                    "improving" if len(resolved) > len(new_findings)
                    else "degrading" if len(new_findings) > len(resolved)
                    else "stable"
                ),
            },
        }

    # ------------------------------------------------------------------
    # PDF Export
    # ------------------------------------------------------------------

    async def export_pdf(self, report_data: dict[str, Any]) -> bytes:
        """Render report to PDF via WeasyPrint (or mock renderer).

        Uses simple HTML template rendering. In production, Jinja2 +
        WeasyPrint. In tests, returns a mock PDF byte string.
        """
        if self._pdf_renderer:
            return await self._pdf_renderer(report_data)

        # Default: generate simple HTML and return as bytes
        html = self.render_html(report_data)
        return html.encode("utf-8")

    def render_html(self, report_data: dict[str, Any]) -> str:
        """Render report data to HTML string."""
        fmt = report_data.get("format", "technical")
        generated = report_data.get("generated_at", "")
        count = report_data.get("finding_count", 0)
        sections = report_data.get("sections", {})

        html_parts = [
            "<!DOCTYPE html><html><head>",
            f"<title>Optimus Prime Security Report — {fmt.title()}</title>",
            "<style>body{font-family:Arial,sans-serif;margin:2em;} "
            "h1{color:#1a1a2e;} h2{color:#16213e;} "
            ".finding{border:1px solid #ddd;padding:1em;margin:0.5em 0;} "
            ".critical{border-left:4px solid #e74c3c;} "
            ".high{border-left:4px solid #e67e22;} "
            ".medium{border-left:4px solid #f39c12;} "
            ".low{border-left:4px solid #27ae60;}</style>",
            "</head><body>",
            f"<h1>Security Assessment Report — {fmt.replace('_', ' ').title()}</h1>",
            f"<p>Generated: {generated} | Findings: {count}</p>",
        ]

        # Render sections based on format
        for section_name, section_data in sections.items():
            html_parts.append(f"<h2>{section_name.replace('_', ' ').title()}</h2>")
            if isinstance(section_data, list):
                for item in section_data:
                    if isinstance(item, dict):
                        sev = item.get("severity", "info")
                        html_parts.append(f'<div class="finding {sev}">')
                        for k, v in item.items():
                            html_parts.append(f"<p><strong>{k}:</strong> {v}</p>")
                        html_parts.append("</div>")
                    else:
                        html_parts.append(f"<p>{item}</p>")
            elif isinstance(section_data, dict):
                for k, v in section_data.items():
                    html_parts.append(f"<p><strong>{k}:</strong> {v}</p>")
            else:
                html_parts.append(f"<p>{section_data}</p>")

        html_parts.append("</body></html>")
        return "\n".join(html_parts)


def _severity_rank(severity: str) -> int:
    """Rank severity for sorting (lower = more severe)."""
    return {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}.get(
        severity.lower(), 5
    )
