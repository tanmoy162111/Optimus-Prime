"""ComplianceMappingDB — Hardcoded control mappings for 5 frameworks (Section 16.2).

Frameworks: GDPR, PCI-DSS, ISO 27001, SOC 2, NIST CSF.
Maps findings to specific compliance controls and performs gap analysis.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class ComplianceControl:
    """A single compliance framework control."""
    control_id: str
    framework: str
    title: str
    description: str
    categories: list[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Framework control definitions
# ---------------------------------------------------------------------------

GDPR_CONTROLS: list[ComplianceControl] = [
    ComplianceControl("GDPR-25", "GDPR", "Data Protection by Design",
                      "Implement appropriate technical measures for data protection",
                      ["application", "data", "encryption"]),
    ComplianceControl("GDPR-32", "GDPR", "Security of Processing",
                      "Ensure confidentiality, integrity, availability of processing systems",
                      ["network", "application", "endpoint", "cloud", "iam"]),
    ComplianceControl("GDPR-33", "GDPR", "Notification of Breach",
                      "Breach notification procedures and data exposure controls",
                      ["data", "monitoring", "incident"]),
]

PCI_DSS_CONTROLS: list[ComplianceControl] = [
    ComplianceControl("PCI-6.1", "PCI-DSS", "Identify Vulnerabilities",
                      "Establish a process to identify security vulnerabilities",
                      ["application", "network"]),
    ComplianceControl("PCI-6.2", "PCI-DSS", "Patch Management",
                      "Protect system components from known vulnerabilities via patching",
                      ["application", "endpoint", "network"]),
    ComplianceControl("PCI-6.5", "PCI-DSS", "Address Common Coding Vulnerabilities",
                      "Prevent common coding vulnerabilities in development",
                      ["application", "injection", "xss"]),
    ComplianceControl("PCI-8.1", "PCI-DSS", "User Identification",
                      "Define and implement policies for user identification management",
                      ["iam", "authentication"]),
    ComplianceControl("PCI-8.2", "PCI-DSS", "Authentication Methods",
                      "Employ at least one authentication method for all users",
                      ["iam", "authentication", "credential"]),
    ComplianceControl("PCI-10.1", "PCI-DSS", "Audit Trails",
                      "Implement audit trails linking access to individual users",
                      ["monitoring", "logging"]),
    ComplianceControl("PCI-11.1", "PCI-DSS", "Test for Wireless APs",
                      "Test for the presence of wireless access points quarterly",
                      ["network", "wireless"]),
    ComplianceControl("PCI-11.2", "PCI-DSS", "Vulnerability Scans",
                      "Run internal and external vulnerability scans quarterly",
                      ["network", "application"]),
]

ISO_27001_CONTROLS: list[ComplianceControl] = [
    ComplianceControl("A.8.1", "ISO27001", "Asset Management",
                      "Identify and manage information assets",
                      ["asset", "inventory"]),
    ComplianceControl("A.9.1", "ISO27001", "Access Control Policy",
                      "Establish access control policy based on business requirements",
                      ["iam", "authentication", "authorization"]),
    ComplianceControl("A.9.4", "ISO27001", "System and Application Access Control",
                      "Prevent unauthorized access to systems and applications",
                      ["iam", "application", "authentication"]),
    ComplianceControl("A.12.6", "ISO27001", "Technical Vulnerability Management",
                      "Prevent exploitation of technical vulnerabilities",
                      ["application", "network", "endpoint"]),
    ComplianceControl("A.13.1", "ISO27001", "Network Security Management",
                      "Ensure protection of information in networks",
                      ["network", "encryption", "firewall"]),
    ComplianceControl("A.14.2", "ISO27001", "Security in Development",
                      "Ensure information security within the development lifecycle",
                      ["application", "development", "injection", "xss"]),
    ComplianceControl("A.18.2", "ISO27001", "Information Security Reviews",
                      "Ensure compliance with security policies and standards",
                      ["monitoring", "compliance"]),
]

SOC2_CONTROLS: list[ComplianceControl] = [
    ComplianceControl("CC6.1", "SOC2", "Logical and Physical Access",
                      "Restrict logical and physical access to information assets",
                      ["iam", "authentication", "network"]),
    ComplianceControl("CC6.6", "SOC2", "Security Measures Against Threats",
                      "Implement measures to prevent/detect/respond to security threats",
                      ["network", "endpoint", "application"]),
    ComplianceControl("CC7.1", "SOC2", "Detection and Monitoring",
                      "Detect anomalies and vulnerabilities through monitoring",
                      ["monitoring", "network", "application"]),
    ComplianceControl("CC7.2", "SOC2", "Activity Monitoring",
                      "Monitor system components for anomalies",
                      ["monitoring", "logging", "endpoint"]),
    ComplianceControl("CC8.1", "SOC2", "Change Management",
                      "Authorize, design, develop, test, and approve changes",
                      ["development", "application"]),
    ComplianceControl("CC9.1", "SOC2", "Risk Mitigation",
                      "Identify and mitigate risks through defined processes",
                      ["risk", "network", "application", "cloud"]),
]

NIST_CSF_CONTROLS: list[ComplianceControl] = [
    ComplianceControl("ID.AM", "NIST-CSF", "Asset Management",
                      "Identify and manage assets enabling business objectives",
                      ["asset", "inventory", "network"]),
    ComplianceControl("ID.RA", "NIST-CSF", "Risk Assessment",
                      "Understand cybersecurity risk to operations and assets",
                      ["risk", "network", "application"]),
    ComplianceControl("PR.AC", "NIST-CSF", "Access Control",
                      "Manage access to assets and associated facilities",
                      ["iam", "authentication", "authorization"]),
    ComplianceControl("PR.DS", "NIST-CSF", "Data Security",
                      "Manage data consistent with risk strategy to protect CIA",
                      ["data", "encryption", "application"]),
    ComplianceControl("PR.IP", "NIST-CSF", "Information Protection",
                      "Maintain security policies to manage protection of assets",
                      ["application", "endpoint", "development"]),
    ComplianceControl("DE.CM", "NIST-CSF", "Security Continuous Monitoring",
                      "Monitor systems and assets to identify cybersecurity events",
                      ["monitoring", "network", "endpoint"]),
    ComplianceControl("RS.RP", "NIST-CSF", "Response Planning",
                      "Execute response processes and procedures during incidents",
                      ["incident", "response"]),
    ComplianceControl("RC.RP", "NIST-CSF", "Recovery Planning",
                      "Execute recovery processes and procedures",
                      ["recovery", "continuity"]),
]

# All frameworks indexed by name
FRAMEWORK_CONTROLS: dict[str, list[ComplianceControl]] = {
    "GDPR": GDPR_CONTROLS,
    "PCI-DSS": PCI_DSS_CONTROLS,
    "ISO27001": ISO_27001_CONTROLS,
    "SOC2": SOC2_CONTROLS,
    "NIST-CSF": NIST_CSF_CONTROLS,
}

SUPPORTED_FRAMEWORKS = list(FRAMEWORK_CONTROLS.keys())

# Finding type -> category mapping for matching
FINDING_CATEGORY_MAP: dict[str, list[str]] = {
    "sql_injection": ["application", "injection"],
    "xss": ["application", "xss"],
    "command_injection": ["application", "injection"],
    "open_port": ["network"],
    "tls_issue": ["encryption", "network"],
    "weak_password": ["iam", "authentication", "credential"],
    "jwt_vulnerability": ["iam", "authentication"],
    "oauth_flaw": ["iam", "authentication"],
    "cloud_misconfiguration": ["cloud", "network"],
    "exposed_secret": ["data", "credential"],
    "pii_exposure": ["data"],
    "edr_bypass": ["endpoint"],
    "privilege_escalation": ["endpoint", "iam"],
    "default_credentials": ["iam", "authentication", "credential"],
    "outdated_software": ["application", "endpoint"],
    "missing_headers": ["application"],
    "cors_misconfiguration": ["application"],
    "ssrf": ["application"],
    "file_inclusion": ["application"],
    "directory_traversal": ["application"],
    "information_disclosure": ["application", "data"],
    "csrf": ["application", "xss"],
}


class ComplianceMappingDB:
    """Maps findings to compliance framework controls."""

    def map_finding(
        self,
        finding: dict[str, Any],
        framework: str,
    ) -> list[ComplianceControl]:
        """Map a single finding to relevant controls in a framework.

        Matching is based on finding type/category overlap with control categories.
        """
        controls = FRAMEWORK_CONTROLS.get(framework, [])
        if not controls:
            return []

        # Determine finding categories
        finding_type = finding.get("type", "").lower()
        finding_tool = finding.get("tool", "").lower()
        finding_title = finding.get("title", "").lower()

        categories: set[str] = set()

        # From type
        if finding_type in FINDING_CATEGORY_MAP:
            categories.update(FINDING_CATEGORY_MAP[finding_type])

        # Heuristic from title/tool
        heuristic_keywords = {
            "sql": ["application", "injection"],
            "xss": ["application", "xss"],
            "inject": ["application", "injection"],
            "tls": ["encryption", "network"],
            "ssl": ["encryption", "network"],
            "port": ["network"],
            "jwt": ["iam", "authentication"],
            "oauth": ["iam", "authentication"],
            "cloud": ["cloud"],
            "aws": ["cloud"],
            "azure": ["cloud"],
            "secret": ["data", "credential"],
            "password": ["iam", "authentication", "credential"],
            "credential": ["iam", "authentication", "credential"],
            "edr": ["endpoint"],
            "privilege": ["endpoint", "iam"],
            "nmap": ["network"],
            "nikto": ["application", "network"],
            "nuclei": ["application", "network"],
            "sqlmap": ["application", "injection"],
            "dalfox": ["application", "xss"],
        }

        for keyword, cats in heuristic_keywords.items():
            if keyword in finding_title or keyword in finding_tool:
                categories.update(cats)

        # If still empty, default to application + network
        if not categories:
            categories = {"application", "network"}

        # Match controls
        matched: list[ComplianceControl] = []
        for control in controls:
            if categories & set(control.categories):
                matched.append(control)

        return matched

    def map_findings(
        self,
        findings: list[dict[str, Any]],
        framework: str,
    ) -> dict[str, list[dict[str, Any]]]:
        """Map all findings to controls. Returns {control_id: [findings]}."""
        result: dict[str, list[dict[str, Any]]] = {}
        for finding in findings:
            controls = self.map_finding(finding, framework)
            for ctrl in controls:
                if ctrl.control_id not in result:
                    result[ctrl.control_id] = []
                result[ctrl.control_id].append(finding)
        return result

    def gap_analysis(
        self,
        findings: list[dict[str, Any]],
        framework: str,
    ) -> dict[str, Any]:
        """Perform gap analysis — identify untested controls.

        Returns dict with tested_controls, untested_controls, coverage_pct.
        """
        all_controls = FRAMEWORK_CONTROLS.get(framework, [])
        mapped = self.map_findings(findings, framework)
        tested_ids = set(mapped.keys())
        all_ids = {c.control_id for c in all_controls}
        untested_ids = all_ids - tested_ids

        untested = [c for c in all_controls if c.control_id in untested_ids]
        tested = [c for c in all_controls if c.control_id in tested_ids]

        total = len(all_controls)
        coverage = len(tested) / total if total > 0 else 0.0

        return {
            "framework": framework,
            "total_controls": total,
            "tested_controls": [
                {"control_id": c.control_id, "title": c.title} for c in tested
            ],
            "untested_controls": [
                {"control_id": c.control_id, "title": c.title} for c in untested
            ],
            "coverage_pct": round(coverage * 100, 1),
        }
