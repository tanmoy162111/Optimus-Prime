import logging
from typing import Dict, Any, List
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class IntelligentReporter:
    def __init__(self):
        self.template_path = "backend/reporting/template.html"

    async def render_html(
        self,
        findings: List[Dict[str, Any]],
        session: Dict[str, Any],
        include_xai: bool = True,
    ) -> str:
        severity_counts = self._count_severity(findings)
        
        html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Optimus Security Report</title>
    <style>
        body {{ font-family: Arial, sans-serif; margin: 40px; }}
        h1 {{ color: #1a1a1a; }}
        .finding {{ border: 1px solid #ddd; margin: 10px 0; padding: 15px; }}
        .critical {{ border-left: 4px solid #d32f2f; }}
        .high {{ border-left: 4px solid #f57c00; }}
        .medium {{ border-left: 4px solid #fbc02d; }}
        .low {{ border-left: 4px solid #388e3c; }}
        .summary {{ background: #f5f5f5; padding: 20px; margin: 20px 0; }}
    </style>
</head>
<body>
    <h1>Optimus Security Report</h1>
    <div class="summary">
        <h2>Executive Summary</h2>
        <p>Target: {session.get('target', 'N/A')}</p>
        <p>Total Findings: {len(findings)}</p>
        <p>CRITICAL: {severity_counts.get('CRITICAL', 0)}</p>
        <p>HIGH: {severity_counts.get('HIGH', 0)}</p>
        <p>MEDIUM: {severity_counts.get('MEDIUM', 0)}</p>
        <p>LOW: {severity_counts.get('LOW', 0)}</p>
    </div>
    <h2>Findings</h2>
"""
        
        for finding in findings:
            severity = finding.get("severity", "LOW").upper()
            html += f"""
    <div class="finding {severity.lower()}">
        <h3>{finding.get('title', 'Untitled')}</h3>
        <p>{finding.get('description', '')}</p>
        <pre>{finding.get('evidence', '')}</pre>
    </div>
"""
        
        if include_xai:
            html += """
    <h2>XAI Audit Trail</h2>
    <p>See full audit log in exported JSON.</p>
"""
        
        html += """
</body>
</html>"""
        
        return html

    def _count_severity(self, findings: List[ Dict[str, Any]]) -> Dict[str, int]:
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for f in findings:
            sev = f.get("severity", "").upper()
            if sev in counts:
                counts[sev] += 1
        return counts

    async def generate_pdf(self, html: str, output_path: str) -> bytes:
        from weasyprint import HTML
        return HTML(string=html).write_pdf()