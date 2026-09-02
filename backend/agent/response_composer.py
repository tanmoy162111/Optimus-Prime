import json
import logging
from typing import Dict, Any, List

logger = logging.getLogger(__name__)


class ResponseComposer:
    def compose(
        self,
        decision: Dict[str, Any],
        findings: List[Dict[str, Any]],
        session_state: Dict[str, Any],
    ) -> str:
        intent = decision.get("intent", "general")
        engine = decision.get("engine", "InfrastructureEngine")
        target = decision.get("target", "unknown")
        phase = decision.get("phase", "analysis")
        tools = decision.get("tools", [])
        
        parts = []
        
        parts.append(f"**Intent:** {intent}")
        parts.append(f"**Engine:** {engine}")
        parts.append(f"**Target:** {target}")
        parts.append(f"**Phase:** {phase}")
        
        if tools:
            parts.append(f"**Tools:** {', '.join(tools)}")
        
        if findings:
            severity_counts = self._count_by_severity(findings)
            parts.append(f"\n**Findings:** {len(findings)} total")
            for severity, count in severity_counts.items():
                parts.append(f"  - {severity}: {count}")
        
        token_remaining = session_state.get("token_budget_remaining", 0)
        if token_remaining < session_state.get("token_budget_initial", 500000) * 0.2:
            parts.append(f"\n⚠️ **Token budget low:** {token_remaining} remaining")
        
        return "\n".join(parts)

    def compose_stream(
        self,
        chunk: str,
        is_first: bool = False,
    ) -> str:
        if is_first:
            return f"> {chunk}"
        return chunk

    def compose_plan_summary(self, plan: Any, session: Any) -> str:
        """Turn an OmX EngagementPlan's dispatch results into an
        operator-facing chat reply (RESEARCH.md Open Question 2 — a new
        method rather than forcing the single-decision compose() signature
        to represent a multi-directive DAG result).
        """
        phase_status = session.state.phase_status
        completed = []
        failed = []
        gated = []
        pending = []

        for directive in plan.directives:
            status = phase_status.get(directive.id, "pending")
            if status == "completed":
                completed.append(directive)
            elif status == "failed":
                failed.append(directive)
            elif status == "gate_pending":
                gated.append(directive)
            else:
                pending.append(directive)

        parts = [f"**Plan:** {plan.rationale}"]
        parts.append(
            f"**Directives:** {len(plan.directives)} total — "
            f"{len(completed)} completed, {len(failed)} failed, "
            f"{len(gated)} pending gate approval, {len(pending)} pending"
        )

        def _describe(directives: List[Any]) -> List[str]:
            return [
                f"  - {d.id} ({d.phase}, {d.agent}): {d.target}" for d in directives
            ]

        if completed:
            parts.append("\n**Completed:**")
            parts.extend(_describe(completed))
        if failed:
            parts.append("\n**Failed:**")
            parts.extend(_describe(failed))
        if gated:
            parts.append("\n**Pending gate approval:**")
            parts.extend(_describe(gated))

        findings = session.state.findings
        if findings:
            severity_counts = self._count_by_severity(findings)
            parts.append(f"\n**Findings:** {len(findings)} total")
            for severity, count in severity_counts.items():
                parts.append(f"  - {severity}: {count}")

        return "\n".join(parts)

    def _count_by_severity(self, findings: List[Dict[str, Any]]) -> Dict[str, int]:
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for finding in findings:
            severity = finding.get("severity", "").upper()
            if severity in counts:
                counts[severity] += 1
        return counts


class ToolPermissionError(Exception):
    pass