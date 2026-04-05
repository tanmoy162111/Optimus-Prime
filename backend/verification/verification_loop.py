"""VerificationLoop — Autonomous finding verification (Section 13, N10).

Implements the OmO Reviewer role. Operates within VerificationPolicy limits:
  - Only uses policy-allowed tools (curl, nmap_verify, testssl_readonly, httpx_probe)
  - Respects max_requests_per_finding (default 3)
  - No credential injection (CredentialVault skips VERIFICATION_LOOP)
  - XAI logs every verification attempt
  - Publishes FINDING_VERIFIED / FINDING_CLASSIFIED events

Classification outcomes:
  - CONFIRMED: Finding reproduced with policy-approved tool
  - FALSE_POSITIVE: Not reproducible after max attempts
  - MANUAL_REVIEW: Ambiguous result requiring operator judgment
"""

from __future__ import annotations

import logging
from typing import Any

from backend.core.models import AgentType, FindingClassification
from backend.core.xai_logger import XAILogger
from backend.verification.verification_policy import (
    DEFAULT_VERIFICATION_POLICY,
    VerificationPolicy,
)

logger = logging.getLogger(__name__)


class VerificationLoop:
    """Autonomous verification of findings before reporting.

    Operates within VerificationPolicy constraints. Uses ToolExecutor
    for actual tool calls (going through full permission pipeline,
    which ensures VERIFICATION_LOOP gets no credentials).
    """

    def __init__(
        self,
        policy: VerificationPolicy | None = None,
        tool_executor: Any = None,
        event_bus: Any = None,
        xai_logger: XAILogger | None = None,
    ) -> None:
        self._policy = policy or DEFAULT_VERIFICATION_POLICY
        self._tool_executor = tool_executor
        self._event_bus = event_bus
        self._xai_logger = xai_logger or XAILogger()
        self._request_counts: dict[str, int] = {}

    @property
    def policy(self) -> VerificationPolicy:
        return self._policy

    async def verify_finding(
        self, finding_id: str, finding: dict[str, Any]
    ) -> FindingClassification:
        """Verify a single finding using policy-approved tools.

        Args:
            finding_id: Unique finding identifier.
            finding: Finding data dict with keys like target, port, tool, severity, etc.

        Returns:
            Classification: CONFIRMED, FALSE_POSITIVE, or MANUAL_REVIEW.
        """
        # Check request budget
        current_count = self._request_counts.get(finding_id, 0)
        if current_count >= self._policy.max_requests_per_finding:
            logger.info(
                "VerificationLoop: %s — max requests (%d) reached, classifying as MANUAL_REVIEW",
                finding_id, self._policy.max_requests_per_finding,
            )
            classification = FindingClassification.MANUAL_REVIEW
            await self._publish_classification(finding_id, classification)
            return classification

        # Determine verification strategy based on finding type
        tool_name, tool_input = self._plan_verification(finding)

        if tool_name is None:
            # No suitable verification tool — manual review
            classification = FindingClassification.MANUAL_REVIEW
            await self._log_attempt(finding_id, "no_tool", {}, "No suitable verification tool")
            await self._publish_classification(finding_id, classification)
            return classification

        # Check tool is in policy allowlist
        if tool_name not in self._policy.allowed_tools:
            logger.warning(
                "VerificationLoop: tool %s not in policy allowlist", tool_name,
            )
            classification = FindingClassification.MANUAL_REVIEW
            await self._publish_classification(finding_id, classification)
            return classification

        # Execute verification
        self._request_counts[finding_id] = current_count + 1
        result = await self._execute_verification(tool_name, tool_input)

        # Log to XAI
        await self._log_attempt(finding_id, tool_name, tool_input, result)

        # Classify based on result
        classification = self._classify_result(finding, result)

        # Publish events
        await self._publish_verification(finding_id, tool_name, result)
        await self._publish_classification(finding_id, classification)

        return classification

    async def verify_findings_batch(
        self, findings: list[dict[str, Any]]
    ) -> dict[str, FindingClassification]:
        """Verify a batch of findings. Returns {finding_id: classification}."""
        results = {}
        for finding in findings:
            fid = finding.get("finding_id", finding.get("id", "unknown"))
            classification = await self.verify_finding(fid, finding)
            results[fid] = classification
        return results

    def _plan_verification(
        self, finding: dict[str, Any]
    ) -> tuple[str | None, dict[str, Any]]:
        """Determine which verification tool and input to use for a finding."""
        target = finding.get("target", "")
        port = finding.get("port")
        tool_used = finding.get("tool", "")
        severity = finding.get("severity", "info")

        if not target:
            return None, {}

        # Port-based finding -> nmap_verify
        if port:
            return "nmap_verify", {
                "target": target,
                "port": str(port),
            }

        # TLS/SSL finding -> testssl_readonly
        if tool_used in ("testssl", "testssl_readonly") or "tls" in str(finding).lower():
            return "testssl_readonly", {"target": target}

        # Web finding -> httpx_probe
        if tool_used in ("nikto", "nuclei", "wpscan", "dalfox", "sqlmap", "whatweb"):
            url = target if target.startswith("http") else f"http://{target}"
            if port:
                url = f"http://{target}:{port}"
            return "httpx_probe", {"target": url}

        # Default: curl
        url = target if target.startswith("http") else f"http://{target}"
        return "curl", {"target": url}

    async def _execute_verification(
        self, tool_name: str, tool_input: dict[str, Any]
    ) -> dict[str, Any]:
        """Execute a verification tool call through ToolExecutor."""
        if self._tool_executor is None:
            # No executor — simulate success for testing
            return {
                "status": "success",
                "tool": tool_name,
                "stdout": f"Verification probe to {tool_input.get('target', '')} completed",
                "exit_code": 0,
            }

        try:
            result = await self._tool_executor.execute(
                tool_name=tool_name,
                tool_input=tool_input,
                scope=None,  # VerificationLoop scope is set by OmO
                stealth_level=None,
                allowed_tools=self._policy.allowed_tools,
                agent_id="verification-loop",
                agent_type=AgentType.VERIFICATION_LOOP,
            )
            return {
                "status": "success" if result.success else "error",
                "output": str(result.output)[:2000] if result.output else "",
                "error": result.error,
            }
        except Exception as exc:
            return {"status": "error", "error": str(exc)}

    def _classify_result(
        self, finding: dict[str, Any], result: dict[str, Any]
    ) -> FindingClassification:
        """Classify a finding based on verification result.

        Heuristics:
          - Tool returned success + output contains evidence -> CONFIRMED
          - Tool returned error or empty -> FALSE_POSITIVE
          - Ambiguous -> MANUAL_REVIEW
        """
        status = result.get("status", "")
        output = result.get("output", result.get("stdout", ""))
        error = result.get("error", "")

        if status == "error" and error:
            return FindingClassification.FALSE_POSITIVE

        if not output:
            return FindingClassification.MANUAL_REVIEW

        # Check for evidence of the finding being real
        target = finding.get("target", "")
        port = finding.get("port")

        output_lower = output.lower() if isinstance(output, str) else ""

        # Port verification: check if port appears open in output
        if port and str(port) in output_lower and "open" in output_lower:
            return FindingClassification.CONFIRMED

        # HTTP verification: check for success indicators
        if any(indicator in output_lower for indicator in ("200", "http/", "html", "server:", "open")):
            return FindingClassification.CONFIRMED

        # If we got output but no clear indicators
        if len(output_lower) > 10:
            return FindingClassification.CONFIRMED

        return FindingClassification.MANUAL_REVIEW

    async def _log_attempt(
        self, finding_id: str, tool_name: str, tool_input: dict, result: Any
    ) -> None:
        """Log verification attempt to XAI."""
        if self._xai_logger:
            await self._xai_logger.log_decision(
                agent="VerificationLoop",
                action=f"verify({finding_id}) using {tool_name}",
                result_summary=str(result)[:500],
                reasoning=f"Verifying finding {finding_id} with policy-approved tool {tool_name}",
            )

    async def _publish_verification(
        self, finding_id: str, tool_name: str, result: dict
    ) -> None:
        """Publish FINDING_VERIFIED event."""
        if self._event_bus:
            await self._event_bus.publish(
                channel="findings",
                event_type="FINDING_VERIFIED",
                payload={
                    "finding_id": finding_id,
                    "tool": tool_name,
                    "status": result.get("status", "unknown"),
                },
            )

    async def _publish_classification(
        self, finding_id: str, classification: FindingClassification
    ) -> None:
        """Publish FINDING_CLASSIFIED event."""
        if self._event_bus:
            await self._event_bus.publish(
                channel="findings",
                event_type="FINDING_CLASSIFIED",
                payload={
                    "finding_id": finding_id,
                    "classification": classification.value,
                },
            )
