"""ReconAgent — First functional security sub-agent (Section 5.2).

Performs active and passive reconnaissance:
  - nmap, whatweb, dnsrecon, sublist3r, amass
  - LLM-driven action planning per iteration
  - Publishes findings to DurableEventLog-backed EventBus
  - Terminates cleanly via max_iterations guard
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Any

from backend.core.base_agent import AgentAction, BaseAgent, ToolResult
from backend.core.llm_router import LLMMessage, LLMRouter
from backend.core.models import (
    AgentResult,
    AgentTask,
    AgentType,
    EngineType,
    Finding,
    FindingClassification,
    ScopeConfig,
)

logger = logging.getLogger(__name__)

# System prompt for ReconAgent's LLM-driven planning
RECON_SYSTEM_PROMPT = """You are a reconnaissance agent in a penetration testing platform.
Your goal is to discover information about the target using available tools.

Available tools: nmap, whatweb, dnsrecon, sublist3r, amass

For each step, respond with a JSON object:
{
    "tool": "tool_name",
    "input": {"target": "...", "flags": "...", "port": "..."},
    "reasoning": "Why this action is appropriate",
    "is_terminal": false
}

When you have gathered sufficient reconnaissance data, respond with:
{
    "tool": null,
    "input": {},
    "reasoning": "Reconnaissance complete — sufficient data gathered",
    "is_terminal": true
}

Always start with broad reconnaissance (dns/subdomain) then narrow to specific services.
Never repeat the same exact scan. Progress through the recon methodology."""


@dataclass
class ReconAgent(BaseAgent):
    """Reconnaissance agent — discovers targets, services, and technologies.

    Inherits from BaseAgent and implements the agentic loop with
    LLM-driven action planning.
    """

    agent_type: AgentType = AgentType.RECON
    engine: EngineType = EngineType.INFRASTRUCTURE
    allowed_tools: frozenset[str] = field(
        default_factory=lambda: frozenset({"nmap", "whatweb", "dnsrecon", "sublist3r", "amass"})
    )
    max_iterations: int = 20

    # Runtime
    llm_router: LLMRouter | None = None
    _action_history: list[dict[str, Any]] = field(default_factory=list)
    _findings: list[Finding] = field(default_factory=list)

    async def execute(self, task: AgentTask) -> AgentResult:
        """Execute reconnaissance via the agentic run_loop."""
        self._action_history = []
        self._findings = []
        return await self.run_loop(task)

    async def _plan_next_action(self, task: AgentTask) -> AgentAction | None:
        """Plan the next reconnaissance action using LLM or fallback logic."""
        # Extract target from task prompt
        target = self._extract_target(task.prompt)

        if self.llm_router:
            return await self._plan_with_llm(task, target)
        else:
            return self._plan_fallback(task, target)

    async def _plan_with_llm(
        self, task: AgentTask, target: str,
    ) -> AgentAction | None:
        """Use LLM to decide the next action."""
        # Build context with history
        history_summary = self._build_history_summary()

        user_message = (
            f"Target: {target}\n"
            f"Task: {task.prompt}\n"
            f"Actions taken so far:\n{history_summary}\n"
            f"Plan the next reconnaissance action."
        )

        response = await self.llm_router.complete(
            messages=[LLMMessage(role="user", content=user_message)],
            system_prompt=RECON_SYSTEM_PROMPT,
            max_tokens=512,
            temperature=0.3,
        )

        try:
            data = json.loads(response.content)
        except json.JSONDecodeError:
            logger.warning("ReconAgent: LLM response not valid JSON, using fallback")
            return self._plan_fallback(task, target)

        if data.get("is_terminal") or data.get("tool") is None:
            return None

        tool_input = data.get("input", {})
        if "target" not in tool_input:
            tool_input["target"] = target

        action = AgentAction(
            tool_name=data["tool"],
            tool_input=tool_input,
            reasoning=data.get("reasoning", "LLM-planned action"),
        )

        self._action_history.append({
            "tool": action.tool_name,
            "input": action.tool_input,
            "reasoning": action.reasoning,
        })

        return action

    def _plan_fallback(self, task: AgentTask, target: str) -> AgentAction | None:
        """Deterministic fallback when LLM is unavailable.

        Follows a standard recon methodology:
          1. DNS reconnaissance
          2. Subdomain enumeration
          3. Port scanning
          4. Web technology fingerprinting
        """
        step = len(self._action_history)

        steps = [
            AgentAction(
                tool_name="dnsrecon",
                tool_input={"target": target, "flags": "-t std"},
                reasoning="Step 1: DNS reconnaissance to discover DNS records",
            ),
            AgentAction(
                tool_name="sublist3r",
                tool_input={"target": target},
                reasoning="Step 2: Subdomain enumeration",
            ),
            AgentAction(
                tool_name="nmap",
                tool_input={"target": target, "flags": "-sV --top-ports 1000"},
                reasoning="Step 3: Service version detection on top 1000 ports",
            ),
            AgentAction(
                tool_name="whatweb",
                tool_input={"target": target, "flags": "-a 3"},
                reasoning="Step 4: Web technology fingerprinting",
            ),
        ]

        if step >= len(steps):
            return None  # Terminal — all steps done

        action = steps[step]
        self._action_history.append({
            "tool": action.tool_name,
            "input": action.tool_input,
            "reasoning": action.reasoning,
        })
        return action

    def _extract_target(self, prompt: str) -> str:
        """Extract the primary target from the task prompt."""
        # Look for common patterns
        import re
        # IP address
        ip_match = re.search(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2})?\b', prompt)
        if ip_match:
            return ip_match.group()

        # Domain
        domain_match = re.search(r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b', prompt)
        if domain_match:
            return domain_match.group()

        # Fallback: use the prompt as target
        return prompt.strip()

    def _build_history_summary(self) -> str:
        """Build a summary of actions taken for LLM context."""
        if not self._action_history:
            return "No actions taken yet."

        lines = []
        for i, action in enumerate(self._action_history, 1):
            lines.append(f"{i}. {action['tool']}({action['input']}) — {action['reasoning']}")
        return "\n".join(lines)

    def parse_findings_from_output(self, tool_name: str, output: Any) -> list[Finding]:
        """Parse tool output into structured findings.

        This is a simplified parser — full parsers for each tool
        will be implemented with dedicated output processors in M2.
        """
        findings = []
        if not output:
            return findings

        output_str = str(output)

        # Simple heuristic: look for open ports in nmap output
        if tool_name == "nmap" and "open" in output_str.lower():
            import re
            port_matches = re.findall(r'(\d+)/(?:tcp|udp)\s+open\s+(\S+)', output_str)
            for port, service in port_matches:
                finding = Finding(
                    finding_id=f"recon-{tool_name}-{port}",
                    title=f"Open port {port}/{service}",
                    severity="info",
                    description=f"Port {port} is open running {service}",
                    tool=tool_name,
                    target=self._action_history[-1]["input"].get("target", "") if self._action_history else "",
                    port=int(port),
                    classification=FindingClassification.UNVERIFIED,
                )
                findings.append(finding)

        return findings
