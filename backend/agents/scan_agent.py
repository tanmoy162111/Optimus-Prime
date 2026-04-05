"""ScanAgent — Vulnerability scanning sub-agent (Section 5.2).

Tools: nikto, nuclei, masscan, wpscan
Follows recon phase — scans discovered services for vulnerabilities.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Any

from backend.core.base_agent import AgentAction, BaseAgent
from backend.core.llm_router import LLMMessage, LLMRouter
from backend.core.models import AgentResult, AgentTask, AgentType, EngineType, Finding, FindingClassification

logger = logging.getLogger(__name__)

SCAN_SYSTEM_PROMPT = """You are a vulnerability scanning agent. Your goal is to find vulnerabilities on the target.

Available tools: nikto, nuclei, masscan, wpscan

Respond with JSON: {"tool": "name", "input": {"target": "...", "flags": "..."}, "reasoning": "...", "is_terminal": false}
When done: {"tool": null, "input": {}, "reasoning": "Scanning complete", "is_terminal": true}"""


@dataclass
class ScanAgent(BaseAgent):
    """Vulnerability scanning agent."""

    agent_type: AgentType = AgentType.SCAN
    engine: EngineType = EngineType.INFRASTRUCTURE
    allowed_tools: frozenset[str] = field(
        default_factory=lambda: frozenset({"nikto", "nuclei", "masscan", "wpscan"})
    )
    max_iterations: int = 20
    llm_router: LLMRouter | None = None
    _action_history: list[dict[str, Any]] = field(default_factory=list)

    async def execute(self, task: AgentTask) -> AgentResult:
        self._action_history = []
        return await self.run_loop(task)

    async def _plan_next_action(self, task: AgentTask) -> AgentAction | None:
        target = _extract_target(task.prompt)
        if self.llm_router:
            return await _plan_with_llm(self, task, target, SCAN_SYSTEM_PROMPT)
        return self._plan_fallback(target)

    def _plan_fallback(self, target: str) -> AgentAction | None:
        step = len(self._action_history)
        steps = [
            AgentAction("masscan", {"target": target, "flags": "-p1-65535 --rate=1000"}, "Fast port scan"),
            AgentAction("nikto", {"target": target}, "Web server vulnerability scan"),
            AgentAction("nuclei", {"target": target, "flags": "-t cves/"}, "CVE template scan"),
            AgentAction("wpscan", {"target": target, "flags": "--enumerate vp"}, "WordPress vulnerability scan"),
        ]
        if step >= len(steps):
            return None
        action = steps[step]
        self._action_history.append({"tool": action.tool_name, "input": action.tool_input, "reasoning": action.reasoning})
        return action


# Shared helpers used by all agents

def _extract_target(prompt: str) -> str:
    import re
    ip = re.search(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2})?\b', prompt)
    if ip:
        return ip.group()
    domain = re.search(r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b', prompt)
    if domain:
        return domain.group()
    return prompt.strip()


async def _plan_with_llm(agent, task, target, system_prompt) -> AgentAction | None:
    history = "\n".join(
        f"{i+1}. {a['tool']}({a['input']})" for i, a in enumerate(agent._action_history)
    ) or "None"
    response = await agent.llm_router.complete(
        messages=[LLMMessage(role="user", content=f"Target: {target}\nTask: {task.prompt}\nHistory:\n{history}")],
        system_prompt=system_prompt, max_tokens=512, temperature=0.3,
    )
    try:
        data = json.loads(response.content)
    except json.JSONDecodeError:
        return None
    if data.get("is_terminal") or data.get("tool") is None:
        return None
    tool_input = data.get("input", {})
    if "target" not in tool_input:
        tool_input["target"] = target
    action = AgentAction(data["tool"], tool_input, data.get("reasoning", "LLM"))
    agent._action_history.append({"tool": action.tool_name, "input": action.tool_input, "reasoning": action.reasoning})
    return action
