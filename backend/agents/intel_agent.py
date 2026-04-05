"""IntelAgent — Threat intelligence sub-agent (Section 5.2).

Tools: shodan, cve_search, exploit_db, dark_web_query
Runs in parallel with other agents — enriches findings with CVE/ATT&CK/threat intel.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from backend.core.base_agent import AgentAction, BaseAgent
from backend.core.llm_router import LLMRouter
from backend.core.models import AgentResult, AgentTask, AgentType, EngineType
from backend.agents.scan_agent import _extract_target, _plan_with_llm

logger = logging.getLogger(__name__)

INTEL_SYSTEM_PROMPT = """You are a threat intelligence agent. Enrich findings with CVE, ATT&CK, and threat intel.

Available tools: shodan, cve_search, exploit_db, dark_web_query

Respond with JSON: {"tool": "name", "input": {"target": "...", "flags": "..."}, "reasoning": "...", "is_terminal": false}
When done: {"tool": null, "input": {}, "reasoning": "Intel gathering complete", "is_terminal": true}"""


@dataclass
class IntelAgent(BaseAgent):
    """Threat intelligence enrichment agent."""

    agent_type: AgentType = AgentType.INTEL
    engine: EngineType = EngineType.INFRASTRUCTURE
    allowed_tools: frozenset[str] = field(
        default_factory=lambda: frozenset({"shodan", "cve_search", "exploit_db", "dark_web_query"})
    )
    max_iterations: int = 15
    llm_router: LLMRouter | None = None
    _action_history: list[dict[str, Any]] = field(default_factory=list)

    async def execute(self, task: AgentTask) -> AgentResult:
        self._action_history = []
        return await self.run_loop(task)

    async def _plan_next_action(self, task: AgentTask) -> AgentAction | None:
        target = _extract_target(task.prompt)
        if self.llm_router:
            return await _plan_with_llm(self, task, target, INTEL_SYSTEM_PROMPT)
        return self._plan_fallback(target)

    def _plan_fallback(self, target: str) -> AgentAction | None:
        step = len(self._action_history)
        steps = [
            AgentAction("shodan", {"target": target}, "Shodan host intelligence lookup"),
            AgentAction("cve_search", {"target": target}, "CVE database correlation"),
            AgentAction("exploit_db", {"target": target}, "Exploit database lookup"),
        ]
        if step >= len(steps):
            return None
        action = steps[step]
        self._action_history.append({"tool": action.tool_name, "input": action.tool_input, "reasoning": action.reasoning})
        return action
