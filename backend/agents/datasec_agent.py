"""DataSecAgent — Data security sub-agent (Section 5.2).

Tools: trufflehog, gitleaks, testssl, pii_parser, exfil_sim
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

DATASEC_SYSTEM_PROMPT = """You are a data security agent. Find exposed secrets, weak TLS, and PII leaks.

Available tools: trufflehog, gitleaks, testssl, pii_parser, exfil_sim

Respond with JSON: {"tool": "name", "input": {"target": "...", "flags": "..."}, "reasoning": "...", "is_terminal": false}
When done: {"tool": null, "input": {}, "reasoning": "Data security assessment complete", "is_terminal": true}"""


@dataclass
class DataSecAgent(BaseAgent):
    """Data security assessment agent."""

    agent_type: AgentType = AgentType.DATASEC
    engine: EngineType = EngineType.INFRASTRUCTURE
    allowed_tools: frozenset[str] = field(
        default_factory=lambda: frozenset({"trufflehog", "gitleaks", "testssl", "pii_parser", "exfil_sim"})
    )
    max_iterations: int = 15
    llm_router: LLMRouter | None = None
    _action_history: list[dict[str, Any]] = field(default_factory=list)

    async def execute(self, task: AgentTask) -> AgentResult:
        self._action_history = []
        return await self.run_loop(task)

    async def _plan_next_action(self, task: AgentTask) -> AgentAction | None:
        target = _extract_target(task.prompt, scope=self.scope)
        if self.llm_router:
            return await _plan_with_llm(self, task, target, DATASEC_SYSTEM_PROMPT)
        return self._plan_fallback(target)

    def _plan_fallback(self, target: str) -> AgentAction | None:
        step = len(self._action_history)
        steps = [
            AgentAction("trufflehog", {"target": target}, "Secret scanning in git repos"),
            AgentAction("gitleaks", {"target": target}, "Git repository secret scanning"),
            AgentAction("testssl", {"target": target}, "TLS/SSL configuration testing"),
            AgentAction("pii_parser", {"target": target}, "PII detection scan"),
        ]
        if step >= len(steps):
            return None
        action = steps[step]
        self._action_history.append({"tool": action.tool_name, "input": action.tool_input, "reasoning": action.reasoning})
        return action
