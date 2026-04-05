"""CloudAgent — Cloud security audit sub-agent (Section 5.2).

Tools: scoutsuite, prowler, pacu
Credentials injected via CredentialVault.
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

CLOUD_SYSTEM_PROMPT = """You are a cloud security audit agent. Assess cloud infrastructure security.

Available tools: scoutsuite, prowler, pacu

Respond with JSON: {"tool": "name", "input": {"target": "...", "flags": "..."}, "reasoning": "...", "is_terminal": false}
When done: {"tool": null, "input": {}, "reasoning": "Cloud audit complete", "is_terminal": true}"""


@dataclass
class CloudAgent(BaseAgent):
    """Cloud security audit agent."""

    agent_type: AgentType = AgentType.CLOUD
    engine: EngineType = EngineType.INFRASTRUCTURE
    allowed_tools: frozenset[str] = field(
        default_factory=lambda: frozenset({"scoutsuite", "prowler", "pacu"})
    )
    max_iterations: int = 10
    llm_router: LLMRouter | None = None
    _action_history: list[dict[str, Any]] = field(default_factory=list)

    async def execute(self, task: AgentTask) -> AgentResult:
        self._action_history = []
        return await self.run_loop(task)

    async def _plan_next_action(self, task: AgentTask) -> AgentAction | None:
        target = _extract_target(task.prompt)
        if self.llm_router:
            return await _plan_with_llm(self, task, target, CLOUD_SYSTEM_PROMPT)
        return self._plan_fallback(target)

    def _plan_fallback(self, target: str) -> AgentAction | None:
        step = len(self._action_history)
        steps = [
            AgentAction("scoutsuite", {"target": target, "flags": "--provider aws"}, "Multi-cloud security audit"),
            AgentAction("prowler", {"target": target}, "AWS security best practices check"),
        ]
        if step >= len(steps):
            return None
        action = steps[step]
        self._action_history.append({"tool": action.tool_name, "input": action.tool_input, "reasoning": action.reasoning})
        return action
