"""EndpointAgent — Endpoint security sub-agent (Section 5.2).

Tools: sharp_edr_checker, lotl_crafter
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

ENDPOINT_SYSTEM_PROMPT = """You are an endpoint security agent. Assess endpoint defenses and evasion.

Available tools: sharp_edr_checker, lotl_crafter

Respond with JSON: {"tool": "name", "input": {"target": "...", "flags": "..."}, "reasoning": "...", "is_terminal": false}
When done: {"tool": null, "input": {}, "reasoning": "Endpoint assessment complete", "is_terminal": true}"""


@dataclass
class EndpointAgent(BaseAgent):
    """Endpoint security assessment agent."""

    agent_type: AgentType = AgentType.ENDPOINT
    engine: EngineType = EngineType.INFRASTRUCTURE
    allowed_tools: frozenset[str] = field(
        default_factory=lambda: frozenset({"sharp_edr_checker", "lotl_crafter"})
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
            return await _plan_with_llm(self, task, target, ENDPOINT_SYSTEM_PROMPT)
        return self._plan_fallback(target)

    def _plan_fallback(self, target: str) -> AgentAction | None:
        step = len(self._action_history)
        steps = [
            AgentAction("sharp_edr_checker", {"target": target}, "EDR detection and evasion check"),
            AgentAction("lotl_crafter", {"target": target}, "Living off the land technique assessment"),
        ]
        if step >= len(steps):
            return None
        action = steps[step]
        self._action_history.append({"tool": action.tool_name, "input": action.tool_input, "reasoning": action.reasoning})
        return action
