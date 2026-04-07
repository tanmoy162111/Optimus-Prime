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
    strategy_engine: Any = None
    _action_history: list[dict[str, Any]] = field(default_factory=list)

    async def execute(self, task: AgentTask) -> AgentResult:
        self._action_history = []
        result = await self.run_loop(task)
        await self._post_run_enrich(result)
        return result

    async def _post_run_enrich(self, result: AgentResult) -> None:
        """Enrich findings with StrategyEvolutionEngine after run_loop completes."""
        if self.strategy_engine is None:
            return

        findings = getattr(result, "findings", []) or []
        if not findings:
            return

        try:
            from backend.intelligence.strategy_evolution import AttackChain, ChainNode

            nodes = []
            for i, finding in enumerate(findings):
                cve_id = finding.get("cve_id") if isinstance(finding, dict) else None
                title = (
                    finding.get("title", "") if isinstance(finding, dict)
                    else getattr(finding, "title", "")
                )
                tool = (
                    finding.get("tool_used", "") if isinstance(finding, dict)
                    else getattr(finding, "tool_used", "")
                )
                nodes.append(ChainNode(
                    step_id=f"intel-{i}",
                    technique=title or "unknown",
                    cve_id=cve_id,
                    tool=tool or None,
                ))

            chain = AttackChain(
                chain_id=f"intel-chain-{id(result)}",
                nodes=nodes,
                target=str(self.scope.targets[0]) if self.scope and self.scope.targets else "",
            )

            enriched = await self.strategy_engine.enrich_chain(chain)
            logger.info(
                "IntelAgent: enriched %d/%d nodes with KB intel",
                enriched.enrichment_count,
                len(nodes),
            )

        except Exception as exc:
            logger.warning("IntelAgent: post-run enrichment failed (non-fatal): %s", exc)

    async def _plan_next_action(self, task: AgentTask) -> AgentAction | None:
        target = _extract_target(task.prompt, scope=self.scope)
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
