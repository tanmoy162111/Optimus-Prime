"""ChatHandler — Operator message routing (Section 3.2 / clawhip).

Receives operator messages from WebSocket:
  - Detects OmX keywords ($pentest, $recon, etc.)
  - Routes keyword commands to OmX planner -> returns structured plan
  - Routes natural language to LLMRouter for conversational response
  - Publishes all interactions to EventBus lifecycle channel
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from backend.core.llm_router import LLMMessage, LLMRouter
from backend.core.models import ScopeConfig
from backend.core.omx import EngagementPlan, OmX

logger = logging.getLogger(__name__)


@dataclass
class ChatResponse:
    """Response from the chat handler."""
    response_type: str  # "plan", "chat", "error"
    content: str
    plan: EngagementPlan | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        """Serialize to dict for WebSocket delivery."""
        result: dict[str, Any] = {
            "type": self.response_type,
            "content": self.content,
        }
        if self.plan:
            result["plan"] = {
                "plan_id": self.plan.plan_id,
                "directive": self.plan.directive,
                "description": self.plan.description,
                "phase_count": self.plan.phase_count(),
                "phases": [
                    {
                        "phase_id": p.phase_id,
                        "name": p.name,
                        "description": p.description,
                        "agents": [a.value for a in p.agent_types],
                        "gate": {
                            "type": p.gate.gate_type,
                            "description": p.gate.description,
                        } if p.gate else None,
                    }
                    for p in self.plan.phases
                ],
                "agents_involved": [a.value for a in self.plan.agent_types_involved()],
            }
        if self.metadata:
            result["metadata"] = self.metadata
        return result


class ChatHandler:
    """Routes operator messages to OmX or conversational LLM.

    Implements the clawhip event-routing pattern: operator messages
    are processed and results published to EventBus for frontend delivery.
    Agent events never pollute agent context.
    """

    def __init__(
        self,
        omx: OmX,
        llm_router: LLMRouter | None = None,
        event_bus: Any = None,
        scope: ScopeConfig | None = None,
    ) -> None:
        self._omx = omx
        self._llm = llm_router
        self._event_bus = event_bus
        self._scope = scope

    def set_scope(self, scope: ScopeConfig) -> None:
        """Update the active engagement scope."""
        self._scope = scope

    async def handle_message(self, message: str) -> ChatResponse:
        """Process an operator message and return a response."""
        # Publish incoming message to EventBus
        if self._event_bus:
            await self._event_bus.publish(
                channel="lifecycle",
                event_type="OPERATOR_MESSAGE",
                payload={"message": message[:500]},
            )

        # Check for OmX directives
        directive = self._omx._detect_directive(message)

        if directive:
            return await self._handle_directive(message)
        else:
            return await self._handle_conversation(message)

    async def _handle_directive(self, message: str) -> ChatResponse:
        """Handle an OmX directive command."""
        try:
            plan = await self._omx.plan(message, scope=self._scope)

            # Build human-readable plan description
            content = self._format_plan(plan)

            # Publish plan to EventBus
            if self._event_bus:
                await self._event_bus.publish(
                    channel="lifecycle",
                    event_type="ENGAGEMENT_PLANNED",
                    payload={
                        "plan_id": plan.plan_id,
                        "directive": plan.directive,
                        "phase_count": plan.phase_count(),
                    },
                )

            return ChatResponse(
                response_type="plan",
                content=content,
                plan=plan,
            )
        except Exception as exc:
            logger.error("ChatHandler: directive handling failed: %s", exc)
            return ChatResponse(
                response_type="error",
                content=f"Failed to create engagement plan: {exc}",
            )

    async def _handle_conversation(self, message: str) -> ChatResponse:
        """Handle a conversational message via LLM."""
        if self._llm is None:
            return ChatResponse(
                response_type="chat",
                content=(
                    "I'm Optimus Prime, a security assessment platform. "
                    "Use directives like $pentest, $recon, $cloud-audit to start an engagement, "
                    "or ask me about security topics."
                ),
            )

        try:
            system_prompt = (
                "You are Optimus Prime, an AI-powered security assessment platform. "
                "You help operators plan and execute security engagements. "
                "Available directives: $pentest, $recon, $cloud-audit, $genai-probe, "
                "$scope-discover, $iam-audit, $endpoint, $ics-audit. "
                "Answer questions about security, explain findings, or help plan engagements."
            )

            response = await self._llm.complete(
                messages=[LLMMessage(role="user", content=message)],
                system_prompt=system_prompt,
                max_tokens=2048,
            )

            return ChatResponse(
                response_type="chat",
                content=response.content,
                metadata={"model": response.model, "tokens": response.tokens_used},
            )
        except Exception as exc:
            logger.error("ChatHandler: LLM conversation failed: %s", exc)
            return ChatResponse(
                response_type="error",
                content=f"I encountered an error processing your message: {exc}",
            )

    def _format_plan(self, plan: EngagementPlan) -> str:
        """Format an engagement plan as human-readable text."""
        lines = [
            f"Engagement Plan: {plan.description}",
            f"Plan ID: {plan.plan_id}",
            f"Directive: {plan.directive}",
            f"Phases: {plan.phase_count()}",
            "",
        ]

        for i, phase in enumerate(plan.phases, 1):
            agents = ", ".join(a.value for a in phase.agent_types) or "auto"
            gate_info = ""
            if phase.gate:
                gate_info = f" [GATE: {phase.gate.gate_type} — {phase.gate.description}]"
            lines.append(f"  {i}. {phase.name}: {phase.description}")
            lines.append(f"     Agents: {agents}{gate_info}")

        lines.append("")
        lines.append(
            f"Agents involved: {', '.join(a.value for a in plan.agent_types_involved())}"
        )

        return "\n".join(lines)
