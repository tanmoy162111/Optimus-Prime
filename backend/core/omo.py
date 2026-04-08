"""OmO — Multi-Agent Coordinator (Section 3.3).

Receives EngagementPlans from OmX and orchestrates phase execution:
  - Dispatches phases sequentially via EngineRouter
  - Spawns agents via TaskRegistry
  - Monitors lifecycle via EventBus
  - Manages phase transitions and gate checks
  - Disagreement resolution protocol (stub — full in M2)
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from dataclasses import dataclass, field
from typing import Any

from backend.core.models import (
    AgentResult,
    AgentType,
    EngineResult,
    EngineTask,
    EngineType,
    ScopeConfig,
    TaskStatus,
)
from backend.core.omx import EngagementPhase, EngagementPlan

logger = logging.getLogger(__name__)


@dataclass
class PhaseResult:
    """Result of executing a single engagement phase."""
    phase_id: str
    phase_name: str
    status: str  # "completed", "failed", "skipped", "gate_blocked"
    agent_results: list[AgentResult] = field(default_factory=list)
    error: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class EngagementResult:
    """Result of executing a complete engagement plan."""
    plan_id: str
    status: str  # "completed", "failed", "partial"
    phase_results: list[PhaseResult] = field(default_factory=list)
    total_findings: int = 0
    error: str | None = None


class OmO:
    """Multi-Agent Coordinator.

    Orchestrates engagement plan execution by dispatching phases
    to the appropriate engines and monitoring agent lifecycle.
    """

    def __init__(
        self,
        engine_router: Any = None,
        task_registry: Any = None,
        event_bus: Any = None,
        scope: ScopeConfig | None = None,
        agent_factory: Any = None,
        gate_timeout: float = 300.0,
    ) -> None:
        self._engine_router = engine_router
        self._task_registry = task_registry
        self._event_bus = event_bus
        self._scope = scope or ScopeConfig()
        self._agent_factory = agent_factory
        # Gate resolution state (#8)
        self._pending_gates: dict[str, asyncio.Event] = {}
        self._gate_decisions: dict[str, bool] = {}
        self._gate_timeout: float = gate_timeout

    async def execute_plan(self, plan: EngagementPlan) -> EngagementResult:
        """Execute an engagement plan phase by phase.

        Phases are executed sequentially (respecting depends_on).
        Gates are checked before phase execution.
        """
        scope = plan.scope or self._scope
        phase_results: list[PhaseResult] = []
        completed_phases: set[str] = set()
        total_findings = 0

        # Publish plan start
        if self._event_bus:
            await self._event_bus.publish(
                channel="lifecycle",
                event_type="ENGAGEMENT_STARTED",
                payload={
                    "plan_id": plan.plan_id,
                    "directive": plan.directive,
                    "phase_count": plan.phase_count(),
                    "agents": [a.value for a in plan.agent_types_involved()],
                },
            )

        for phase in plan.phases:
            # Check dependencies
            unmet = [dep for dep in phase.depends_on if dep not in completed_phases]
            if unmet:
                logger.warning(
                    "OmO: skipping phase %s — unmet deps: %s",
                    phase.phase_id, unmet,
                )
                phase_results.append(PhaseResult(
                    phase_id=phase.phase_id,
                    phase_name=phase.name,
                    status="skipped",
                    error=f"Unmet dependencies: {unmet}",
                ))
                continue

            # Check gate
            if phase.gate:
                gate_passed = await self._check_gate(phase)
                if not gate_passed:
                    phase_results.append(PhaseResult(
                        phase_id=phase.phase_id,
                        phase_name=phase.name,
                        status="gate_blocked",
                        error=f"Gate blocked: {phase.gate.description}",
                    ))
                    continue

            # Publish phase start
            if self._event_bus:
                await self._event_bus.publish(
                    channel="lifecycle",
                    event_type="PHASE_STARTED",
                    payload={
                        "plan_id": plan.plan_id,
                        "phase_id": phase.phase_id,
                        "phase_name": phase.name,
                        "agents": [a.value for a in phase.agent_types],
                    },
                )

            # Execute phase
            phase_result = await self._execute_phase(phase, scope, plan.plan_id)
            phase_results.append(phase_result)

            if phase_result.status == "completed":
                completed_phases.add(phase.phase_id)
                for ar in phase_result.agent_results:
                    total_findings += len(ar.findings)

            # Publish phase end
            if self._event_bus:
                await self._event_bus.publish(
                    channel="lifecycle",
                    event_type="PHASE_COMPLETED",
                    payload={
                        "plan_id": plan.plan_id,
                        "phase_id": phase.phase_id,
                        "status": phase_result.status,
                        "findings": total_findings,
                    },
                )

        # Determine overall status
        statuses = {pr.status for pr in phase_results}
        if all(s == "completed" for s in statuses):
            overall = "completed"
        elif "completed" in statuses:
            overall = "partial"
        else:
            overall = "failed"

        # Publish plan end
        if self._event_bus:
            await self._event_bus.publish(
                channel="lifecycle",
                event_type="ENGAGEMENT_COMPLETED",
                payload={
                    "plan_id": plan.plan_id,
                    "status": overall,
                    "total_findings": total_findings,
                },
            )

        return EngagementResult(
            plan_id=plan.plan_id,
            status=overall,
            phase_results=phase_results,
            total_findings=total_findings,
        )

    async def _execute_phase(
        self,
        phase: EngagementPhase,
        scope: ScopeConfig,
        plan_id: str,
    ) -> PhaseResult:
        """Execute a single phase by dispatching agents."""
        agent_results: list[AgentResult] = []

        for agent_type in phase.agent_types:
            try:
                result = await self._dispatch_agent(
                    agent_type=agent_type,
                    engine=phase.engine,
                    scope=scope,
                    phase_name=phase.name,
                    plan_id=plan_id,
                )
                agent_results.append(result)
            except Exception as exc:
                logger.error(
                    "OmO: agent %s failed in phase %s: %s",
                    agent_type.value, phase.phase_id, exc,
                )
                agent_results.append(AgentResult(
                    status="failed",
                    error=str(exc),
                ))

        # Phase is completed if at least one agent succeeded or exhausted its budget
        PARTIAL_SUCCESS_STATUSES = {"completed", "max_iterations_reached"}
        has_success = any(ar.status in PARTIAL_SUCCESS_STATUSES for ar in agent_results)
        status = "completed" if has_success else "failed"

        # Phase with no agents (e.g., report) is auto-completed
        if not phase.agent_types:
            status = "completed"

        return PhaseResult(
            phase_id=phase.phase_id,
            phase_name=phase.name,
            status=status,
            agent_results=agent_results,
        )

    async def _dispatch_agent(
        self,
        agent_type: AgentType,
        engine: EngineType,
        scope: ScopeConfig,
        phase_name: str,
        plan_id: str,
    ) -> AgentResult:
        """Dispatch a single agent via the engine router or agent factory."""
        # Guard: require at least one target before dispatching
        if not scope.targets:
            logger.warning(
                "OmO: no targets in scope for phase %s — aborting agent dispatch",
                phase_name,
            )
            return AgentResult(
                status="failed",
                error="No targets configured. Set scope via the Scope panel before running a directive.",
            )

        task_id = str(uuid.uuid4())

        # Build a prompt that includes actual targets so agents can extract them
        targets_str = " ".join(scope.targets) if scope.targets else ""
        prompt = f"Execute {phase_name} phase against {targets_str}".strip() if targets_str else f"Execute {phase_name} phase"

        # Register task
        if self._task_registry:
            task = self._task_registry.create_task(
                task_id=task_id,
                agent_class=agent_type.value,
                prompt=prompt,
            )
        else:
            from backend.core.models import AgentTask
            task = AgentTask(
                task_id=task_id,
                agent_class=agent_type.value,
                prompt=prompt,
            )

        # Publish agent spawn
        if self._event_bus:
            await self._event_bus.publish(
                channel="lifecycle",
                event_type="AGENT_SPAWNED",
                payload={
                    "task_id": task_id,
                    "agent_type": agent_type.value,
                    "phase": phase_name,
                    "plan_id": plan_id,
                },
            )

        # Use agent factory if available
        if self._agent_factory:
            try:
                agent = self._agent_factory(agent_type, scope)
                result = await agent.execute(task)

                # Update task status
                if self._task_registry:
                    status = TaskStatus.COMPLETED if result.status == "completed" else TaskStatus.FAILED
                    self._task_registry.update_status(task_id, status, result.output)

                return result
            except Exception as exc:
                logger.error("OmO: agent factory failed for %s: %s", agent_type.value, exc)
                if self._task_registry:
                    self._task_registry.update_status(task_id, TaskStatus.FAILED, str(exc))
                return AgentResult(status="failed", error=str(exc))

        # Fallback: use engine router
        if self._engine_router:
            engine_task = EngineTask(
                task_id=task_id,
                engine_type=engine,
                agent_class=agent_type.value,
                prompt=prompt,
                scope=scope,
            )

            results = await self._engine_router.route(engine_task)
            if results and results[0].agent_results:
                return results[0].agent_results[0]
            return AgentResult(status="completed", output="Engine dispatch completed")

        return AgentResult(status="completed", output="No dispatcher configured — stub")

    async def _check_gate(self, phase: EngagementPhase) -> bool:
        """Check if a phase gate condition is satisfied.

        Auto gates pass automatically. Human gates require operator
        confirmation via EventBus (#8).
        """
        if phase.gate is None:
            return True

        if phase.gate.gate_type == "auto":
            return True

        if phase.gate.gate_type == "human":
            gate_event_id = str(uuid.uuid4())

            # Publish gate request — operator must respond in chat
            if self._event_bus:
                await self._event_bus.publish(
                    channel="lifecycle",
                    event_type="GATE_CONFIRMATION_REQUIRED",
                    payload={
                        "gate_event_id": gate_event_id,
                        "phase_id": phase.phase_id,
                        "phase_name": phase.name,
                        "gate_description": phase.gate.description,
                        "confirm_command": f"confirm-{phase.phase_id}",
                        "message": (
                            f"[GATE] {phase.gate.description}. "
                            f"Type confirm-{phase.phase_id} to proceed or skip-{phase.phase_id} to abort."
                        ),
                    },
                )

            # Wait for operator confirmation (poll the gate registry, max 5 min)
            self._pending_gates[gate_event_id] = asyncio.Event()
            try:
                await asyncio.wait_for(
                    self._pending_gates[gate_event_id].wait(),
                    timeout=self._gate_timeout,
                )
                approved = self._gate_decisions.get(gate_event_id, False)
            except asyncio.TimeoutError:
                logger.warning("OmO: gate %s timed out — blocking phase", phase.phase_id)
                approved = False
            finally:
                self._pending_gates.pop(gate_event_id, None)

            return approved

        return True

    def resolve_gate(self, gate_event_id: str, approved: bool) -> None:
        """Called by ChatHandler when operator types confirm-X or skip-X."""
        self._gate_decisions[gate_event_id] = approved
        if gate_event_id in self._pending_gates:
            self._pending_gates[gate_event_id].set()
