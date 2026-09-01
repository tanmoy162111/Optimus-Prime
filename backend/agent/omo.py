"""OmO — sequential multi-agent dispatch coordinator (D-01 layer 3, D-02/D-07/D-08, ORCH-01/ORCH-03).

Walks a validated `EngagementPlan` DAG (from Plan 06's OmX) one directive at a
time, enforcing the pre-execution validation gates (scope-membership +
agent-registry + dependency-cycle + gate/dependency discipline) before any
directive is ever dispatched, invoking each `BaseAgent.execute()` with a
per-directive timeout, tracking `EngagementState.phase_status` +
`TaskRegistry`, and emitting whole-directive `PHASE_FAILED` events via
`clawhip` the instant a directive raises or times out.

D-02a note: OmO consumes OmX's directives directly. `Directive.tools` is
passed straight to `BaseAgent.execute(target, tools=...)` — no `ToolSelector`
re-selection, no `InstructionParser.parse()`, no standalone
`EngineRouter.dispatch()` call site. This is a deliberate architectural
choice (03-CONTEXT.md D-02a), not an oversight.

D-08: dispatch() is strictly sequential — one `await` per directive in DAG
order, never `asyncio.gather`/`asyncio.create_task`.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any, Dict, Optional

from backend.agent.clawhip import ClawhipEvent, ClawhipEventType
from backend.agent.omx import Directive, EngagementPlan, OmXPlanValidationError

logger = logging.getLogger(__name__)

# Last-resort per-directive wall-clock timeout (AI-SPEC.md Section 3 pitfall
# #5 — sequential dispatch with no timeout hangs the whole DAG). Overridable
# per-OmO-instance via the `directive_timeout` constructor argument.
DEFAULT_DIRECTIVE_TIMEOUT_SECONDS = 300

# Tool-name tokens that indicate aggressive scan timing/threading. Directive
# in this schema carries a plain tool-name list (no per-flag detail — OmX
# doesn't emit flags separately), so this stealth-tier hook is deliberately
# conservative: it only rejects a tool *name* that itself embeds one of these
# escalation tokens, and only applies when scope.stealth_level requests a
# stealth/low-and-slow posture. Full flag-level enforcement is a future-phase
# concern once Directive carries a dedicated `flags` field.
_STEALTH_ESCALATION_TOKENS = ("-t4", "-t5", "--max-rate", "--min-rate")
_STEALTH_CONSTRAINED_LEVELS = ("stealth", "low")


def validate_plan_against_registry(plan: EngagementPlan, agents: Dict[str, Any]) -> None:
    """Raise OmXPlanValidationError listing any directive.agent not in the
    live agent registry (RESEARCH.md Code Examples, verbatim shape).

    Pydantic validates `Directive.agent` as a plain `str`, not a `Literal[...]`
    of real agent names (the registry is dynamic) — a hallucinated/typo'd
    agent name (e.g. "ReconAgennt") passes schema validation and can only be
    caught here, before dispatch ever calls `agents[directive.agent]`.
    """
    unknown = [d.agent for d in plan.directives if d.agent not in agents]
    if unknown:
        raise OmXPlanValidationError(
            f"Plan references unregistered agent(s): {unknown}. "
            f"Known agents: {sorted(agents.keys())}"
        )


def validate_plan_acyclic(plan: EngagementPlan) -> None:
    """Raise OmXPlanValidationError if the depends_on graph has a cycle."""
    graph = {d.id: list(d.depends_on) for d in plan.directives}
    WHITE, GRAY, BLACK = 0, 1, 2
    color: Dict[str, int] = {node_id: WHITE for node_id in graph}

    def visit(node_id: str, stack: list) -> None:
        state = color.get(node_id, WHITE)
        if state == GRAY:
            cycle = " -> ".join(stack + [node_id])
            raise OmXPlanValidationError(f"Plan depends_on graph has a cycle: {cycle}")
        if state == BLACK:
            return
        color[node_id] = GRAY
        for dep in graph.get(node_id, []):
            visit(dep, stack + [node_id])
        color[node_id] = BLACK

    for directive_id in graph:
        if color[directive_id] == WHITE:
            visit(directive_id, [])


def validate_plan_scope(plan: EngagementPlan, scope: Any) -> None:
    """Deterministic set-membership scope-authorization gate (T-03-01).

    Every `directive.target` must be a member of `scope.targets` and NOT a
    member of `scope.exclusions`, UNLESS the directive carries
    `gate_required=True` — an ambiguous/discovered asset escalates via the
    gate rather than being silently included or silently excluded
    (AI-SPEC.md dimension 1).

    NOTE (03-RESEARCH.md Pitfall 7): this proves AUTHORIZATION, not
    shell-metacharacter safety — a target string that legitimately passes
    this check can still reach an unescaped f-string sink inside a sub-agent
    (a pre-existing, explicitly out-of-scope injection surface). This gate
    is not a general input-sanitization boundary.
    """
    targets = set(scope.targets)
    exclusions = set(scope.exclusions)
    violations = [
        d.id
        for d in plan.directives
        if not d.gate_required and (d.target not in targets or d.target in exclusions)
    ]
    if violations:
        raise OmXPlanValidationError(
            f"Plan directive(s) {violations} target(s) outside approved scope "
            f"(not in scope.targets, or present in scope.exclusions) and are "
            f"not gate_required"
        )


def validate_plan_stealth(plan: EngagementPlan, stealth_level: str) -> None:
    """Stealth-tier tool/flag allowlist hook (AI-SPEC.md dimension 2 /
    Section 6 guardrail table). No-op unless stealth_level is
    stealth-constrained.
    """
    if stealth_level not in _STEALTH_CONSTRAINED_LEVELS:
        return
    violations = [
        (d.id, tool)
        for d in plan.directives
        for tool in d.tools
        if any(token in tool.lower() for token in _STEALTH_ESCALATION_TOKENS)
    ]
    if violations:
        raise OmXPlanValidationError(
            f"Plan directive(s) select tool configurations exceeding "
            f"stealth_level '{stealth_level}': {violations}"
        )


def validate_plan(plan: EngagementPlan, agents: Dict[str, Any], scope: Any) -> None:
    """Run every pre-dispatch validation gate, in order, before OmO.dispatch()
    ever calls agent.execute() for directive 1 (AI-SPEC.md Section 5/6 —
    "validate before execute", Critical Failure Mode #3).
    """
    validate_plan_against_registry(plan, agents)
    validate_plan_acyclic(plan)
    validate_plan_scope(plan, scope)
    validate_plan_stealth(plan, scope.stealth_level)


class OmO:
    """Sequential multi-agent dispatch coordinator.

    D-08: dispatch() awaits each directive strictly in DAG order — never
    `asyncio.gather`/`asyncio.create_task`.
    """

    def __init__(
        self,
        agents: Dict[str, Any],
        clawhip: Any,
        task_registry: Any,
        architect: Optional[Any] = None,
        directive_timeout: int = DEFAULT_DIRECTIVE_TIMEOUT_SECONDS,
    ) -> None:
        self.agents = agents
        self.clawhip = clawhip
        self.task_registry = task_registry
        # OmO's Architect role (D-10) — a StrategyEvolutionEngine instance or
        # None. Optional and called defensively; never required for dispatch
        # to succeed.
        self.architect = architect
        self.directive_timeout = directive_timeout

    async def dispatch(
        self,
        plan: EngagementPlan,
        session: Any,
        agents: Optional[Dict[str, Any]] = None,
    ) -> None:
        active_agents = agents if agents is not None else self.agents

        # Pre-dispatch validation gate — must run to completion before
        # directive 1 ever dispatches (Critical Failure Mode #3).
        validate_plan(plan, active_agents, session.scope)

        # D-08: strictly sequential — one await per directive in DAG order,
        # no concurrent/batched dispatch primitives. The DAG is already
        # topologically ordered by OmX; OmO does not reorder it.
        for directive in plan.directives:
            unmet = [
                dep
                for dep in directive.depends_on
                if session.state.phase_status.get(dep) != "completed"
            ]
            if unmet:
                logger.warning(
                    "Directive %s skipped: unmet dependencies %s",
                    directive.id, unmet,
                )
                continue

            if directive.gate_required:
                await self._gate_pending(session, directive)
                continue

            await self._dispatch_directive(session, directive, active_agents)

    async def _gate_pending(self, session: Any, directive: Directive) -> None:
        """Terminal gate boundary (D-08 phase-3 scope boundary).

        A `gate_required=True` directive can never be cleared mid-dispatch
        this phase (OmO.dispatch() runs synchronously within a single
        process_stream() call — there is no interruption point for operator
        input). This fails closed: never blocks/polls/loops waiting for a
        clearance that cannot arrive.
        """
        session.state.set_phase_status(directive.id, "gate_pending")
        await self.task_registry.mark(
            session.session_id,
            directive.id,
            directive.agent,
            "failed",
            error_detail="gate_required, manual re-issue needed",
        )
        await self.clawhip.emit(
            session.session_id,
            ClawhipEvent(
                event_type=ClawhipEventType.GATE_PENDING,
                directive_id=directive.id,
                detail=(
                    "Directive requires operator gate approval; mid-dispatch "
                    "approval is out of scope for phase 3 — re-issue after review"
                ),
            ),
        )

    async def _dispatch_directive(
        self, session: Any, directive: Directive, active_agents: Dict[str, Any]
    ) -> None:
        agent = active_agents[directive.agent]

        await self.task_registry.mark(
            session.session_id, directive.id, directive.agent, "running"
        )
        session.state.set_phase_status(directive.id, "running")
        await self.clawhip.emit(
            session.session_id,
            ClawhipEvent(
                event_type=ClawhipEventType.PHASE_STARTED, directive_id=directive.id
            ),
        )

        try:
            # directive.tools passed straight through — no ToolSelector
            # re-selection over data OmX already produced (D-02a).
            result = await asyncio.wait_for(
                agent.execute(directive.target, tools=directive.tools),
                timeout=self.directive_timeout,
            )
        except asyncio.TimeoutError:
            await self._fail_directive(
                session, directive, f"timed out after {self.directive_timeout}s"
            )
            return
        except Exception as e:
            # Whole directive is the failure unit (D-07) — never a bare
            # except/pass; always log + emit PHASE_FAILED.
            await self._fail_directive(session, directive, str(e))
            return

        session.state.set_phase_status(directive.id, "completed")
        session.state.add_finding(result)
        await self.task_registry.mark(
            session.session_id, directive.id, directive.agent, "completed"
        )
        await self.clawhip.emit(
            session.session_id,
            ClawhipEvent(
                event_type=ClawhipEventType.PHASE_COMPLETED, directive_id=directive.id
            ),
        )

        if self.architect is not None:
            try:
                await self.architect.enrich_directive(directive)
            except Exception as exc:
                # Architect enrichment (D-10 minimal stub) is call-safe by
                # design — it must never break a directive's own success path.
                logger.warning(
                    "Architect enrichment failed for directive %s: %s",
                    directive.id, exc,
                )

    async def _fail_directive(self, session: Any, directive: Directive, error: str) -> None:
        session.state.set_phase_status(directive.id, "failed")
        await self.task_registry.mark(
            session.session_id,
            directive.id,
            directive.agent,
            "failed",
            error_detail=error,
        )
        logger.error("Directive %s failed: %s", directive.id, error)
        await self.clawhip.emit(
            session.session_id,
            ClawhipEvent(
                event_type=ClawhipEventType.PHASE_FAILED,
                directive_id=directive.id,
                detail=f"Directive {directive.id} failed",
                error=error,
            ),
        )
