import asyncio

import pytest
from unittest.mock import AsyncMock, MagicMock

from backend.agent.omx import Directive, EngagementPlan, OmXPlanValidationError
from backend.session.engagement_session import EngagementSession, ScopeConfig


def make_session(targets=None, exclusions=None, stealth_level="medium"):
    session = EngagementSession.create()
    session.scope = ScopeConfig(
        targets=list(targets) if targets is not None else ["acme.com"],
        exclusions=list(exclusions) if exclusions is not None else [],
        stealth_level=stealth_level,
    )
    return session


def make_directive(**overrides):
    defaults = dict(
        id="d1",
        phase="recon",
        engine="InfrastructureEngine",
        agent="ReconAgent",
        target="acme.com",
        tools=["nmap"],
        depends_on=[],
        gate_required=False,
    )
    defaults.update(overrides)
    return Directive(**defaults)


def make_plan(directives, rationale="test plan"):
    return EngagementPlan(directives=list(directives), rationale=rationale)


@pytest.fixture
def mock_agent():
    agent = MagicMock()
    agent.execute = AsyncMock(return_value={"result": "ok"})
    return agent


@pytest.fixture
def agents(mock_agent):
    return {"ReconAgent": mock_agent}


@pytest.fixture
def clawhip():
    c = MagicMock()
    c.emit = AsyncMock()
    return c


@pytest.fixture
def task_registry():
    tr = MagicMock()
    tr.mark = AsyncMock()
    return tr


# ---------------------------------------------------------------------------
# Task 1: pre-dispatch validation gate (registry + cycle + scope + stealth)
# ---------------------------------------------------------------------------


class TestValidatePlanAgainstRegistry:
    def test_unregistered_agent_blocks_dispatch(self):
        from backend.agent.omo import validate_plan_against_registry

        plan = make_plan([make_directive(agent="ReconAgennt")])
        with pytest.raises(OmXPlanValidationError):
            validate_plan_against_registry(plan, {"ReconAgent": object()})

    def test_registered_agent_passes(self):
        from backend.agent.omo import validate_plan_against_registry

        plan = make_plan([make_directive(agent="ReconAgent")])
        # Should not raise.
        validate_plan_against_registry(plan, {"ReconAgent": object()})


class TestValidatePlanAcyclic:
    def test_cycle_raises(self):
        from backend.agent.omo import validate_plan_acyclic

        plan = make_plan(
            [
                make_directive(id="d1", depends_on=["d2"]),
                make_directive(id="d2", depends_on=["d1"]),
            ]
        )
        with pytest.raises(OmXPlanValidationError):
            validate_plan_acyclic(plan)

    def test_acyclic_plan_passes(self):
        from backend.agent.omo import validate_plan_acyclic

        plan = make_plan(
            [
                make_directive(id="d1", depends_on=[]),
                make_directive(id="d2", depends_on=["d1"]),
            ]
        )
        # Should not raise.
        validate_plan_acyclic(plan)


class TestValidatePlanScope:
    def test_target_not_in_scope_targets_raises(self):
        from backend.agent.omo import validate_plan_scope

        plan = make_plan([make_directive(target="evil.com")])
        scope = ScopeConfig(targets=["acme.com"], exclusions=[])
        with pytest.raises(OmXPlanValidationError):
            validate_plan_scope(plan, scope)

    def test_target_in_exclusions_raises(self):
        from backend.agent.omo import validate_plan_scope

        plan = make_plan([make_directive(target="acme.com")])
        scope = ScopeConfig(targets=["acme.com"], exclusions=["acme.com"])
        with pytest.raises(OmXPlanValidationError):
            validate_plan_scope(plan, scope)

    def test_target_in_scope_and_not_excluded_passes(self):
        from backend.agent.omo import validate_plan_scope

        plan = make_plan([make_directive(target="acme.com")])
        scope = ScopeConfig(targets=["acme.com"], exclusions=[])
        # Should not raise.
        validate_plan_scope(plan, scope)

    def test_gate_required_directive_is_flagged_not_hard_rejected(self):
        from backend.agent.omo import validate_plan_scope

        plan = make_plan(
            [make_directive(target="discovered.acme.com", gate_required=True)]
        )
        scope = ScopeConfig(targets=["acme.com"], exclusions=[])
        # An out-of-scope target with gate_required=True escalates via the
        # gate rather than being hard-rejected at validation time.
        validate_plan_scope(plan, scope)


class TestValidationBlocksAllExecuteCalls:
    @pytest.mark.asyncio
    async def test_unregistered_agent_blocks_dispatch_before_execute(
        self, agents, clawhip, task_registry, mock_agent
    ):
        from backend.agent.omo import OmO

        plan = make_plan([make_directive(agent="ReconAgennt")])
        session = make_session()
        omo = OmO(agents, clawhip, task_registry)

        with pytest.raises(OmXPlanValidationError):
            await omo.dispatch(plan, session)

        mock_agent.execute.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_cycle_blocks_dispatch_before_execute(
        self, agents, clawhip, task_registry, mock_agent
    ):
        from backend.agent.omo import OmO

        plan = make_plan(
            [
                make_directive(id="d1", depends_on=["d2"]),
                make_directive(id="d2", depends_on=["d1"]),
            ]
        )
        session = make_session()
        omo = OmO(agents, clawhip, task_registry)

        with pytest.raises(OmXPlanValidationError):
            await omo.dispatch(plan, session)

        mock_agent.execute.assert_not_awaited()

    @pytest.mark.asyncio
    async def test_scope_violation_blocks_dispatch_before_execute(
        self, agents, clawhip, task_registry, mock_agent
    ):
        from backend.agent.omo import OmO

        plan = make_plan([make_directive(target="evil.com")])
        session = make_session(targets=["acme.com"])
        omo = OmO(agents, clawhip, task_registry)

        with pytest.raises(OmXPlanValidationError):
            await omo.dispatch(plan, session)

        mock_agent.execute.assert_not_awaited()


# ---------------------------------------------------------------------------
# Task 2: sequential dispatch loop, per-directive timeout, phase_status,
# PHASE_FAILED + terminal GATE_PENDING emission
# ---------------------------------------------------------------------------


def _clawhip_event_types(clawhip_mock):
    return [call.args[1].event_type for call in clawhip_mock.emit.await_args_list]


class TestDispatchSuccessPath:
    @pytest.mark.asyncio
    async def test_success_sets_completed_status_and_emits_phase_completed(
        self, agents, clawhip, task_registry, mock_agent
    ):
        from backend.agent.clawhip import ClawhipEventType
        from backend.agent.omo import OmO

        plan = make_plan([make_directive(id="d1")])
        session = make_session()
        omo = OmO(agents, clawhip, task_registry)

        await omo.dispatch(plan, session)

        assert session.state.phase_status["d1"] == "completed"
        assert session.state.findings == [{"result": "ok"}]
        mock_agent.execute.assert_awaited_once_with("acme.com", tools=["nmap"])
        task_registry.mark.assert_any_await(
            session.session_id, "d1", "ReconAgent", "completed"
        )
        assert ClawhipEventType.PHASE_COMPLETED in _clawhip_event_types(clawhip)

    @pytest.mark.asyncio
    async def test_directive_tools_passed_straight_through_no_tool_selector(
        self, agents, clawhip, task_registry, mock_agent
    ):
        from backend.agent.omo import OmO

        plan = make_plan([make_directive(id="d1", tools=["nikto", "nuclei"])])
        session = make_session()
        omo = OmO(agents, clawhip, task_registry)

        await omo.dispatch(plan, session)

        mock_agent.execute.assert_awaited_once_with(
            "acme.com", tools=["nikto", "nuclei"]
        )


class TestDispatchFailurePath:
    @pytest.mark.asyncio
    async def test_directive_failure_emits_phase_failed(
        self, agents, clawhip, task_registry, mock_agent
    ):
        from backend.agent.clawhip import ClawhipEventType
        from backend.agent.omo import OmO

        mock_agent.execute = AsyncMock(side_effect=RuntimeError("tool crashed"))
        plan = make_plan([make_directive(id="d1")])
        session = make_session()
        omo = OmO(agents, clawhip, task_registry)

        await omo.dispatch(plan, session)

        failed_calls = [
            call
            for call in clawhip.emit.await_args_list
            if call.args[1].event_type == ClawhipEventType.PHASE_FAILED
        ]
        assert len(failed_calls) == 1
        event = failed_calls[0].args[1]
        assert event.directive_id == "d1"
        assert "tool crashed" in event.error

    @pytest.mark.asyncio
    async def test_phase_status_set_to_failed_on_exception(
        self, agents, clawhip, task_registry, mock_agent
    ):
        from backend.agent.omo import OmO

        mock_agent.execute = AsyncMock(side_effect=RuntimeError("boom"))
        plan = make_plan([make_directive(id="d1")])
        session = make_session()
        omo = OmO(agents, clawhip, task_registry)

        await omo.dispatch(plan, session)

        assert session.state.phase_status["d1"] == "failed"
        task_registry.mark.assert_any_await(
            session.session_id, "d1", "ReconAgent", "failed", error_detail="boom"
        )

    @pytest.mark.asyncio
    async def test_timeout_is_treated_as_directive_failure_not_unhandled(
        self, agents, clawhip, task_registry, mock_agent
    ):
        from backend.agent.clawhip import ClawhipEventType
        from backend.agent.omo import OmO

        async def _slow_execute(*args, **kwargs):
            await asyncio.sleep(10)
            return {"result": "too slow"}

        mock_agent.execute = AsyncMock(side_effect=_slow_execute)
        plan = make_plan([make_directive(id="d1")])
        session = make_session()
        omo = OmO(agents, clawhip, task_registry, directive_timeout=0.01)

        # Should not raise (unhandled TimeoutError) — treated as a directive
        # failure instead.
        await omo.dispatch(plan, session)

        assert session.state.phase_status["d1"] == "failed"
        assert ClawhipEventType.PHASE_FAILED in _clawhip_event_types(clawhip)


class TestDispatchGateBoundary:
    @pytest.mark.asyncio
    async def test_gate_required_directive_is_terminal(
        self, agents, clawhip, task_registry, mock_agent
    ):
        from backend.agent.clawhip import ClawhipEventType
        from backend.agent.omo import OmO

        plan = make_plan([make_directive(id="d1", gate_required=True)])
        session = make_session()
        omo = OmO(agents, clawhip, task_registry)

        await omo.dispatch(plan, session)

        mock_agent.execute.assert_not_awaited()
        gate_calls = [
            call
            for call in clawhip.emit.await_args_list
            if call.args[1].event_type == ClawhipEventType.GATE_PENDING
        ]
        assert len(gate_calls) == 1
        assert gate_calls[0].args[1].directive_id == "d1"


class TestDispatchOrdering:
    @pytest.mark.asyncio
    async def test_directives_dispatch_strictly_in_dag_order(
        self, agents, clawhip, task_registry, mock_agent
    ):
        from backend.agent.omo import OmO

        call_order = []

        async def _record(target, **kwargs):
            call_order.append(target)
            return {"result": target}

        mock_agent.execute = AsyncMock(side_effect=_record)
        plan = make_plan(
            [
                make_directive(id="d1", target="acme.com", depends_on=[]),
                make_directive(id="d2", target="acme.com", depends_on=["d1"]),
                make_directive(id="d3", target="acme.com", depends_on=["d2"]),
            ]
        )
        session = make_session()
        omo = OmO(agents, clawhip, task_registry)

        await omo.dispatch(plan, session)

        assert call_order == ["acme.com", "acme.com", "acme.com"]
        assert mock_agent.execute.await_count == 3

    def test_no_gather_or_create_task_in_dispatch_source(self):
        import inspect
        import backend.agent.omo as omo_module

        source = inspect.getsource(omo_module.OmO.dispatch)
        assert "asyncio.gather" not in source
        assert "asyncio.create_task" not in source

    @pytest.mark.asyncio
    async def test_directive_with_unmet_dependency_is_not_dispatched(
        self, agents, clawhip, task_registry, mock_agent
    ):
        from backend.agent.omo import OmO

        mock_agent.execute = AsyncMock(side_effect=RuntimeError("d1 fails"))
        plan = make_plan(
            [
                make_directive(id="d1", depends_on=[]),
                make_directive(id="d2", depends_on=["d1"]),
            ]
        )
        session = make_session()
        omo = OmO(agents, clawhip, task_registry)

        await omo.dispatch(plan, session)

        # d1 failed, so d2 (which depends on it) must never be dispatched.
        mock_agent.execute.assert_awaited_once_with("acme.com", tools=["nmap"])
        assert "d2" not in session.state.phase_status


class TestDispatchNoBareExcept:
    def test_no_bare_except_pass_in_dispatch_source(self):
        import inspect
        import backend.agent.omo as omo_module

        source = inspect.getsource(omo_module.OmO.dispatch)
        assert "except:" not in source
        assert "except Exception:\n        pass" not in source


class TestArchitectIntegration:
    @pytest.mark.asyncio
    async def test_architect_call_does_not_raise_when_architect_present(
        self, agents, clawhip, task_registry, mock_agent
    ):
        from backend.agent.omo import OmO

        architect = MagicMock()
        architect.enrich_directive = AsyncMock(side_effect=RuntimeError("kb down"))
        plan = make_plan([make_directive(id="d1")])
        session = make_session()
        omo = OmO(agents, clawhip, task_registry, architect=architect)

        # A raising Architect call must never propagate out of dispatch().
        await omo.dispatch(plan, session)

        assert session.state.phase_status["d1"] == "completed"
        architect.enrich_directive.assert_awaited_once()

    @pytest.mark.asyncio
    async def test_dispatch_succeeds_when_architect_is_none(
        self, agents, clawhip, task_registry, mock_agent
    ):
        from backend.agent.omo import OmO

        plan = make_plan([make_directive(id="d1")])
        session = make_session()
        omo = OmO(agents, clawhip, task_registry, architect=None)

        await omo.dispatch(plan, session)

        assert session.state.phase_status["d1"] == "completed"
