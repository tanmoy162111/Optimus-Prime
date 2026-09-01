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
