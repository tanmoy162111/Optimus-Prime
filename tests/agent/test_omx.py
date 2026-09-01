import pytest
from unittest.mock import AsyncMock, MagicMock
from pydantic import ValidationError

from backend.agent.omx import (
    Directive,
    EngagementPlan,
    OmX,
    OmXPlanValidationError,
    _OMX_PLANNING_SYSTEM_PROMPT,
)
from backend.agent.orchestrator import _SYSTEM_PROMPT as _ORCHESTRATOR_SYSTEM_PROMPT
from backend.session.engagement_session import EngagementSession


def _valid_directive_dict(i, depends_on=None, gate_required=False, agent="ReconAgent"):
    return {
        "id": f"d{i}",
        "phase": "recon",
        "engine": "InfrastructureEngine",
        "agent": agent,
        "target": "acme.com",
        "tools": ["nmap"],
        "depends_on": depends_on or [],
        "gate_required": gate_required,
    }


# ---------------------------------------------------------------------------
# Task 1: Directive/EngagementPlan models + OmXPlanValidationError + prompt
# ---------------------------------------------------------------------------


def test_engagement_plan_model_validate_accepts_eight_directives():
    plan_dict = {
        "directives": [_valid_directive_dict(i) for i in range(1, 9)],
        "rationale": "full pentest decomposition",
    }
    plan = EngagementPlan.model_validate(plan_dict)
    assert len(plan.directives) == 8
    assert all(isinstance(d, Directive) for d in plan.directives)


def test_directive_rejects_bogus_engine():
    bad = _valid_directive_dict(1)
    bad["engine"] = "BogusEngine"
    with pytest.raises(ValidationError):
        Directive.model_validate(bad)


def test_directive_defaults_tools_depends_on_gate_required():
    minimal = {
        "id": "d1",
        "phase": "recon",
        "engine": "InfrastructureEngine",
        "agent": "ReconAgent",
        "target": "acme.com",
    }
    d = Directive.model_validate(minimal)
    assert d.tools == []
    assert d.depends_on == []
    assert d.gate_required is False


def test_omx_plan_validation_error_is_minimal_exception():
    assert issubclass(OmXPlanValidationError, Exception)
    assert OmXPlanValidationError.__init__ is Exception.__init__


def test_omx_planning_system_prompt_is_distinct_and_scoped():
    assert _OMX_PLANNING_SYSTEM_PROMPT != _ORCHESTRATOR_SYSTEM_PROMPT
    for engine_name in ("InfrastructureEngine", "MLAIEngine", "ICSEngine"):
        assert engine_name in _OMX_PLANNING_SYSTEM_PROMPT
    assert "$pentest" in _OMX_PLANNING_SYSTEM_PROMPT


def test_omx_planning_system_prompt_states_scope_and_stealth_constraints():
    assert "scope.targets" in _OMX_PLANNING_SYSTEM_PROMPT
    assert "scope.exclusions" in _OMX_PLANNING_SYSTEM_PROMPT
    assert "gate_required" in _OMX_PLANNING_SYSTEM_PROMPT
    assert "stealth_level" in _OMX_PLANNING_SYSTEM_PROMPT
    assert "retries" in _OMX_PLANNING_SYSTEM_PROMPT or "retry" in _OMX_PLANNING_SYSTEM_PROMPT


# ---------------------------------------------------------------------------
# Task 2: OmX.plan() forced-tool-use call with 3-attempt validation retry
# ---------------------------------------------------------------------------


def _mock_router():
    router = MagicMock()
    router.claude = MagicMock()
    router.claude.messages = MagicMock()
    return router


def _tool_use_response(plan_dict, stop_reason="tool_use", leading_text=False):
    blocks = []
    if leading_text:
        text_block = MagicMock()
        text_block.type = "text"
        blocks.append(text_block)
    tool_block = MagicMock()
    tool_block.type = "tool_use"
    tool_block.input = plan_dict
    blocks.append(tool_block)
    response = MagicMock()
    response.content = blocks
    response.stop_reason = stop_reason
    return response


@pytest.fixture
def session():
    s = EngagementSession.create()
    s.scope.targets = ["acme.com"]
    return s


@pytest.mark.asyncio
async def test_plan_generates_valid_dag(session):
    router = _mock_router()
    valid_plan = {"directives": [_valid_directive_dict(1)], "rationale": "recon only"}
    router.claude.messages.create = AsyncMock(return_value=_tool_use_response(valid_plan))
    omx = OmX(router)

    plan = await omx.plan("$recon acme.com", session)

    assert isinstance(plan, EngagementPlan)
    assert len(plan.directives) == 1
    router.claude.messages.create.assert_awaited_once()
    call_kwargs = router.claude.messages.create.call_args.kwargs
    assert call_kwargs["tool_choice"] == {
        "type": "tool",
        "name": "emit_engagement_plan",
        "disable_parallel_tool_use": True,
    }


@pytest.mark.asyncio
async def test_plan_selects_tool_use_block_not_by_position(session):
    router = _mock_router()
    valid_plan = {"directives": [_valid_directive_dict(1)], "rationale": "r"}
    router.claude.messages.create = AsyncMock(
        return_value=_tool_use_response(valid_plan, leading_text=True)
    )
    omx = OmX(router)

    plan = await omx.plan("$recon acme.com", session)

    assert isinstance(plan, EngagementPlan)


@pytest.mark.asyncio
async def test_plan_retries_on_validation_failure_then_succeeds_on_third_attempt(session):
    router = _mock_router()
    invalid_plan = {
        "directives": [{**_valid_directive_dict(1), "engine": "BogusEngine"}],
        "rationale": "r",
    }
    valid_plan = {"directives": [_valid_directive_dict(1)], "rationale": "r"}
    router.claude.messages.create = AsyncMock(
        side_effect=[
            _tool_use_response(invalid_plan),
            _tool_use_response(invalid_plan),
            _tool_use_response(valid_plan),
        ]
    )
    omx = OmX(router)

    plan = await omx.plan("$recon acme.com", session)

    assert isinstance(plan, EngagementPlan)
    assert router.claude.messages.create.await_count == 3


@pytest.mark.asyncio
async def test_three_failed_attempts_raises(session):
    router = _mock_router()
    invalid_plan = {
        "directives": [{**_valid_directive_dict(1), "engine": "BogusEngine"}],
        "rationale": "r",
    }
    router.claude.messages.create = AsyncMock(
        side_effect=[_tool_use_response(invalid_plan) for _ in range(3)]
    )
    omx = OmX(router)

    with pytest.raises(OmXPlanValidationError):
        await omx.plan("$recon acme.com", session)

    assert router.claude.messages.create.await_count == 3


@pytest.mark.asyncio
async def test_max_tokens_stop_reason_triggers_retry_not_parsed_as_complete(session):
    router = _mock_router()
    valid_plan = {"directives": [_valid_directive_dict(1)], "rationale": "r"}
    truncated_response = _tool_use_response({"directives": []}, stop_reason="max_tokens")
    router.claude.messages.create = AsyncMock(
        side_effect=[truncated_response, _tool_use_response(valid_plan)]
    )
    omx = OmX(router)

    plan = await omx.plan("$recon acme.com", session)

    assert isinstance(plan, EngagementPlan)
    assert router.claude.messages.create.await_count == 2


def test_omx_module_does_not_reference_ollama_or_complete_fallback():
    import inspect
    from backend.agent import omx as omx_module

    source = inspect.getsource(omx_module)
    assert "_ollama" not in source
    assert "mode=\"orchestration\"" not in source
    assert ".complete(" not in source
