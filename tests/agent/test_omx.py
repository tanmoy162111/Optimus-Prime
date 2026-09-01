import pytest
from pydantic import ValidationError

from backend.agent.omx import (
    Directive,
    EngagementPlan,
    OmXPlanValidationError,
    _OMX_PLANNING_SYSTEM_PROMPT,
)
from backend.agent.orchestrator import _SYSTEM_PROMPT as _ORCHESTRATOR_SYSTEM_PROMPT


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
