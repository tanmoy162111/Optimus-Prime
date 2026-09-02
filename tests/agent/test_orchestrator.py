import inspect
import logging

import pytest
from unittest.mock import AsyncMock, patch

from backend.agent.clawhip import ClawhipEventType
from backend.agent.llm_router import LLMResponse
from backend.agent.omx import Directive, EngagementPlan, OmXPlanValidationError
from backend.agent.orchestrator import Orchestrator
from backend.session.engagement_session import EngagementSession
from backend.session.session_store import session_store


def _make_plan(num_directives: int = 1) -> EngagementPlan:
    directives = [
        Directive(
            id=f"d{i}",
            phase="recon",
            engine="InfrastructureEngine",
            agent="ReconAgent",
            target="example.com",
        )
        for i in range(1, num_directives + 1)
    ]
    return EngagementPlan(directives=directives, rationale="test plan")


def _compaction_response(content: str = "compacted summary") -> LLMResponse:
    return LLMResponse(
        content=content, model_used="qwen2.5:7b", input_tokens=5, output_tokens=3
    )


# ---------------------------------------------------------------------------
# Task 1: construction — agent registry + OmX + OmO + Clawhip in __init__
# ---------------------------------------------------------------------------


def test_orchestrator_constructs_with_all_pipeline_collaborators():
    orchestrator = Orchestrator()

    assert orchestrator.omx is not None
    assert orchestrator.omo is not None
    assert orchestrator.clawhip is not None
    assert orchestrator._agents is not None


def test_agent_registry_has_all_11_agents():
    orchestrator = Orchestrator()

    expected = {
        "CloudAgent", "DataSecAgent", "EndpointAgent", "ExploitAgent",
        "GenAIAgent", "IAMAgent", "ICSAgent", "IntelAgent", "ModelSecAgent",
        "ReconAgent", "ScanAgent",
    }
    assert set(orchestrator._agents.keys()) == expected
    assert len(orchestrator._agents) == 11


def test_omo_task_registry_is_the_shared_session_store_instance():
    orchestrator = Orchestrator()

    assert orchestrator.omo.task_registry is session_store.task_registry


def test_orchestrator_does_not_construct_its_own_task_registry():
    import backend.agent.orchestrator as orchestrator_module

    source = inspect.getsource(orchestrator_module)
    # Only the import line ("from backend.agent.task_registry import ...")
    # would reference TaskRegistry — orchestrator.py never imports it and
    # never calls "TaskRegistry(" to construct one directly.
    assert "TaskRegistry(" not in source


def test_clawhip_constructed_with_manager_and_explainable_ai():
    from backend.api.ws_handler import manager
    from backend.reporting.explainable_ai import ExplainableAI

    orchestrator = Orchestrator()

    assert orchestrator.clawhip._manager is manager
    assert isinstance(orchestrator.clawhip._xai, ExplainableAI)


# ---------------------------------------------------------------------------
# Task 2: process_stream() / process() — OmX -> OmO -> ResponseComposer pipeline
# ---------------------------------------------------------------------------


@pytest.mark.asyncio
async def test_process_stream_runs_omx_plan_then_omo_dispatch_then_composes_reply():
    session = EngagementSession.create()
    orchestrator = Orchestrator()
    plan = _make_plan()

    with patch.object(orchestrator.omx, "plan", new=AsyncMock(return_value=plan)) as mock_plan, \
         patch.object(orchestrator.omo, "dispatch", new=AsyncMock()) as mock_dispatch, \
         patch.object(orchestrator.llm_router, "complete", new=AsyncMock(return_value=_compaction_response())):
        chunks = [chunk async for chunk in orchestrator.process_stream(message="run recon on example.com", session=session)]

    mock_plan.assert_awaited_once()
    mock_dispatch.assert_awaited_once()
    assert all(isinstance(c, str) for c in chunks)
    assert session.conv_history.messages[0]["role"] == "user"
    assert session.conv_history.messages[0]["content"] == "run recon on example.com"


@pytest.mark.asyncio
async def test_process_stream_plan_rejection_emits_plan_rejected_and_skips_dispatch():
    session = EngagementSession.create()
    orchestrator = Orchestrator()

    with patch.object(orchestrator.omx, "plan", new=AsyncMock(side_effect=OmXPlanValidationError("bad plan"))), \
         patch.object(orchestrator.omo, "dispatch", new=AsyncMock()) as mock_dispatch, \
         patch.object(orchestrator.clawhip, "emit", new=AsyncMock()) as mock_emit:
        chunks = [chunk async for chunk in orchestrator.process_stream(message="run recon", session=session)]

    mock_dispatch.assert_not_awaited()
    mock_emit.assert_awaited_once()
    session_id_arg, event_arg = mock_emit.await_args.args
    assert session_id_arg == session.session_id
    assert event_arg.event_type == ClawhipEventType.PLAN_REJECTED
    assert "".join(chunks).strip() != ""


@pytest.mark.asyncio
async def test_process_stream_preserves_word_by_word_streaming_contract():
    session = EngagementSession.create()
    orchestrator = Orchestrator()
    plan = _make_plan()

    with patch.object(orchestrator.omx, "plan", new=AsyncMock(return_value=plan)), \
         patch.object(orchestrator.omo, "dispatch", new=AsyncMock()), \
         patch.object(orchestrator.composer, "compose_plan_summary", return_value="hello world"), \
         patch.object(orchestrator.llm_router, "complete", new=AsyncMock(return_value=_compaction_response())):
        chunks = [chunk async for chunk in orchestrator.process_stream(message="run recon", session=session)]

    assert chunks == ["hello ", "world "]


@pytest.mark.asyncio
async def test_process_stream_does_not_call_parser_engine_router_or_tool_selector():
    session = EngagementSession.create()
    orchestrator = Orchestrator()
    plan = _make_plan()

    with patch.object(orchestrator.omx, "plan", new=AsyncMock(return_value=plan)), \
         patch.object(orchestrator.omo, "dispatch", new=AsyncMock()), \
         patch.object(orchestrator.llm_router, "complete", new=AsyncMock(return_value=_compaction_response())), \
         patch.object(orchestrator.parser, "parse") as mock_parse, \
         patch.object(orchestrator.engine_router, "dispatch") as mock_engine_dispatch, \
         patch.object(orchestrator.tool_selector, "select") as mock_tool_select:
        async for _ in orchestrator.process_stream(message="run recon", session=session):
            pass

    mock_parse.assert_not_called()
    mock_engine_dispatch.assert_not_called()
    mock_tool_select.assert_not_called()


@pytest.mark.asyncio
async def test_process_stream_logs_omx_plan_and_omo_dispatch_as_distinct_lines(caplog):
    session = EngagementSession.create()
    orchestrator = Orchestrator()
    plan = _make_plan()

    with caplog.at_level(logging.INFO, logger="backend.agent.orchestrator"):
        with patch.object(orchestrator.omx, "plan", new=AsyncMock(return_value=plan)), \
             patch.object(orchestrator.omo, "dispatch", new=AsyncMock()), \
             patch.object(orchestrator.llm_router, "complete", new=AsyncMock(return_value=_compaction_response())):
            async for _ in orchestrator.process_stream(message="run recon", session=session):
                pass

    messages = [r.message % r.args if r.args else r.message for r in caplog.records]
    assert any("OmX generated" in m for m in messages)
    assert any("OmO dispatch" in m for m in messages)


@pytest.mark.asyncio
async def test_compaction_called_exactly_once_before_assistant_reply_and_not_conditional():
    session = EngagementSession.create()
    orchestrator = Orchestrator()
    plan = _make_plan()

    call_order = []

    async def fake_dispatch(*args, **kwargs):
        call_order.append("dispatch")

    async def fake_complete(*args, **kwargs):
        call_order.append("compaction")
        assert kwargs.get("mode") == "compaction"
        return _compaction_response()

    with patch.object(orchestrator.omx, "plan", new=AsyncMock(return_value=plan)), \
         patch.object(orchestrator.omo, "dispatch", new=fake_dispatch), \
         patch.object(orchestrator.llm_router, "complete", new=fake_complete) as mock_complete:
        async for _ in orchestrator.process_stream(message="run recon", session=session):
            pass

    assert call_order == ["dispatch", "compaction"]


@pytest.mark.asyncio
async def test_compacted_summary_added_to_conv_history_not_raw_findings():
    session = EngagementSession.create()
    session.state.add_finding({"severity": "HIGH", "title": "example finding"})
    orchestrator = Orchestrator()
    plan = _make_plan()

    with patch.object(orchestrator.omx, "plan", new=AsyncMock(return_value=plan)), \
         patch.object(orchestrator.omo, "dispatch", new=AsyncMock()), \
         patch.object(orchestrator.composer, "compose_plan_summary", return_value="REPLY_TEXT"), \
         patch.object(orchestrator.llm_router, "complete", new=AsyncMock(return_value=_compaction_response())) as mock_complete:
        async for _ in orchestrator.process_stream(message="run recon", session=session):
            pass

    mock_complete.assert_awaited_once()
    _, kwargs = mock_complete.await_args
    assert kwargs["mode"] == "compaction"

    contents = [m["content"] for m in session.conv_history.messages]
    assert "compacted summary" in contents
    assert "REPLY_TEXT" in contents
    # Raw finding dicts must never be dumped wholesale into conv_history.
    assert str(session.state.findings) not in contents


@pytest.mark.asyncio
async def test_compaction_resolved_provider_is_logged(caplog):
    session = EngagementSession.create()
    orchestrator = Orchestrator()
    plan = _make_plan()

    with caplog.at_level(logging.INFO, logger="backend.agent.orchestrator"):
        with patch.object(orchestrator.omx, "plan", new=AsyncMock(return_value=plan)), \
             patch.object(orchestrator.omo, "dispatch", new=AsyncMock()), \
             patch.object(orchestrator.llm_router, "complete", new=AsyncMock(return_value=_compaction_response())):
            async for _ in orchestrator.process_stream(message="run recon", session=session):
                pass

    messages = [r.message % r.args if r.args else r.message for r in caplog.records]
    assert any("compaction handled by" in m for m in messages)


@pytest.mark.asyncio
async def test_process_runs_same_pipeline_and_returns_dict_reply():
    session = EngagementSession.create()
    orchestrator = Orchestrator()
    plan = _make_plan()

    with patch.object(orchestrator.omx, "plan", new=AsyncMock(return_value=plan)) as mock_plan, \
         patch.object(orchestrator.omo, "dispatch", new=AsyncMock()) as mock_dispatch, \
         patch.object(orchestrator.composer, "compose_plan_summary", return_value="REPLY"), \
         patch.object(orchestrator.llm_router, "complete", new=AsyncMock(return_value=_compaction_response())):
        result = await orchestrator.process(message="run recon", session=session)

    mock_plan.assert_awaited_once()
    mock_dispatch.assert_awaited_once()
    assert result["reply"] == "REPLY"
    assert result["session_id"] == session.session_id


@pytest.mark.asyncio
async def test_process_plan_rejection_returns_dict_without_dispatch():
    session = EngagementSession.create()
    orchestrator = Orchestrator()

    with patch.object(orchestrator.omx, "plan", new=AsyncMock(side_effect=OmXPlanValidationError("bad plan"))), \
         patch.object(orchestrator.omo, "dispatch", new=AsyncMock()) as mock_dispatch, \
         patch.object(orchestrator.clawhip, "emit", new=AsyncMock()):
        result = await orchestrator.process(message="run recon", session=session)

    mock_dispatch.assert_not_awaited()
    assert "Plan rejected" in result["reply"]
    assert result["session_id"] == session.session_id
