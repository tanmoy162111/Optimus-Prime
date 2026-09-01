import pytest
from unittest.mock import AsyncMock, MagicMock

from backend.agent.clawhip import Clawhip, ClawhipEvent, ClawhipEventType


def _make_clawhip():
    manager = MagicMock()
    manager.send = AsyncMock()
    xai = MagicMock()
    xai.log_decision = MagicMock()
    return Clawhip(connection_manager=manager, xai_logger=xai), manager, xai


@pytest.mark.asyncio
async def test_emit_phase_failed_sends_and_logs():
    clawhip, manager, xai = _make_clawhip()
    event = ClawhipEvent(
        event_type=ClawhipEventType.PHASE_FAILED,
        directive_id="d1",
        detail="boom",
        error="X",
    )

    await clawhip.emit("session-1", event)

    manager.send.assert_awaited_once()
    args, _ = manager.send.await_args
    assert args[0] == "session-1"
    payload = args[1]
    assert payload["event_type"] == "PHASE_FAILED"

    xai.log_decision.assert_called_once()
    _, kwargs = xai.log_decision.call_args
    assert kwargs["decision_type"] == "PHASE_FAILED"
    assert kwargs["factors"] == ["d1"]


@pytest.mark.asyncio
async def test_emit_plan_rejected_logs_to_xai():
    clawhip, manager, xai = _make_clawhip()
    event = ClawhipEvent(event_type=ClawhipEventType.PLAN_REJECTED, directive_id="d2", detail="rejected")

    await clawhip.emit("session-1", event)

    manager.send.assert_awaited_once()
    xai.log_decision.assert_called_once()


@pytest.mark.asyncio
async def test_emit_gate_pending_logs_to_xai():
    clawhip, manager, xai = _make_clawhip()
    event = ClawhipEvent(event_type=ClawhipEventType.GATE_PENDING, directive_id="d3", detail="awaiting approval")

    await clawhip.emit("session-1", event)

    manager.send.assert_awaited_once()
    xai.log_decision.assert_called_once()
    _, kwargs = xai.log_decision.call_args
    assert kwargs["decision_type"] == "GATE_PENDING"
    assert kwargs["factors"] == ["d3"]


@pytest.mark.asyncio
async def test_emit_phase_started_does_not_log_to_xai():
    clawhip, manager, xai = _make_clawhip()
    event = ClawhipEvent(event_type=ClawhipEventType.PHASE_STARTED, directive_id="d4", detail="starting")

    await clawhip.emit("session-1", event)

    manager.send.assert_awaited_once()
    xai.log_decision.assert_not_called()


@pytest.mark.asyncio
async def test_emit_phase_completed_does_not_log_to_xai():
    clawhip, manager, xai = _make_clawhip()
    event = ClawhipEvent(event_type=ClawhipEventType.PHASE_COMPLETED, directive_id="d5", detail="done")

    await clawhip.emit("session-1", event)

    manager.send.assert_awaited_once()
    xai.log_decision.assert_not_called()


@pytest.mark.asyncio
async def test_emit_payload_is_plain_dict_not_pydantic_model():
    clawhip, manager, xai = _make_clawhip()
    event = ClawhipEvent(event_type=ClawhipEventType.PHASE_STARTED, directive_id="d6", detail="starting")

    await clawhip.emit("session-1", event)

    args, _ = manager.send.await_args
    payload = args[1]
    assert isinstance(payload, dict)
    assert not isinstance(payload, ClawhipEvent)


def test_clawhip_event_type_has_gate_pending_member():
    assert ClawhipEventType.GATE_PENDING == "GATE_PENDING"


def test_no_collab_websocket_reference_in_clawhip_module():
    import inspect
    import backend.agent.clawhip as clawhip_module

    source = inspect.getsource(clawhip_module)
    assert "Collab" not in source


@pytest.mark.asyncio
async def test_research_daemon_stub_is_callable_and_inert():
    from backend.intelligence.research_daemon import ResearchDaemon
    from backend.intelligence.research_kb import ResearchKB

    daemon = ResearchDaemon(research_kb=MagicMock(spec=ResearchKB))

    # Should not raise, and should not return anything meaningful (no delivery side effect)
    result = await daemon.deliver_to_clawhip({"event_type": "PHASE_FAILED", "detail": "test"})
    assert result is None


def test_research_daemon_stub_has_no_thread_or_task_creation():
    import inspect
    from backend.intelligence import research_daemon as research_daemon_module

    source = inspect.getsource(research_daemon_module.ResearchDaemon.deliver_to_clawhip)
    assert "Thread(" not in source
    assert "create_task(" not in source
