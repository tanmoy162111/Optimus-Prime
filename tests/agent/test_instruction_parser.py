import pytest

from backend.agent.instruction_parser import InstructionParser
from backend.agent.engine_router import EngineRouter
from backend.session.engagement_session import EngagementSession


def test_parse_accepts_engagement_session_and_does_not_raise():
    parser = InstructionParser()
    session = EngagementSession.create()

    result = parser.parse("recon acme.com", session)

    assert set(result.keys()) == {"intent", "target", "constraints", "phase", "confidence", "mode"}


def test_parse_with_explicit_mode_returns_it_unchanged():
    parser = InstructionParser()
    session = EngagementSession.create()

    result = parser.parse("recon acme.com", session, mode="ICSEngine")

    assert result["mode"] == "ICSEngine"


def test_parse_with_mode_none_derives_mode_via_engine_router_dispatch():
    parser = InstructionParser()
    session = EngagementSession.create()

    message = "assess model.onnx for adversarial risk"
    result = parser.parse(message, session, mode=None)

    intent = parser._detect_intent(message)
    target = parser._extract_target(message)
    expected_mode = EngineRouter().dispatch(intent, target)

    assert expected_mode == "MLAIEngine"
    assert result["mode"] == expected_mode


def test_instruction_parser_module_does_not_define_local_engine_router():
    import backend.agent.instruction_parser as m

    assert m.EngineRouter.__module__ == "backend.agent.engine_router"
