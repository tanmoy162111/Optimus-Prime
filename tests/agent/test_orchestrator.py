import pytest
from unittest.mock import AsyncMock, patch

from backend.session.engagement_session import EngagementSession
from backend.agent.llm_router import LLMResponse
from backend.agent.orchestrator import Orchestrator


@pytest.mark.asyncio
async def test_process_stores_user_message_in_history():
    session = EngagementSession.create()
    orchestrator = Orchestrator()

    mock_llm_response = LLMResponse(
        content="Running recon on example.com",
        model_used="mock",
        input_tokens=10,
        output_tokens=8,
    )

    with patch.object(orchestrator.llm_router, "complete", new=AsyncMock(return_value=mock_llm_response)):
        await orchestrator.process(message="Recon example.com", session=session)

    assert len(session.conv_history.messages) == 2
    assert session.conv_history.messages[0]["role"] == "user"
    assert session.conv_history.messages[0]["content"] == "Recon example.com"
    assert session.conv_history.messages[1]["role"] == "assistant"
    assert session.conv_history.messages[1]["content"] == "Running recon on example.com"


@pytest.mark.asyncio
async def test_process_sends_history_as_messages():
    session = EngagementSession.create()
    session.conv_history.add_message("user", "first message")
    session.conv_history.add_message("assistant", "first reply")

    orchestrator = Orchestrator()
    mock_llm_response = LLMResponse(content="second reply", model_used="mock", input_tokens=5, output_tokens=3)

    captured_messages = {}

    async def capture(messages, mode, system=""):
        captured_messages["messages"] = messages
        return mock_llm_response

    with patch.object(orchestrator.llm_router, "complete", new=capture):
        await orchestrator.process(message="second message", session=session)

    msgs = captured_messages["messages"]
    assert msgs[0] == {"role": "user", "content": "first message"}
    assert msgs[1] == {"role": "assistant", "content": "first reply"}
    assert msgs[2] == {"role": "user", "content": "second message"}


@pytest.mark.asyncio
async def test_process_returns_reply_and_session_id():
    session = EngagementSession.create()
    orchestrator = Orchestrator()
    mock_response = LLMResponse(content="ok", model_used="mock", input_tokens=1, output_tokens=1)

    with patch.object(orchestrator.llm_router, "complete", new=AsyncMock(return_value=mock_response)):
        result = await orchestrator.process(message="hello", session=session)

    assert result["reply"] == "ok"
    assert result["session_id"] == session.session_id
