import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from backend.agent.llm_router import LLMRouter, LLMResponse
from backend import config


@pytest.mark.asyncio
async def test_complete_passes_messages_to_claude():
    router = LLMRouter()
    messages = [{"role": "user", "content": "hello"}]

    mock_response = MagicMock()
    mock_response.content = [MagicMock(text="hi")]
    mock_response.usage = MagicMock(input_tokens=5, output_tokens=2)

    with patch.object(router.claude.messages, "create", new=AsyncMock(return_value=mock_response)) as mock_create:
        result = await router.complete(messages=messages, mode="orchestration")

    mock_create.assert_called_once()
    call_kwargs = mock_create.call_args.kwargs
    assert call_kwargs["messages"] == messages
    assert isinstance(result, LLMResponse)
    assert result.content == "hi"


@pytest.mark.asyncio
async def test_complete_includes_system_prompt_when_provided():
    router = LLMRouter()
    messages = [{"role": "user", "content": "go"}]
    system = "You are Optimus."

    mock_response = MagicMock()
    mock_response.content = [MagicMock(text="done")]
    mock_response.usage = MagicMock(input_tokens=10, output_tokens=3)

    with patch.object(router.claude.messages, "create", new=AsyncMock(return_value=mock_response)) as mock_create:
        await router.complete(messages=messages, mode="orchestration", system=system)

    call_kwargs = mock_create.call_args.kwargs
    assert call_kwargs["system"] == system


def test_claude_model_is_sonnet_4_6():
    """Regression: claude_model must be 'claude-sonnet-4-6' or Claude API 404s and silently falls back to Ollama."""
    assert config.settings.claude_model == "claude-sonnet-4-6"


@pytest.mark.asyncio
async def test_complete_passes_claude_sonnet_4_6_model_to_sdk():
    """Verify the configured claude_model flows through to the Anthropic SDK call kwargs."""
    router = LLMRouter()
    messages = [{"role": "user", "content": "ping"}]

    mock_response = MagicMock()
    mock_response.content = [MagicMock(text="pong")]
    mock_response.usage = MagicMock(input_tokens=1, output_tokens=1)

    with patch.object(router.claude.messages, "create", new=AsyncMock(return_value=mock_response)) as mock_create:
        await router.complete(messages=messages, mode="orchestration")

    call_kwargs = mock_create.call_args.kwargs
    assert call_kwargs["model"] == "claude-sonnet-4-6"
