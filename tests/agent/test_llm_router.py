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


@pytest.mark.asyncio
async def test_compaction_mode_routes_to_ollama():
    """mode='compaction' must call Ollama with qwen_model and never touch Claude (D-04)."""
    router = LLMRouter()
    messages = [{"role": "user", "content": "summarize this conversation"}]

    with patch.object(router.claude.messages, "create", new=AsyncMock()) as mock_claude_create, \
         patch.object(router.ollama, "generate", new=AsyncMock(return_value="summary text")) as mock_generate:
        result = await router.complete(messages=messages, mode="compaction")

    mock_claude_create.assert_not_called()
    mock_generate.assert_called_once()
    call_kwargs = mock_generate.call_args.kwargs
    assert call_kwargs["model"] == config.settings.qwen_model
    assert isinstance(result, LLMResponse)
    assert result.content == "summary text"
    assert result.model_used == config.settings.qwen_model


@pytest.mark.asyncio
async def test_orchestration_mode_still_claude():
    """Regression guard: mode='orchestration' must still resolve to Claude, never removed (D-00)."""
    router = LLMRouter()
    messages = [{"role": "user", "content": "plan the engagement"}]

    mock_response = MagicMock()
    mock_response.content = [MagicMock(text="planned")]
    mock_response.usage = MagicMock(input_tokens=4, output_tokens=2)

    with patch.object(router.claude.messages, "create", new=AsyncMock(return_value=mock_response)) as mock_create, \
         patch.object(router.ollama, "generate", new=AsyncMock()) as mock_generate:
        result = await router.complete(messages=messages, mode="orchestration")

    mock_create.assert_called_once()
    mock_generate.assert_not_called()
    assert result.content == "planned"


@pytest.mark.asyncio
async def test_unknown_mode_still_routes_to_ollama_mistral():
    """Unchanged behavior: an unrecognized mode falls through to the existing Ollama/mistral path."""
    router = LLMRouter()
    messages = [{"role": "user", "content": "misc task"}]

    with patch.object(router.ollama, "generate", new=AsyncMock(return_value="misc result")) as mock_generate:
        result = await router.complete(messages=messages, mode="some_unknown_mode")

    mock_generate.assert_called_once()
    call_kwargs = mock_generate.call_args.kwargs
    assert call_kwargs["model"] == config.settings.mistral_model
    assert result.content == "misc result"


def test_only_one_ollama_client_constructed():
    """Regression: _compaction_complete must reuse self.ollama, not construct a second OllamaClient."""
    import inspect

    from backend.agent import llm_router as llm_router_module

    source = inspect.getsource(llm_router_module)
    assert source.count("OllamaClient(") == 1
