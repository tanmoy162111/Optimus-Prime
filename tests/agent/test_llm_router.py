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


@pytest.mark.asyncio
async def test_deepseek_mode_without_api_key_makes_no_http_call(monkeypatch):
    """With deepseek_api_key=='' (default), mode='deepseek' must not attempt a DeepSeek HTTP
    call and must degrade gracefully — absence never breaks orchestration/compaction (D-04)."""
    monkeypatch.setattr(config.settings, "deepseek_api_key", "")
    router = LLMRouter()
    messages = [{"role": "user", "content": "no key configured"}]

    with patch("backend.agent.llm_router.httpx.AsyncClient") as mock_async_client, \
         patch.object(router.ollama, "generate", new=AsyncMock(return_value="degraded response")) as mock_generate:
        result = await router.complete(messages=messages, mode="deepseek")

    mock_async_client.assert_not_called()
    mock_generate.assert_called_once()
    assert isinstance(result, LLMResponse)
    assert result.content == "degraded response"


@pytest.mark.asyncio
async def test_deepseek_mode_with_api_key_calls_configured_endpoint(monkeypatch):
    """With a configured deepseek_api_key, mode='deepseek' must POST to deepseek_base_url
    using deepseek_model."""
    monkeypatch.setattr(config.settings, "deepseek_api_key", "test-key-123")
    router = LLMRouter()
    messages = [{"role": "user", "content": "summarize via deepseek"}]

    mock_http_response = MagicMock()
    mock_http_response.raise_for_status = MagicMock()
    mock_http_response.json = MagicMock(
        return_value={
            "choices": [{"message": {"content": "deepseek reply"}}],
            "usage": {"prompt_tokens": 7, "completion_tokens": 3},
        }
    )

    mock_client_instance = AsyncMock()
    mock_client_instance.post = AsyncMock(return_value=mock_http_response)

    mock_async_client_cls = MagicMock()
    mock_async_client_cls.return_value.__aenter__ = AsyncMock(return_value=mock_client_instance)
    mock_async_client_cls.return_value.__aexit__ = AsyncMock(return_value=False)

    with patch("backend.agent.llm_router.httpx.AsyncClient", mock_async_client_cls):
        result = await router.complete(messages=messages, mode="deepseek")

    mock_client_instance.post.assert_called_once()
    call_args, call_kwargs = mock_client_instance.post.call_args
    assert call_args[0] == f"{config.settings.deepseek_base_url}/chat/completions"
    assert call_kwargs["json"]["model"] == config.settings.deepseek_model
    assert result.content == "deepseek reply"
    assert result.model_used == config.settings.deepseek_model


@pytest.mark.asyncio
async def test_deepseek_branch_does_not_affect_orchestration_or_compaction():
    """orchestration and compaction routing must be unaffected by the new deepseek branch."""
    router = LLMRouter()
    messages = [{"role": "user", "content": "unaffected check"}]

    mock_response = MagicMock()
    mock_response.content = [MagicMock(text="claude reply")]
    mock_response.usage = MagicMock(input_tokens=2, output_tokens=2)

    with patch.object(router.claude.messages, "create", new=AsyncMock(return_value=mock_response)) as mock_create:
        orch_result = await router.complete(messages=messages, mode="orchestration")
    assert orch_result.content == "claude reply"

    with patch.object(router.ollama, "generate", new=AsyncMock(return_value="qwen reply")) as mock_generate:
        compaction_result = await router.complete(messages=messages, mode="compaction")
    assert compaction_result.content == "qwen reply"
    assert compaction_result.model_used == config.settings.qwen_model
