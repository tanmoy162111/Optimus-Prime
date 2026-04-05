"""LLM Router — Two-tier model routing with provider abstraction (Section 12).

Primary:      Claude (claude-sonnet-4) for orchestration, reasoning, reports
Cost fallback: Mistral (via Ollama) for compaction, classification, budget-exhausted mode

TokenBudgetManager tracks usage and enforces thresholds:
  60k  -> ConversationSummariser fires (Mistral)
  80%  -> TOKEN_BUDGET_WARNING published to EventBus
  100% -> Mistral-only mode activated
"""

from __future__ import annotations

import json
import logging
import os
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

import httpx

logger = logging.getLogger(__name__)


@dataclass
class LLMMessage:
    """A message in the LLM conversation."""
    role: str  # system, user, assistant
    content: str


@dataclass
class LLMResponse:
    """Response from an LLM provider."""
    content: str
    model: str
    tokens_used: int = 0
    finish_reason: str = ""
    raw: dict[str, Any] = field(default_factory=dict)


class LLMProvider(ABC):
    """Abstract LLM provider interface (Section 12.2).

    Cloud migration can introduce additional providers behind this interface.
    """

    @abstractmethod
    async def complete(
        self,
        messages: list[LLMMessage],
        max_tokens: int = 4096,
        temperature: float = 0.7,
        system_prompt: str | None = None,
    ) -> LLMResponse:
        ...

    @abstractmethod
    def provider_name(self) -> str:
        ...


class ClaudeProvider(LLMProvider):
    """Claude API provider (primary tier)."""

    def __init__(
        self,
        api_key: str | None = None,
        model: str = "claude-sonnet-4-20250514",
        base_url: str = "https://api.anthropic.com",
    ) -> None:
        self._api_key = api_key or os.environ.get("CLAUDE_API_KEY", "")
        self._model = model
        self._base_url = base_url
        self._client = httpx.AsyncClient(timeout=120.0)

    def provider_name(self) -> str:
        return "claude"

    async def complete(
        self,
        messages: list[LLMMessage],
        max_tokens: int = 4096,
        temperature: float = 0.7,
        system_prompt: str | None = None,
    ) -> LLMResponse:
        if not self._api_key:
            raise RuntimeError("Claude API key not configured")

        # Build messages for Claude API
        api_messages = []
        for msg in messages:
            if msg.role != "system":
                api_messages.append({"role": msg.role, "content": msg.content})

        body: dict[str, Any] = {
            "model": self._model,
            "max_tokens": max_tokens,
            "messages": api_messages,
            "temperature": temperature,
        }

        if system_prompt:
            body["system"] = system_prompt
        else:
            # Extract system from messages
            for msg in messages:
                if msg.role == "system":
                    body["system"] = msg.content
                    break

        resp = await self._client.post(
            f"{self._base_url}/v1/messages",
            json=body,
            headers={
                "x-api-key": self._api_key,
                "anthropic-version": "2023-06-01",
                "content-type": "application/json",
            },
        )
        resp.raise_for_status()
        data = resp.json()

        content = ""
        for block in data.get("content", []):
            if block.get("type") == "text":
                content += block.get("text", "")

        tokens = data.get("usage", {})
        total_tokens = tokens.get("input_tokens", 0) + tokens.get("output_tokens", 0)

        return LLMResponse(
            content=content,
            model=self._model,
            tokens_used=total_tokens,
            finish_reason=data.get("stop_reason", ""),
            raw=data,
        )


class MistralOllamaProvider(LLMProvider):
    """Mistral via Ollama — cost fallback tier."""

    def __init__(
        self,
        base_url: str | None = None,
        model: str = "mistral:7b",
    ) -> None:
        self._base_url = base_url or os.environ.get("OLLAMA_HOST", "http://ollama:11434")
        self._model = model
        self._client = httpx.AsyncClient(timeout=120.0)

    def provider_name(self) -> str:
        return "mistral"

    async def complete(
        self,
        messages: list[LLMMessage],
        max_tokens: int = 4096,
        temperature: float = 0.7,
        system_prompt: str | None = None,
    ) -> LLMResponse:
        api_messages = []
        if system_prompt:
            api_messages.append({"role": "system", "content": system_prompt})
        for msg in messages:
            api_messages.append({"role": msg.role, "content": msg.content})

        body = {
            "model": self._model,
            "messages": api_messages,
            "stream": False,
            "options": {
                "num_predict": max_tokens,
                "temperature": temperature,
            },
        }

        resp = await self._client.post(
            f"{self._base_url}/api/chat",
            json=body,
        )
        resp.raise_for_status()
        data = resp.json()

        content = data.get("message", {}).get("content", "")
        total_tokens = data.get("eval_count", 0) + data.get("prompt_eval_count", 0)

        return LLMResponse(
            content=content,
            model=self._model,
            tokens_used=total_tokens,
            finish_reason=data.get("done_reason", ""),
            raw=data,
        )


class TokenBudgetManager:
    """Tracks token usage and enforces budget thresholds (Section 12.3)."""

    def __init__(
        self,
        budget: int = 200_000,
        warning_pct: int = 80,
        event_bus: Any = None,
    ) -> None:
        self._budget = budget
        self._warning_pct = warning_pct
        self._used = 0
        self._event_bus = event_bus
        self._warning_sent = False
        self._mistral_only = False

    @property
    def used(self) -> int:
        return self._used

    @property
    def remaining(self) -> int:
        return max(0, self._budget - self._used)

    @property
    def is_mistral_only(self) -> bool:
        return self._mistral_only

    async def record_usage(self, tokens: int) -> None:
        """Record token usage and check thresholds."""
        self._used += tokens
        pct = (self._used / self._budget) * 100 if self._budget > 0 else 100

        # 80% warning
        if pct >= self._warning_pct and not self._warning_sent:
            self._warning_sent = True
            if self._event_bus:
                await self._event_bus.publish(
                    channel="system",
                    event_type="TOKEN_BUDGET_WARNING",
                    payload={"used": self._used, "budget": self._budget, "pct": pct},
                )
            logger.warning("TokenBudget: %.0f%% used (%d/%d)", pct, self._used, self._budget)

        # 100% — Mistral-only mode
        if pct >= 100:
            self._mistral_only = True
            logger.warning("TokenBudget: exhausted — switching to Mistral-only mode")

    def reset(self) -> None:
        """Reset the budget (new session or manual reset)."""
        self._used = 0
        self._warning_sent = False
        self._mistral_only = False


class LLMRouter:
    """Routes LLM calls between Claude (primary) and Mistral (fallback).

    Routing logic:
      1. If budget exhausted -> Mistral only
      2. If explicitly requesting compaction -> Mistral
      3. Try Claude -> on failure, fallback to Mistral
      4. Record token usage after each call
    """

    def __init__(
        self,
        claude: ClaudeProvider | None = None,
        mistral: MistralOllamaProvider | None = None,
        budget_manager: TokenBudgetManager | None = None,
    ) -> None:
        self._claude = claude or ClaudeProvider()
        self._mistral = mistral or MistralOllamaProvider()
        self._budget = budget_manager or TokenBudgetManager()

    @property
    def budget_manager(self) -> TokenBudgetManager:
        return self._budget

    async def complete(
        self,
        messages: list[LLMMessage],
        max_tokens: int = 4096,
        temperature: float = 0.7,
        system_prompt: str | None = None,
        prefer_mistral: bool = False,
    ) -> LLMResponse:
        """Route an LLM completion request.

        Args:
            messages: Conversation messages.
            max_tokens: Max tokens for response.
            temperature: Sampling temperature.
            system_prompt: Optional system prompt.
            prefer_mistral: Force Mistral (e.g., for compaction).
        """
        # Mistral-only mode or explicit preference
        if self._budget.is_mistral_only or prefer_mistral:
            return await self._call_mistral(messages, max_tokens, temperature, system_prompt)

        # Try Claude primary
        try:
            response = await self._claude.complete(
                messages, max_tokens, temperature, system_prompt,
            )
            await self._budget.record_usage(response.tokens_used)
            return response
        except Exception as exc:
            logger.warning("LLMRouter: Claude failed, falling back to Mistral: %s", exc)

        # Fallback to Mistral
        return await self._call_mistral(messages, max_tokens, temperature, system_prompt)

    async def _call_mistral(
        self,
        messages: list[LLMMessage],
        max_tokens: int,
        temperature: float,
        system_prompt: str | None,
    ) -> LLMResponse:
        """Call Mistral and record usage."""
        response = await self._mistral.complete(
            messages, max_tokens, temperature, system_prompt,
        )
        await self._budget.record_usage(response.tokens_used)
        return response
