import logging
from dataclasses import dataclass
from typing import Dict, List

import httpx

from backend import config
from backend.inference.ollama_client import OllamaClient

logger = logging.getLogger(__name__)


@dataclass
class LLMResponse:
    content: str
    model_used: str
    input_tokens: int
    output_tokens: int


class LLMRouter:
    def __init__(self):
        import anthropic
        self.claude = anthropic.AsyncAnthropic(api_key=config.settings.anthropic_api_key)
        self.ollama = OllamaClient(config.settings.ollama_host)

    async def complete(
        self,
        messages: List[Dict[str, str]],
        mode: str = "orchestration",
        system: str = "",
    ) -> LLMResponse:
        if mode == "orchestration":
            return await self._claude_complete(messages, system)
        elif mode == "compaction":
            return await self._compaction_complete(messages)
        elif mode == "deepseek":
            return await self._deepseek_complete(messages)
        return await self._ollama_complete(messages)

    async def _claude_complete(
        self, messages: List[Dict[str, str]], system: str
    ) -> LLMResponse:
        try:
            kwargs = dict(
                model=config.settings.claude_model,
                max_tokens=4096,
                messages=messages,
            )
            if system:
                kwargs["system"] = system
            response = await self.claude.messages.create(**kwargs)
            return LLMResponse(
                content=response.content[0].text,
                model_used=config.settings.claude_model,
                input_tokens=response.usage.input_tokens,
                output_tokens=response.usage.output_tokens,
            )
        except Exception as e:
            logger.error(f"Claude error: {e}, falling back to Ollama")
            return await self._ollama_complete(messages)

    async def _ollama_complete(self, messages: List[Dict[str, str]]) -> LLMResponse:
        prompt = "\n".join(f"{m['role'].upper()}: {m['content']}" for m in messages)
        content = await self.ollama.generate(
            model=config.settings.mistral_model,
            prompt=prompt,
        )
        return LLMResponse(
            content=content,
            model_used=config.settings.mistral_model,
            input_tokens=len(prompt.split()),
            output_tokens=len(content.split()),
        )

    async def _compaction_complete(self, messages: List[Dict[str, str]]) -> LLMResponse:
        prompt = "\n".join(f"{m['role'].upper()}: {m['content']}" for m in messages)
        content = await self.ollama.generate(
            model=config.settings.qwen_model,
            prompt=prompt,
        )
        return LLMResponse(
            content=content,
            model_used=config.settings.qwen_model,
            input_tokens=len(prompt.split()),
            output_tokens=len(content.split()),
        )

    async def _deepseek_complete(self, messages: List[Dict[str, str]]) -> LLMResponse:
        if not config.settings.deepseek_api_key:
            logger.warning(
                "DeepSeek API key not configured; degrading to Ollama (D-04: absence never breaks orchestration)"
            )
            return await self._ollama_complete(messages)
        try:
            headers = {
                "Authorization": f"Bearer {config.settings.deepseek_api_key}",
                "Content-Type": "application/json",
            }
            payload = {
                "model": config.settings.deepseek_model,
                "messages": messages,
            }
            url = f"{config.settings.deepseek_base_url}/chat/completions"
            async with httpx.AsyncClient(timeout=30.0) as client:
                response = await client.post(url, json=payload, headers=headers)
                response.raise_for_status()
                data = response.json()
            content = data["choices"][0]["message"]["content"]
            usage = data.get("usage", {})
            return LLMResponse(
                content=content,
                model_used=config.settings.deepseek_model,
                input_tokens=usage.get("prompt_tokens", 0),
                output_tokens=usage.get("completion_tokens", 0),
            )
        except Exception as e:
            logger.error(f"DeepSeek error: {e}, falling back to Ollama")
            return await self._ollama_complete(messages)

    async def embed(self, text: str) -> list:
        return await self.ollama.embed(
            model=config.settings.embed_model,
            text=text,
        )
