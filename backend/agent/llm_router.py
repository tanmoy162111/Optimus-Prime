import logging
from dataclasses import dataclass
from typing import Dict, List

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

    async def embed(self, text: str) -> list:
        return await self.ollama.embed(
            model=config.settings.embed_model,
            text=text,
        )
