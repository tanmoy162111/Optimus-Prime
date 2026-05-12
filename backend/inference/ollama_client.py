import aiohttp
import logging
from typing import List, Dict, Any, Optional

logger = logging.getLogger(__name__)


class OllamaClient:
    def __init__(self, host: str = "http://ollama:11434"):
        self.host = host

    async def generate(
        self,
        model: str,
        prompt: str,
        options: Optional[Dict[str, Any]] = None,
    ) -> str:
        url = f"{self.host}/api/generate"
        
        payload = {
            "model": model,
            "prompt": prompt,
            "stream": False,
        }
        if options:
            payload.update(options)
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(url, json=payload) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        return data.get("response", "")
                    else:
                        logger.error(f"Ollama generate failed: {resp.status}")
                        return ""
        except Exception as e:
            logger.error(f"Ollama error: {e}")
            return ""

    async def embed(self, model: str, text: str) -> List[float]:
        url = f"{self.host}/api/embeddings"
        
        payload = {"model": model, "prompt": text}
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(url, json=payload) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        return data.get("embedding", [])
                    else:
                        logger.error(f"Ollama embed failed: {resp.status}")
                        return []
        except Exception as e:
            logger.error(f"Ollama embed error: {e}")
            return []

    async def chat(
        self,
        model: str,
        messages: List[Dict[str, str]],
    ) -> str:
        url = f"{self.host}/api/chat"
        
        payload = {"model": model, "messages": messages, "stream": False}
        
        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(url, json=payload) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        return data.get("message", {}).get("content", "")
                    else:
                        logger.error(f"Ollama chat failed: {resp.status}")
                        return ""
        except Exception as e:
            logger.error(f"Ollama chat error: {e}")
            return ""