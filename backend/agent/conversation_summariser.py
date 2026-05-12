import logging
import tiktoken
from typing import List, Dict, Any

from backend.config import settings

logger = logging.getLogger(__name__)


class ConversationSummariser:
    def __init__(self):
        self.threshold = settings.summariser_threshold

    async def should_summarise(self, messages: List[Dict[str, str]]) -> bool:
        total_tokens = sum(self._estimate_tokens(m["content"]) for m in messages)
        return total_tokens > self.threshold

    async def summarise(self, messages: List[Dict[str, str]]) -> List[Dict[str, str]]:
        if not messages:
            return messages
        
        recent_findings = messages[-10:]
        recent_tools = messages[-5:]
        
        summary_msg = {
            "role": "system",
            "content": f"Summarised {len(messages)} messages. Key context preserved from last 15 exchanges.",
        }
        
        return [summary_msg] + recent_findings + recent_tools

    def _estimate_tokens(self, text: str) -> int:
        try:
            encoder = tiktoken.get_encoding("cl100k_base")
            return len(encoder.encode(text))
        except Exception:
            return len(text.split()) * 2