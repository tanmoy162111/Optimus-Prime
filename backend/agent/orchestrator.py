import logging
from dataclasses import dataclass
from typing import Any, AsyncIterator, Dict, List, Optional

from backend.agent.engine_router import EngineRouter
from backend.agent.instruction_parser import InstructionParser
from backend.agent.llm_router import LLMRouter
from backend.agent.response_composer import ResponseComposer
from backend.agent.tool_selector import ToolSelector
from backend.session.engagement_session import EngagementSession

logger = logging.getLogger(__name__)

_SYSTEM_PROMPT = (
    "You are Optimus, a universal AI security platform. "
    "Analyze the user's intent and provide a structured security assessment response. "
    "Be concise and actionable."
)


@dataclass
class OrchestratorDecision:
    intent: str
    engine: str
    target: str
    constraints: dict
    phase: str
    tools: list
    confidence: float


class Orchestrator:
    def __init__(self):
        self.llm_router = LLMRouter()
        self.parser = InstructionParser()
        self.engine_router = EngineRouter()
        self.tool_selector = ToolSelector()
        self.composer = ResponseComposer()

    async def process(
        self,
        message: str,
        session: EngagementSession,
        mode: Optional[str] = None,
    ) -> Dict[str, Any]:
        session.conv_history.add_message("user", message)

        messages = session.conv_history.get_context_window()
        response = await self.llm_router.complete(
            messages=messages,
            mode="orchestration",
            system=_SYSTEM_PROMPT,
        )

        session.conv_history.add_message("assistant", response.content)

        return {
            "reply": response.content,
            "session_id": session.session_id,
            "tokens_used": response.input_tokens + response.output_tokens,
        }

    async def process_stream(
        self,
        message: str,
        session: EngagementSession,
        mode: Optional[str] = None,
    ) -> AsyncIterator[str]:
        session.conv_history.add_message("user", message)

        messages = session.conv_history.get_context_window()
        response = await self.llm_router.complete(
            messages=messages,
            mode="orchestration",
            system=_SYSTEM_PROMPT,
        )

        session.conv_history.add_message("assistant", response.content)

        for word in response.content.split():
            yield word + " "
