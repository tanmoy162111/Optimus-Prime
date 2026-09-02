import json
import logging
from dataclasses import dataclass
from typing import Any, AsyncIterator, Dict, List, Optional

from backend.agent.clawhip import Clawhip, ClawhipEvent, ClawhipEventType
from backend.agent.engine_router import EngineRouter
from backend.agent.instruction_parser import InstructionParser
from backend.agent.llm_router import LLMRouter
from backend.agent.omo import OmO
from backend.agent.omx import OmX, OmXPlanValidationError
from backend.agent.response_composer import ResponseComposer
from backend.agent.sub_agents.cloud_agent import CloudAgent
from backend.agent.sub_agents.data_sec_agent import DataSecAgent
from backend.agent.sub_agents.endpoint_agent import EndpointAgent
from backend.agent.sub_agents.exploit_agent import ExploitAgent
from backend.agent.sub_agents.genai_agent import GenAIAgent
from backend.agent.sub_agents.iam_agent import IAMAgent
from backend.agent.sub_agents.ics_agent import ICSAgent
from backend.agent.sub_agents.intel_agent import IntelAgent
from backend.agent.sub_agents.model_sec_agent import ModelSecAgent
from backend.agent.sub_agents.recon_agent import ReconAgent
from backend.agent.sub_agents.scan_agent import ScanAgent
from backend.agent.tool_selector import ToolSelector
from backend.reporting.explainable_ai import ExplainableAI
from backend.session.engagement_session import EngagementSession
from backend.session.session_store import session_store

logger = logging.getLogger(__name__)

_SYSTEM_PROMPT = (
    "You are Optimus, a universal AI security platform. "
    "Analyze the user's intent and provide a structured security assessment response. "
    "Be concise and actionable."
)

_COMPACTION_SYSTEM_PROMPT = "Summarize these pentest findings concisely."


@dataclass
class OrchestratorDecision:
    intent: str
    engine: str
    target: str
    constraints: dict
    phase: str
    tools: list
    confidence: float


def _build_agent_registry() -> Dict[str, Any]:
    """Construct the 11-agent registry OmO dispatches against (RESEARCH.md
    Code Examples). Every BaseAgent subclass constructor is zero-arg."""
    return {
        cls.__name__: cls()
        for cls in (
            CloudAgent,
            DataSecAgent,
            EndpointAgent,
            ExploitAgent,
            GenAIAgent,
            IAMAgent,
            ICSAgent,
            IntelAgent,
            ModelSecAgent,
            ReconAgent,
            ScanAgent,
        )
    }


class Orchestrator:
    def __init__(self):
        self.llm_router = LLMRouter()
        # D-02a: parser/engine_router/tool_selector remain instantiated for
        # backward compatibility but are deliberately never called in the new
        # process()/process_stream() pipeline — OmX's LLM DAG generation
        # supersedes their regex-based intent/target/tool-selection role.
        self.parser = InstructionParser()
        self.engine_router = EngineRouter()
        self.tool_selector = ToolSelector()
        self.composer = ResponseComposer()

        self._agents = _build_agent_registry()
        self.clawhip = Clawhip(self._get_manager(), ExplainableAI())
        self.omx = OmX(self.llm_router)
        # Read the single shared TaskRegistry instance owned by session_store
        # (Plan 04) — never construct a TaskRegistry here.
        self.omo = OmO(self._agents, self.clawhip, session_store.task_registry)

    @staticmethod
    def _get_manager():
        # Imported lazily (module-level import would be fine too, since
        # ws_handler.py only imports Orchestrator lazily inside its own
        # function body — no circular import risk) but kept as a small
        # helper to make the manager dependency explicit and easy to mock.
        from backend.api.ws_handler import manager

        return manager

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
