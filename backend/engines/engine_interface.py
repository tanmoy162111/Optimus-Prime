from abc import ABC, abstractmethod
from typing import Dict, Any
from dataclasses import dataclass


@dataclass
class EngineResult:
    engine: str
    intent: str
    target: str
    findings: list
    status: str


class EngineInterface(ABC):
    @abstractmethod
    async def execute(self, task: Dict[str, Any]) -> EngineResult:
        pass


class InfrastructureEngine(EngineInterface):
    async def execute(self, task: Dict[str, Any]) -> EngineResult:
        from backend.agent.sub_agents import scan_agent
        
        return EngineResult(
            engine="InfrastructureEngine",
            intent=task.get("intent", "general"),
            target=task.get("target", ""),
            findings=[],
            status="completed",
        )


class MLAIEngine(EngineInterface):
    async def execute(self, task: Dict[str, Any]) -> EngineResult:
        return EngineResult(
            engine="MLAIEngine",
            intent=task.get("intent", "genai_security"),
            target=task.get("target", ""),
            findings=[],
            status="completed",
        )


class ICSEngine(EngineInterface):
    async def execute(self, task: Dict[str, Any]) -> EngineResult:
        return EngineResult(
            engine="ICSEngine",
            intent=task.get("intent", "ics"),
            target=task.get("target", ""),
            findings=[],
            status="stub",
        )