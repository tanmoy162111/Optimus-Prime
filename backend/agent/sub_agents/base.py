from abc import ABC, abstractmethod
from typing import List, Dict, Any, Optional
from dataclasses import dataclass, field


@dataclass
class BaseAgent(ABC):
    name: str
    engine: str
    allowed_tools: List[str] = field(default_factory=list)
    priority: int = 1

    @abstractmethod
    async def execute(self, target: str, **kwargs) -> Dict[str, Any]:
        pass

    def check_tool_permission(self, tool: str) -> bool:
        return tool in self.allowed_tools

    def get_fields(self) -> List[str]:
        return []


class ToolPermissionError(Exception):
    pass