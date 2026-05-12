import logging
from typing import Dict, Any

logger = logging.getLogger(__name__)


class InfrastructureEngine:
    """Engine 1: Traditional Infrastructure Security"""

    def __init__(self):
        self.name = "InfrastructureEngine"

    async def execute(
        self,
        task: Dict[str, Any],
        sub_agent: Any,
    ) -> Dict[str, Any]:
        intent = task.get("intent", "general")
        target = task.get("target", "")
        
        result = await sub_agent.execute(target)
        
        return {
            "engine": self.name,
            "intent": intent,
            "target": target,
            "findings": result.get("findings", []),
            "sub_agent": sub_agent.name,
        }