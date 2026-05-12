from backend.agent.sub_agents.base import BaseAgent


class IntelAgent(BaseAgent):
    def __init__(self):
        super().__init__(
            name="IntelAgent",
            engine="InfrastructureEngine",
            allowed_tools=["surface_web_intel", "dark_web_intel", "web_intelligence"],
            priority=1,
        )

    async def execute(self, target: str, **kwargs):
        from backend.intelligence.surface_web_intel import SurfaceWebIntel
        from backend.intelligence.dark_web_intel import DarkWebIntel
        
        results = {}
        
        surface = SurfaceWebIntel()
        results["surface"] = await surface.query(target)
        
        dark = DarkWebIntel()
        results["dark"] = await dark.query(target)
        
        return {
            "agent": self.name,
            "target": target,
            "findings": results,
            "tools_used": self.allowed_tools,
        }

    def get_fields(self):
        return ["All"]