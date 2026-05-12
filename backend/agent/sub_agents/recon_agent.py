from backend.agent.sub_agents.base import BaseAgent


class ReconAgent(BaseAgent):
    def __init__(self):
        super().__init__(
            name="ReconAgent",
            engine="InfrastructureEngine",
            allowed_tools=["sublist3r", "amass", "theHarvester", "dnsenum", "whatweb"],
            priority=1,
        )

    async def execute(self, target: str, **kwargs):
        from backend.execution.ssh_client import SSHClient
        from backend.execution.shell_manager import ShellManager
        
        ssh = SSHClient()
        shell = ShellManager(ssh)
        
        commands = [
            f"sublist3r -d {target} -o /tmp/recon.txt",
            f"amass enum -d {target}",
            f"theHarvester -d {target} -b all",
        ]
        
        results = []
        for cmd in commands:
            output = await shell.execute(cmd)
            results.append({"command": cmd, "output": output})
        
        return {
            "agent": self.name,
            "target": target,
            "findings": results,
            "tools_used": self.allowed_tools,
        }