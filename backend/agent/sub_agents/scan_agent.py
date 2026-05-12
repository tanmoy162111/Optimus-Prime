from backend.agent.sub_agents.base import BaseAgent


class ScanAgent(BaseAgent):
    def __init__(self):
        super().__init__(
            name="ScanAgent",
            engine="InfrastructureEngine",
            allowed_tools=["nmap", "masscan", "nikto", "nuclei", "wpscan"],
            priority=1,
        )

    async def execute(self, target: str, **kwargs):
        from backend.execution.ssh_client import SSHClient
        from backend.execution.shell_manager import ShellManager
        
        ssh = SSHClient()
        shell = ShellManager(ssh)
        
        commands = [
            f"nmap -sV -sC -oA /tmp/scan {target}",
            f"nikto -h {target}",
            f"nuclei -u {target} -severity critical,high,medium",
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

    def get_fields(self):
        return ["Network", "Application"]