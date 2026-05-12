from backend.agent.sub_agents.base import BaseAgent


class CloudAgent(BaseAgent):
    def __init__(self):
        super().__init__(
            name="CloudAgent",
            engine="InfrastructureEngine",
            allowed_tools=["scoutsuite", "prowler", "pacu", "aws-cli", "az-cli", "gcloud"],
            priority=2,
        )

    async def execute(self, target: str, **kwargs):
        from backend.execution.ssh_client import SSHClient
        from backend.execution.shell_manager import ShellManager
        
        provider = kwargs.get("provider", "auto")
        command_type = kwargs.get("command", "scoutsuite")
        
        ssh = SSHClient()
        shell = ShellManager(ssh)
        
        if provider == "auto":
            provider = self._detect_provider(target)
        
        if command_type == "scoutsuite":
            cmd = f"scoutsuite --provider {provider} --report-dir /tmp/cloud"
        elif command_type == "prowler":
            cmd = f"prowler {provider} --csv"
        elif command_type == "pacu":
            cmd = f"pacu run --services all"
        else:
            cmd = f"scoutsuite --provider {provider}"
        
        output = await shell.execute(cmd)
        
        return {
            "agent": self.name,
            "target": target,
            "provider": provider,
            "command": command_type,
            "output": output,
            "findings": self._parse_findings(output, provider),
            "tools_used": self.allowed_tools,
        }

    def _detect_provider(self, target: str) -> str:
        if "arn:aws" in target or target.startswith("AKIA"):
            return "aws"
        elif "/subscriptions/" in target or len(target) == 36:
            return "azure"
        elif "projects/" in target:
            return "gcp"
        return "aws"

    def _parse_findings(self, output: str, provider: str) -> list:
        findings = []
        lines = output.split("\n")
        
        severity_keywords = {
            "CRITICAL": ["root", "admin", "administrator"],
            "HIGH": ["public", "exposed", "unencrypted"],
            "MEDIUM": ["weak", "default", "missing"],
            "LOW": ["info", "notice"],
        }
        
        for line in lines:
            line_lower = line.lower()
            for severity, keywords in severity_keywords.items():
                if any(k in line_lower for k in keywords):
                    findings.append({
                        "severity": severity,
                        "title": line.strip()[:100],
                        "evidence": line.strip(),
                        "provider": provider,
                    })
                    break
        
        return findings[:50]

    def get_fields(self):
        return ["Cloud"]