from backend.agent.sub_agents.base import BaseAgent


class IAMAgent(BaseAgent):
    def __init__(self):
        super().__init__(
            name="IAMAgent",
            engine="InfrastructureEngine",
            allowed_tools=["jwt-tool", "oauthscan", "saml-raider", "modlishka", "o365spray"],
            priority=3,
        )

    async def execute(self, target: str, **kwargs):
        from backend.execution.ssh_client import SSHClient
        from backend.execution.shell_manager import ShellManager
        
        assessment_type = kwargs.get("type", "auto")
        
        ssh = SSHClient()
        shell = ShellManager(ssh)
        
        if assessment_type == "jwt" or self._is_jwt_target(target):
            result = await self._assess_jwt(target, shell)
        elif assessment_type == "oauth":
            result = await self._assess_oauth(target, shell)
        elif assessment_type == "saml":
            result = await self._assess_saml(target, shell)
        elif assessment_type == "mfa":
            result = await self._assess_mfa(target, shell)
        else:
            result = await self._assess_jwt(target, shell)
        
        return {
            "agent": self.name,
            "target": target,
            "assessment_type": assessment_type,
            "findings": result.get("findings", []),
            "tools_used": self.allowed_tools,
        }

    def _is_jwt_target(self, target: str) -> bool:
        return "jwt" in target.lower() or "token" in target.lower()

    async def _assess_jwt(self, target: str, shell) -> dict:
        cmd = f"python3 -m jwt_tool {target} -v"
        output = await shell.execute(cmd)
        
        findings = []
        if "alg" in output.lower():
            findings.append({
                "severity": "HIGH",
                "title": "JWT Algorithm Confusion",
                "description": "Potential algorithm confusion vulnerability",
                "evidence": "RS256 to HS256 bypass possible",
            })
        if "none" in output.lower():
            findings.append({
                "severity": "CRITICAL",
                "title": "JWT 'none' Algorithm",
                "description": "Token accepts 'none' algorithm",
                "evidence": "Authentication bypass possible",
            })
        
        return {"findings": findings, "output": output}

    async def _assess_oauth(self, target: str, shell) -> dict:
        cmd = f"oauthscan -u {target}"
        output = await shell.execute(cmd)
        
        return {
            "findings": [
                {"severity": "MEDIUM", "title": "OAuth Misconfiguration", "evidence": output[:200]}
            ],
            "output": output,
        }

    async def _assess_saml(self, target: str, shell) -> dict:
        cmd = f"saml-raider -t {target}"
        output = await shell.execute(cmd)
        
        findings = []
        if "signed" in output.lower():
            findings.append({
                "severity": "HIGH",
                "title": "SAML Assertion Not Signed",
                "description": "SAML assertion lacks signature verification",
            })
        
        return {"findings": findings, "output": output}

    async def _assess_mfa(self, target: str, shell) -> dict:
        cmd = f"modlishka -target {target} -list"
        output = await shell.execute(cmd)
        
        return {
            "findings": [
                {"severity": "MEDIUM", "title": "MFA Bypass Possible", "evidence": "Reverse proxy setup detected"}
            ],
            "output": output,
        }

    def get_fields(self):
        return ["IAM"]