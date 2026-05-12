from backend.agent.sub_agents.base import BaseAgent


class DataSecAgent(BaseAgent):
    def __init__(self):
        super().__init__(
            name="DataSecAgent",
            engine="InfrastructureEngine",
            allowed_tools=["trufflehog", "gitleaks", "testssl.sh", "pii_parser", "exfil_sim"],
            priority=3,
        )

    async def execute(self, target: str, **kwargs):
        from backend.execution.ssh_client import SSHClient
        from backend.execution.shell_manager import ShellManager
        
        ssh = SSHClient()
        shell = ShellManager(ssh)
        
        scan_type = kwargs.get("type", "secrets")
        
        results = {}
        
        if scan_type in ["secrets", "all"]:
            results["secrets"] = await self._scan_secrets(target, shell)
        
        if scan_type in ["tls", "all"]:
            results["tls"] = await self._scan_tls(target, shell)
        
        if scan_type in ["pii", "all"]:
            results["pii"] = await self._scan_pii(target, shell)
        
        if scan_type in ["exfil", "all"]:
            results["exfil"] = await self._test_exfil(target, shell)
        
        findings = self._aggregate_findings(results)
        
        return {
            "agent": self.name,
            "target": target,
            "scan_type": scan_type,
            "findings": findings,
            "results": results,
            "tools_used": self.allowed_tools,
        }

    async def _scan_secrets(self, target: str, shell) -> dict:
        commands = [
            f"trufflehog filesystem {target}",
            f"gitleaks detect --source={target}",
        ]
        
        all_findings = []
        for cmd in commands:
            try:
                output = await shell.execute(cmd)
                if "{" in output or "found" in output.lower():
                    all_findings.append({
                        "severity": "CRITICAL",
                        "type": "hardcoded_secret",
                        "evidence": output[:300],
                    })
            except Exception:
                pass
        
        return {"findings": all_findings}

    async def _scan_tls(self, target: str, shell) -> dict:
        import re
        match = re.search(r"(?:https?://)?([^:/]+)", target)
        host = match.group(1) if match else target
        
        cmd = f"testssl.sh --jsonfile /tmp/tls.json {host}"
        output = await shell.execute(cmd)
        
        findings = []
        weak_ciphers = ["rc4", "export", "des", "3des"]
        for cipher in weak_ciphers:
            if cipher in output.lower():
                findings.append({
                    "severity": "HIGH",
                    "type": "weak_cipher",
                    "title": f"Weak TLS cipher: {cipher}",
                    "evidence": f"Cipher {cipher} is enabled",
                })
        
        if "expired" in output.lower():
            findings.append({
                "severity": "HIGH",
                "type": "expired_cert",
                "title": "Expired TLS certificate",
            })
        
        return {"findings": findings, "output": output}

    async def _scan_pii(self, target: str, shell) -> dict:
        cmd = f"curl -s {target} | grep -Eo '[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{{2,}}' | head -20"
        output = await shell.execute(cmd)
        
        findings = []
        emails = output.strip().split("\n")
        if len(emails) > 0 and emails[0]:
            findings.append({
                "severity": "MEDIUM",
                "type": "pii_email",
                "title": "Email addresses in response",
                "description": f"Found {len(emails)} email(s)",
                "evidence": f"Sample: {emails[0]}",
            })
        
        phone_pattern = r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b"
        import re
        phones = re.findall(phone_pattern, output)
        if phones:
            findings.append({
                "severity": "MEDIUM",
                "type": "pii_phone",
                "title": "Phone numbers in response",
                "description": f"Found {len(phones)} phone number(s)",
            })
        
        return {"findings": findings}

    async def _test_exfil(self, target: str, shell) -> dict:
        findings = []
        
        dns_cmd = f"python3 -c \"import socket; s=socket.socket(socket.AF_INET, socket.SOCK_DGRAM); s.sendto(b'test', ('{target}', 53))\""
        await shell.execute(dns_cmd)
        findings.append({
            "severity": "LOW",
            "type": "exfil_dns",
            "title": "DNS exfil test",
            "description": "DNS channel available for data exfiltration",
        })
        
        http_cmd = f"curl -X POST {target} -d 'data=test' -w '%{{http_code}}'"
        output = await shell.execute(http_cmd)
        if "200" in output or "201" in output:
            findings.append({
                "severity": "LOW",
                "type": "exfil_http",
                "title": "HTTP POST exfil possible",
                "description": "HTTP POST channel available",
            })
        
        return {"findings": findings}

    def _aggregate_findings(self, results: dict) -> list:
        all_findings = []
        for category, data in results.items():
            if isinstance(data, dict) and "findings" in data:
                all_findings.extend(data["findings"])
        return all_findings

    def get_fields(self):
        return ["Data Security"]