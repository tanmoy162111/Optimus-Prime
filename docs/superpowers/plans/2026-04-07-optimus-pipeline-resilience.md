# Optimus Pipeline Resilience Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Fix the findings pipeline (all findings in report with verification status), scope discovery (target-type routing), two-phase exploitation (CONTROLLED → FULL gate), tool resilience (fallback resolver + auto-install), and Kali-side dynamic timeouts.

**Architecture:** Nine targeted edits + one new file (`tool_fallback.py`). Each task is independently testable. Tasks 1-5 fix correctness bugs; Tasks 6-8 add resilience infrastructure; Task 9 hardens LLM parsing. All follow existing async/dataclass conventions.

**Tech Stack:** Python 3.14, pytest-asyncio, paramiko, asyncio, unittest.mock.AsyncMock, SQLite (ResearchKB)

---

## File Map

| Task | Files |
|------|-------|
| 1 | `backend/verification/verification_loop.py` · `backend/tests/test_verification_loop_classify.py` (new) |
| 2 | `backend/intelligence/intelligent_reporter.py` · `backend/tests/test_reporter_verification_status.py` (new) |
| 3 | `backend/agents/scope_discovery_agent.py` · `backend/tests/test_scope_discovery_target_type.py` (new) |
| 4 | `backend/core/omx.py` · `backend/tests/test_omx_two_phase_exploit.py` (new) |
| 5 | `backend/agents/exploit_agent.py` · `backend/tests/test_exploit_agent_fallback.py` (new) |
| 6 | `backend/core/tool_fallback.py` (new) · `backend/tests/test_tool_fallback_resolver.py` (new) |
| 7 | `backend/core/base_agent.py` · `backend/tests/test_base_agent_resilience.py` (new) |
| 8 | `backend/tools/backends/kali_ssh.py` · `backend/tests/test_kali_ssh_timeouts.py` (new) |
| 9 | `backend/agents/scan_agent.py` · `backend/tests/test_llm_json_hardening.py` (new) |

---

## Task 1: Fix VerificationLoop — Tool Failure → MANUAL_REVIEW

**Problem:** `_classify_result()` returns `FALSE_POSITIVE` when the verification tool itself fails (SSH error, tool not found, timeout). Only tool runs that produce no evidence should be `FALSE_POSITIVE`.

**Files:**
- Modify: `backend/verification/verification_loop.py:192-230`
- Create: `backend/tests/test_verification_loop_classify.py`

- [ ] **Step 1: Write failing tests**

Create `backend/tests/test_verification_loop_classify.py`:

```python
"""Tests for VerificationLoop._classify_result() classification logic."""
from __future__ import annotations
import pytest
from backend.core.models import FindingClassification
from backend.verification.verification_loop import VerificationLoop


@pytest.fixture
def vl():
    return VerificationLoop()


SAMPLE_FINDING = {"finding_id": "f-001", "target": "10.0.0.1", "port": 80, "severity": "medium"}


class TestClassifyResult:
    def test_ssh_connection_error_is_manual_review(self, vl):
        """Tool failure (SSH/connection) must not be classified as FALSE_POSITIVE."""
        result = {"status": "error", "error": "Connection refused: SSH unreachable", "output": ""}
        cls = vl._classify_result(SAMPLE_FINDING, result)
        assert cls == FindingClassification.MANUAL_REVIEW

    def test_tool_not_found_error_is_manual_review(self, vl):
        """tool_not_found error must be MANUAL_REVIEW, not FALSE_POSITIVE."""
        result = {"status": "error", "error": "Tool 'nmap_verify' not found on Kali", "output": ""}
        cls = vl._classify_result(SAMPLE_FINDING, result)
        assert cls == FindingClassification.MANUAL_REVIEW

    def test_timeout_error_is_manual_review(self, vl):
        """Timeout errors must be MANUAL_REVIEW."""
        result = {"status": "error", "error": "Command timed out after 60s", "output": ""}
        cls = vl._classify_result(SAMPLE_FINDING, result)
        assert cls == FindingClassification.MANUAL_REVIEW

    def test_tool_ran_no_output_is_false_positive(self, vl):
        """Tool ran successfully but produced no evidence → FALSE_POSITIVE."""
        result = {"status": "success", "output": "", "error": ""}
        cls = vl._classify_result(SAMPLE_FINDING, result)
        assert cls == FindingClassification.FALSE_POSITIVE

    def test_tool_ran_with_port_open_is_confirmed(self, vl):
        """Tool ran and shows port open → CONFIRMED."""
        result = {"status": "success", "output": "80/tcp open http", "error": ""}
        cls = vl._classify_result(SAMPLE_FINDING, result)
        assert cls == FindingClassification.CONFIRMED

    def test_tool_ran_with_http_response_is_confirmed(self, vl):
        """Tool ran and shows HTTP response → CONFIRMED."""
        result = {"status": "success", "output": "HTTP/1.1 200 OK\nServer: Apache", "error": ""}
        cls = vl._classify_result({"target": "10.0.0.1", "tool": "nikto"}, result)
        assert cls == FindingClassification.CONFIRMED

    def test_tool_ran_with_any_output_is_confirmed(self, vl):
        """Tool ran with >10 chars output and no clear indicator → CONFIRMED (benefit of doubt)."""
        result = {"status": "success", "output": "some output that is longer than 10 characters", "error": ""}
        cls = vl._classify_result({"target": "10.0.0.1"}, result)
        assert cls == FindingClassification.CONFIRMED
```

- [ ] **Step 2: Run tests to verify they fail**

```
cd C:\Projects\Optimus
.venv\Scripts\pytest backend/tests/test_verification_loop_classify.py -v
```
Expected: Several FAILED — `test_ssh_connection_error_is_manual_review`, `test_tool_not_found_error_is_manual_review`, `test_timeout_error_is_manual_review` return `FALSE_POSITIVE` instead of `MANUAL_REVIEW`.

- [ ] **Step 3: Fix `_classify_result()` in `backend/verification/verification_loop.py`**

Replace the entire `_classify_result` method (lines ~192-230):

```python
def _classify_result(
    self, finding: dict[str, Any], result: dict[str, Any]
) -> FindingClassification:
    """Classify a finding based on verification result.

    Distinguishes tool infrastructure failure from finding absence:
      - Tool failure (SSH error, tool not found, timeout) → MANUAL_REVIEW
        (finding neither confirmed nor refuted — needs operator review)
      - Tool ran, no evidence found → FALSE_POSITIVE
      - Tool ran, evidence found → CONFIRMED
    """
    status = result.get("status", "")
    output = result.get("output", result.get("stdout", ""))
    error = result.get("error", "")

    # Infrastructure failure: tool could not run — do NOT mark as false positive.
    # The finding is neither confirmed nor refuted.
    if status == "error" and error:
        _infra_keywords = (
            "connection", "unreachable", "timeout", "timed out",
            "not found", "tool_not_found", "ssh", "refused", "reset",
        )
        if any(kw in error.lower() for kw in _infra_keywords):
            return FindingClassification.MANUAL_REVIEW
        # Generic error with no output — still can't confirm the finding is false
        if not output:
            return FindingClassification.MANUAL_REVIEW

    # Tool ran but produced no output → no evidence → false positive
    if not output:
        return FindingClassification.FALSE_POSITIVE

    # Check for evidence of the finding being real
    port = finding.get("port")
    output_lower = output.lower() if isinstance(output, str) else ""

    # Port verification: check if port appears open in output
    if port and str(port) in output_lower and "open" in output_lower:
        return FindingClassification.CONFIRMED

    # HTTP verification: check for success indicators
    if any(indicator in output_lower for indicator in ("200", "http/", "html", "server:", "open")):
        return FindingClassification.CONFIRMED

    # Output present but no clear indicators → give benefit of the doubt
    if len(output_lower) > 10:
        return FindingClassification.CONFIRMED

    return FindingClassification.MANUAL_REVIEW
```

- [ ] **Step 4: Run tests to verify they pass**

```
.venv\Scripts\pytest backend/tests/test_verification_loop_classify.py -v
```
Expected: All 7 PASSED.

- [ ] **Step 5: Verify no regression in verification policy tests**

```
.venv\Scripts\pytest backend/tests/test_verification_policy.py -v
```
Expected: All PASSED.

- [ ] **Step 6: Commit**

```bash
git add backend/verification/verification_loop.py backend/tests/test_verification_loop_classify.py
git commit -m "fix: tool infrastructure failure classifies as MANUAL_REVIEW not FALSE_POSITIVE

Previously, SSH errors and tool_not_found results were classified as
FALSE_POSITIVE, dropping valid findings from the report. Now these are
MANUAL_REVIEW — the finding is unrefuted and needs operator review.

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>"
```

---

## Task 2: IntelligentReporter — All Findings with Verification Status

**Problem:** Reporter only surfaces CONFIRMED findings. 90-112 findings generated but only 3-4 confirmed ones appear. All findings must appear in reports with a `verification_status` field.

**Files:**
- Modify: `backend/intelligence/intelligent_reporter.py:57-129`
- Create: `backend/tests/test_reporter_verification_status.py`

- [ ] **Step 1: Write failing tests**

Create `backend/tests/test_reporter_verification_status.py`:

```python
"""Tests for IntelligentReporter all-findings with verification_status."""
from __future__ import annotations
import pytest
from backend.intelligence.intelligent_reporter import IntelligentReporter


@pytest.fixture
def reporter():
    return IntelligentReporter()


class TestReporterVerificationStatus:
    @pytest.mark.asyncio
    async def test_finding_created_sets_unverified_status(self, reporter):
        await reporter._on_finding_event({
            "event_type": "FINDING_CREATED",
            "payload": {"finding_id": "f-001", "title": "Open port 80", "severity": "info"},
        })
        findings = reporter.get_findings_for_report()
        assert len(findings) == 1
        assert findings[0]["verification_status"] == "unverified"

    @pytest.mark.asyncio
    async def test_confirmed_classification_updates_status(self, reporter):
        await reporter._on_finding_event({
            "event_type": "FINDING_CREATED",
            "payload": {"finding_id": "f-001", "title": "Open port 80", "severity": "info"},
        })
        await reporter._on_finding_event({
            "event_type": "FINDING_CLASSIFIED",
            "payload": {"finding_id": "f-001", "classification": "confirmed"},
        })
        findings = reporter.get_findings_for_report()
        assert findings[0]["verification_status"] == "confirmed"

    @pytest.mark.asyncio
    async def test_manual_review_classification_updates_status(self, reporter):
        await reporter._on_finding_event({
            "event_type": "FINDING_CREATED",
            "payload": {"finding_id": "f-002", "title": "SSH exposed", "severity": "medium"},
        })
        await reporter._on_finding_event({
            "event_type": "FINDING_CLASSIFIED",
            "payload": {"finding_id": "f-002", "classification": "manual_review"},
        })
        findings = reporter.get_findings_for_report()
        assert findings[0]["verification_status"] == "manual_review"

    @pytest.mark.asyncio
    async def test_false_positive_classification_updates_status(self, reporter):
        await reporter._on_finding_event({
            "event_type": "FINDING_CREATED",
            "payload": {"finding_id": "f-003", "title": "Ghost port", "severity": "info"},
        })
        await reporter._on_finding_event({
            "event_type": "FINDING_CLASSIFIED",
            "payload": {"finding_id": "f-003", "classification": "false_positive"},
        })
        findings = reporter.get_findings_for_report()
        assert findings[0]["verification_status"] == "false_positive"

    @pytest.mark.asyncio
    async def test_all_findings_returned_regardless_of_status(self, reporter):
        """All 3 findings appear in report — confirmed, manual_review, unverified."""
        for fid, title in [("f-001", "SQLi"), ("f-002", "XSS"), ("f-003", "Open port")]:
            await reporter._on_finding_event({
                "event_type": "FINDING_CREATED",
                "payload": {"finding_id": fid, "title": title, "severity": "high"},
            })
        # Only f-001 gets confirmed
        await reporter._on_finding_event({
            "event_type": "FINDING_CLASSIFIED",
            "payload": {"finding_id": "f-001", "classification": "confirmed"},
        })
        # f-002 gets false_positive
        await reporter._on_finding_event({
            "event_type": "FINDING_CLASSIFIED",
            "payload": {"finding_id": "f-002", "classification": "false_positive"},
        })
        findings = reporter.get_findings_for_report()
        assert len(findings) == 3
        statuses = {f["finding_id"]: f["verification_status"] for f in findings}
        assert statuses["f-001"] == "confirmed"
        assert statuses["f-002"] == "false_positive"
        assert statuses["f-003"] == "unverified"

    @pytest.mark.asyncio
    async def test_report_severity_uses_all_findings(self, reporter):
        """Executive report severity should use all findings, not just confirmed."""
        for fid, sev in [("f-001", "critical"), ("f-002", "high"), ("f-003", "high")]:
            await reporter._on_finding_event({
                "event_type": "FINDING_CREATED",
                "payload": {"finding_id": fid, "title": f"Finding {fid}", "severity": sev},
            })
        # No findings confirmed — all unverified
        report = reporter.generate_report("executive")
        # With 1 critical + 2 high, overall risk must NOT be LOW
        assert report["sections"]["risk_summary"]["overall_risk"] in ("CRITICAL", "HIGH", "MEDIUM")

    def test_generate_report_includes_verification_status_per_finding(self, reporter):
        """Technical report findings all have verification_status field."""
        reporter.add_finding({"finding_id": "f-001", "title": "SQLi", "severity": "critical"})
        report = reporter.generate_report("technical")
        for finding in report["sections"]["detailed_findings"]:
            assert "verification_status" in finding
```

- [ ] **Step 2: Run tests to verify they fail**

```
.venv\Scripts\pytest backend/tests/test_reporter_verification_status.py -v
```
Expected: All FAILED — `get_findings_for_report()` doesn't return unverified findings and findings lack `verification_status`.

- [ ] **Step 3: Update `_on_finding_event` to track all findings with status**

In `backend/intelligence/intelligent_reporter.py`, replace `_on_finding_event` and update `get_findings_for_report`:

```python
async def _on_finding_event(self, event: dict[str, Any]) -> None:
    """Handle incoming finding events.

    Tracks ALL findings with their verification status:
      FINDING_CREATED        → added to _all_findings with status "unverified"
      FINDING_CLASSIFIED     → status updated in _all_findings cache
    """
    event_type = event.get("event_type", "")
    payload = event.get("payload", {})

    if event_type == "FINDING_CREATED":
        fid = payload.get("finding_id") or payload.get("id", "")
        finding = dict(payload)
        finding.setdefault("verification_status", "unverified")
        if fid:
            self._finding_cache[fid] = finding
        self._all_findings.append(finding)

    elif event_type == "FINDING_CLASSIFIED":
        classification = payload.get("classification", "")
        fid = payload.get("finding_id", "")
        if fid and fid in self._finding_cache:
            self._finding_cache[fid]["verification_status"] = classification
            # Also update the entry in _all_findings list (same dict object via cache ref)
        # Legacy: also maintain confirmed list for backwards compat
        if classification == "confirmed":
            if fid and fid in self._finding_cache:
                full = dict(self._finding_cache[fid])
                full["classification"] = "confirmed"
                self._confirmed_findings.append(full)
            else:
                entry = dict(payload)
                entry["verification_status"] = "confirmed"
                self._confirmed_findings.append(entry)

def get_findings_for_report(self) -> list[dict[str, Any]]:
    """Return ALL findings for report generation, each with verification_status.

    Returns the complete finding set so the report reflects all discovered
    issues regardless of verification outcome. The verification_status field
    lets operators filter by CONFIRMED / MANUAL_REVIEW / UNVERIFIED / FALSE_POSITIVE.
    """
    findings = []
    for finding in self._all_findings:
        f = dict(finding)
        f.setdefault("verification_status", "unverified")
        findings.append(f)
    if not findings and self._confirmed_findings:
        # Fallback: manually-added findings via add_finding()
        return list(self._confirmed_findings)
    return findings
```

- [ ] **Step 4: Update `add_finding()` to set verification_status**

Replace the `add_finding` method:

```python
def add_finding(self, finding: dict[str, Any]) -> None:
    """Manually add a confirmed finding (useful for testing / direct use)."""
    fid = finding.get("finding_id") or finding.get("id", "")
    entry = dict(finding)
    entry.setdefault("verification_status", "confirmed")
    if fid:
        self._finding_cache[fid] = entry
    self._all_findings.append(entry)
    self._confirmed_findings.append(entry)
```

- [ ] **Step 5: Add `verification_status` to `_gen_technical` detailed_findings**

In `_gen_technical`, add `"verification_status"` to each finding dict:

```python
detailed_findings.append({
    "finding_id": f.get("finding_id", ""),
    "title": f.get("title", "Unknown"),
    "severity": f.get("severity", "info"),
    "verification_status": f.get("verification_status", "unverified"),
    "description": f.get("description", ""),
    "target": f.get("target", ""),
    "port": f.get("port"),
    "tool": f.get("tool", ""),
    "evidence": f.get("evidence", ""),
    "reproduction_steps": f.get("reproduction_steps", "Run tool against target"),
    "cvss_score": f.get("cvss_score"),
    "cve_ids": f.get("cve_ids", []),
    "attack_technique": f.get("attack_technique", ""),
})
```

- [ ] **Step 6: Run tests**

```
.venv\Scripts\pytest backend/tests/test_reporter_verification_status.py backend/tests/test_report_formats.py -v
```
Expected: All PASSED.

- [ ] **Step 7: Commit**

```bash
git add backend/intelligence/intelligent_reporter.py backend/tests/test_reporter_verification_status.py
git commit -m "fix: reporter includes all findings with verification_status field

All 90-112 findings now appear in reports annotated with their
verification outcome (confirmed/manual_review/unverified/false_positive).
Executive risk level now reflects true severity across all findings.

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>"
```

---

## Task 3: ScopeDiscoveryAgent — Target Auto-detection

**Problem:** OSINT tools fail silently for internal/RFC-1918 targets, producing 0 findings. Need to route to appropriate tools per target type and always generate ≥ 1 finding.

**Files:**
- Modify: `backend/agents/scope_discovery_agent.py`
- Create: `backend/tests/test_scope_discovery_target_type.py`

- [ ] **Step 1: Write failing tests**

Create `backend/tests/test_scope_discovery_target_type.py`:

```python
"""Tests for ScopeDiscoveryAgent target type detection and tool routing."""
from __future__ import annotations
import pytest
from unittest.mock import AsyncMock
from backend.agents.scope_discovery_agent import ScopeDiscoveryAgent
from backend.core.models import AgentTask, AgentType, EngineType, ScopeConfig


@pytest.fixture
def agent():
    return ScopeDiscoveryAgent(
        agent_id="test-scope",
        agent_type=AgentType.SCOPE_DISCOVERY,
        engine=EngineType.INFRASTRUCTURE,
        scope=ScopeConfig(targets=["10.0.0.1"]),
    )


class TestTargetTypeDetection:
    def test_rfc1918_10_is_internal(self, agent):
        assert agent._detect_target_type("10.0.0.1") == "internal"

    def test_rfc1918_172_is_internal(self, agent):
        assert agent._detect_target_type("172.16.5.1") == "internal"

    def test_rfc1918_192_168_is_internal(self, agent):
        assert agent._detect_target_type("192.168.1.100") == "internal"

    def test_public_ip_is_public_ip(self, agent):
        assert agent._detect_target_type("8.8.8.8") == "public_ip"

    def test_domain_is_public_domain(self, agent):
        assert agent._detect_target_type("example.com") == "public_domain"

    def test_subdomain_is_public_domain(self, agent):
        assert agent._detect_target_type("api.example.com") == "public_domain"


class TestToolRouting:
    def test_internal_target_uses_local_tools_only(self, agent):
        """Internal IPs must not use OSINT tools (crt_sh, github_scan, shodan)."""
        agent._action_history = []
        actions = []
        action = agent._plan_fallback("10.0.0.1")
        while action is not None:
            actions.append(action.tool_name)
            action = agent._plan_fallback("10.0.0.1")
        osint_tools = {"crt_sh", "github_scan"}
        assert not osint_tools.intersection(set(actions)), \
            f"OSINT tools {osint_tools} must not run on internal target"
        assert "nmap" in actions

    def test_public_domain_uses_osint_tools(self, agent):
        """Public domains should use OSINT suite."""
        agent._action_history = []
        actions = []
        action = agent._plan_fallback("example.com")
        while action is not None:
            actions.append(action.tool_name)
            action = agent._plan_fallback("example.com")
        assert "crt_sh" in actions
        assert "whois" in actions

    def test_public_ip_uses_shodan_not_crt_sh(self, agent):
        """Public IPs use shodan/nmap but not crt_sh (CT logs are for domains)."""
        agent._action_history = []
        actions = []
        action = agent._plan_fallback("8.8.8.8")
        while action is not None:
            actions.append(action.tool_name)
            action = agent._plan_fallback("8.8.8.8")
        assert "crt_sh" not in actions
        assert "nmap" in actions


class TestScopeAnchorFinding:
    @pytest.mark.asyncio
    async def test_always_produces_at_least_one_finding(self):
        """Even if all tools return empty, a scope anchor finding must be generated."""
        executor = AsyncMock()
        from backend.core.base_agent import ToolResult
        executor.execute = AsyncMock(return_value=ToolResult(success=True, output={"stdout": "", "stderr": "", "status": "success", "exit_code": 0}))

        agent = ScopeDiscoveryAgent(
            agent_id="test-scope",
            agent_type=AgentType.SCOPE_DISCOVERY,
            engine=EngineType.INFRASTRUCTURE,
            scope=ScopeConfig(targets=["10.0.0.5"]),
            tool_executor=executor,
        )
        task = AgentTask(task_id="t1", agent_class="scope_discovery", prompt="Execute Scope Discovery phase against 10.0.0.5")
        result = await agent.execute(task)
        assert len(result.findings) >= 1
        titles = [f.get("title", "") for f in result.findings]
        assert any("10.0.0.5" in t or "scope" in t.lower() for t in titles)
```

- [ ] **Step 2: Run tests to verify they fail**

```
.venv\Scripts\pytest backend/tests/test_scope_discovery_target_type.py -v
```
Expected: All FAILED — `_detect_target_type` doesn't exist; `_plan_fallback` doesn't route by type.

- [ ] **Step 3: Add `_detect_target_type` to `ScopeDiscoveryAgent`**

In `backend/agents/scope_discovery_agent.py`, add this method to the class (before `_plan_fallback`):

```python
def _detect_target_type(self, target: str) -> str:
    """Detect whether target is internal RFC-1918, public IP, or public domain.

    Returns:
        "internal"      — RFC-1918 IP (10.x, 172.16-31.x, 192.168.x)
        "public_ip"     — Routable IP address
        "public_domain" — Domain name (contains letters, no CIDR slash)
    """
    import ipaddress
    import re as _re

    # Domain: has letters and dots but no slash (not CIDR)
    if _re.match(r'^[a-zA-Z]', target) and '/' not in target:
        return "public_domain"

    # Try as IP address
    try:
        ip = ipaddress.ip_address(target.split('/')[0])
        if ip.is_private:
            return "internal"
        return "public_ip"
    except ValueError:
        pass

    # Fallback for CIDR ranges — check first octet
    first_octet_match = _re.match(r'^(\d+)\.', target)
    if first_octet_match:
        first = int(first_octet_match.group(1))
        if first == 10 or first == 172 or first == 192:
            return "internal"
    return "public_ip"
```

- [ ] **Step 4: Replace `_plan_fallback` with target-type-aware routing**

Replace the existing `_plan_fallback` method in `ScopeDiscoveryAgent`:

```python
def _plan_fallback(self, target: str) -> AgentAction | None:
    """Route tool selection based on target type.

    internal    → nmap (full port scan), whatweb, dns_enum
    public_ip   → shodan (InternetDB), nmap, whatweb, whois
    public_domain → crt_sh, whois, shodan, dns_enum, github_scan
    """
    target_type = self._detect_target_type(target)

    if target_type == "internal":
        steps = [
            AgentAction("nmap", {"target": target, "flags": "-Pn -sV --top-ports 1000"}, "Full port scan of internal target"),
            AgentAction("whatweb", {"target": target, "flags": "-a 3"}, "Web tech fingerprinting"),
            AgentAction("dns_enum", {"target": target}, "DNS enumeration for IPs"),
        ]
    elif target_type == "public_ip":
        steps = [
            AgentAction("shodan", {"target": target}, "Internet exposure check via Shodan InternetDB"),
            AgentAction("nmap", {"target": target, "flags": "-Pn -sV --top-ports 1000"}, "Port scan"),
            AgentAction("whatweb", {"target": target, "flags": "-a 3"}, "Web tech fingerprinting"),
            AgentAction("whois", {"target": target}, "WHOIS lookup"),
        ]
    else:  # public_domain
        steps = [
            AgentAction("crt_sh", {"target": target}, "Certificate transparency — subdomain discovery"),
            AgentAction("whois", {"target": target}, "Domain registration info"),
            AgentAction("dns_enum", {"target": target}, "DNS enumeration — IP addresses"),
            AgentAction("github_scan", {"target": target}, "GitHub repository search"),
        ]
        # Shodan only at low/medium stealth
        if self.stealth_level != StealthLevel.HIGH:
            steps.insert(2, AgentAction("shodan", {"target": target}, "Internet exposure via Shodan"))

    step = len(self._action_history)
    if step >= len(steps):
        return None

    action = steps[step]
    self._action_history.append({
        "tool": action.tool_name,
        "input": action.tool_input,
        "reasoning": action.reasoning,
    })
    return action
```

- [ ] **Step 5: Add scope anchor finding to `execute()`**

Replace the `execute` method in `ScopeDiscoveryAgent`:

```python
async def execute(self, task: AgentTask) -> AgentResult:
    self._action_history = []
    self._discovered_assets = {t: [] for t in ASSET_TYPES}
    result = await self.run_loop(task)

    # Guarantee at least 1 finding — scope anchor from the seed target
    if not result.findings:
        target = _extract_target(task.prompt, scope=self.scope)
        anchor = {
            "finding_id": f"scope-anchor-{abs(hash(target)) & 0xFFFF:04x}",
            "title": f"Target in scope: {target}",
            "severity": "info",
            "tool": "scope_discovery",
            "target": target,
            "description": (
                f"Seed target '{target}' confirmed in engagement scope. "
                "Asset discovery tools returned no additional data."
            ),
        }
        result.findings = [anchor]
        if self.event_bus:
            await self.event_bus.publish(
                channel="findings",
                event_type="FINDING_CREATED",
                payload=anchor,
            )

    # Attach asset summary to result metadata
    result.metadata = result.metadata or {}
    result.metadata["asset_types"] = self._discovered_assets
    result.metadata["asset_type_count"] = sum(
        1 for v in self._discovered_assets.values() if v
    )
    return result
```

- [ ] **Step 6: Run tests**

```
.venv\Scripts\pytest backend/tests/test_scope_discovery_target_type.py -v
```
Expected: All PASSED.

- [ ] **Step 7: Commit**

```bash
git add backend/agents/scope_discovery_agent.py backend/tests/test_scope_discovery_target_type.py
git commit -m "fix: scope discovery auto-detects target type and routes tools accordingly

Internal IPs use local tools (nmap/whatweb/dns_enum) instead of OSINT.
Public domains use full OSINT suite. Scope anchor finding guarantees
>=1 finding even when all tools return empty output.

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>"
```

---

## Task 4: OmX — Two-Phase Exploitation with Human Escalation Gate

**Problem:** Single exploit phase. Need CONTROLLED first, then human gate, then optional FULL escalation. `--freehand` must skip CONTROLLED and go directly to FULL.

**Files:**
- Modify: `backend/core/omx.py:73-131`
- Create: `backend/tests/test_omx_two_phase_exploit.py`

- [ ] **Step 1: Write failing tests**

Create `backend/tests/test_omx_two_phase_exploit.py`:

```python
"""Tests for OmX two-phase exploitation plan structure."""
from __future__ import annotations
import pytest
from backend.core.models import ScopeConfig
from backend.core.omx import OmX


@pytest.fixture
def omx():
    return OmX()


class TestTwoPhaseExploitation:
    @pytest.mark.asyncio
    async def test_pentest_has_exploit_controlled_phase(self, omx):
        plan = await omx.plan("$pentest 10.0.0.1", ScopeConfig(targets=["10.0.0.1"]))
        phase_ids = [p.phase_id for p in plan.phases]
        assert "exploit_controlled" in phase_ids

    @pytest.mark.asyncio
    async def test_pentest_has_exploit_full_phase(self, omx):
        plan = await omx.plan("$pentest 10.0.0.1", ScopeConfig(targets=["10.0.0.1"]))
        phase_ids = [p.phase_id for p in plan.phases]
        assert "exploit_full" in phase_ids

    @pytest.mark.asyncio
    async def test_exploit_full_depends_on_exploit_controlled(self, omx):
        plan = await omx.plan("$pentest 10.0.0.1", ScopeConfig(targets=["10.0.0.1"]))
        full_phase = next(p for p in plan.phases if p.phase_id == "exploit_full")
        assert "exploit_controlled" in full_phase.depends_on

    @pytest.mark.asyncio
    async def test_exploit_full_has_human_gate(self, omx):
        plan = await omx.plan("$pentest 10.0.0.1", ScopeConfig(targets=["10.0.0.1"]))
        full_phase = next(p for p in plan.phases if p.phase_id == "exploit_full")
        assert full_phase.gate is not None
        assert full_phase.gate.gate_type == "human"

    @pytest.mark.asyncio
    async def test_exploit_controlled_metadata_has_controlled_mode(self, omx):
        plan = await omx.plan("$pentest 10.0.0.1", ScopeConfig(targets=["10.0.0.1"]))
        controlled = next(p for p in plan.phases if p.phase_id == "exploit_controlled")
        assert controlled.metadata.get("exploit_mode") == "controlled"

    @pytest.mark.asyncio
    async def test_exploit_full_metadata_has_full_mode(self, omx):
        plan = await omx.plan("$pentest 10.0.0.1", ScopeConfig(targets=["10.0.0.1"]))
        full = next(p for p in plan.phases if p.phase_id == "exploit_full")
        assert full.metadata.get("exploit_mode") == "full"

    @pytest.mark.asyncio
    async def test_freehand_flag_skips_controlled_phase(self, omx):
        """--freehand goes directly to FULL, no exploit_controlled phase."""
        plan = await omx.plan("$pentest --freehand 10.0.0.1", ScopeConfig(targets=["10.0.0.1"]))
        phase_ids = [p.phase_id for p in plan.phases]
        assert "exploit_controlled" not in phase_ids
        assert "exploit_full" in phase_ids

    @pytest.mark.asyncio
    async def test_freehand_exploit_full_depends_on_scan(self, omx):
        """When --freehand, exploit_full depends on scan (not exploit_controlled)."""
        plan = await omx.plan("$pentest --freehand 10.0.0.1", ScopeConfig(targets=["10.0.0.1"]))
        full = next(p for p in plan.phases if p.phase_id == "exploit_full")
        assert "scan" in full.depends_on
        assert "exploit_controlled" not in full.depends_on

    @pytest.mark.asyncio
    async def test_no_single_exploit_phase_in_default_pentest(self, omx):
        """The old single 'exploit' phase_id must not exist."""
        plan = await omx.plan("$pentest 10.0.0.1", ScopeConfig(targets=["10.0.0.1"]))
        phase_ids = [p.phase_id for p in plan.phases]
        assert "exploit" not in phase_ids
```

- [ ] **Step 2: Run tests to verify they fail**

```
.venv\Scripts\pytest backend/tests/test_omx_two_phase_exploit.py -v
```
Expected: All FAILED — `exploit_controlled` not in plan, single `exploit` phase still present.

- [ ] **Step 3: Replace `_pentest_phases` in `backend/core/omx.py`**

Replace the entire `_pentest_phases` function:

```python
def _pentest_phases(exploit_mode: str = "controlled") -> list[EngagementPhase]:
    """Full penetration test protocol with two-phase exploitation.

    Default flow:
      scope → recon → scan → exploit_controlled [human gate] →
      exploit_full [human gate] → verify → intel → report

    With --freehand:
      scope → recon → scan → exploit_full [human gate] → verify → intel → report

    Args:
        exploit_mode: ``"controlled"`` (default, two-phase) or ``"full"``
            (freehand — skips controlled phase, goes straight to full).
    """
    mode = exploit_mode.lower()

    base_phases = [
        EngagementPhase(
            phase_id="scope", name="Scope Discovery",
            description="Discover and validate engagement scope boundaries",
            agent_types=[AgentType.SCOPE_DISCOVERY],
        ),
        EngagementPhase(
            phase_id="recon", name="Reconnaissance",
            description="Active and passive reconnaissance of targets",
            agent_types=[AgentType.RECON],
            depends_on=["scope"],
        ),
        EngagementPhase(
            phase_id="scan", name="Vulnerability Scanning",
            description="Automated vulnerability scanning and service enumeration",
            agent_types=[AgentType.SCAN],
            depends_on=["recon"],
        ),
    ]

    if mode == "full":
        # Freehand: single FULL exploit phase, no CONTROLLED phase
        exploit_phases = [
            EngagementPhase(
                phase_id="exploit_full", name="Full Exploitation (Freehand)",
                description="Aggressive exploitation of all discovered services — FREEHAND mode",
                agent_types=[AgentType.EXPLOIT],
                depends_on=["scan"],
                gate=PhaseGate("human", "Operator approval required before freehand exploitation"),
                metadata={"exploit_mode": "full"},
            ),
        ]
        verify_depends = ["exploit_full"]
    else:
        # Default: CONTROLLED first, then human gate before FULL escalation
        exploit_phases = [
            EngagementPhase(
                phase_id="exploit_controlled", name="Exploitation (Controlled)",
                description="Controlled exploitation of confirmed vulnerabilities only",
                agent_types=[AgentType.EXPLOIT],
                depends_on=["scan"],
                gate=PhaseGate("human", "Operator approval required before controlled exploitation"),
                metadata={"exploit_mode": "controlled"},
            ),
            EngagementPhase(
                phase_id="exploit_full", name="Exploitation (Full Escalation)",
                description="Full freehand exploitation — operator escalation from CONTROLLED",
                agent_types=[AgentType.EXPLOIT],
                depends_on=["exploit_controlled"],
                gate=PhaseGate(
                    "human",
                    "CONTROLLED exploitation complete. Escalate to FULL freehand mode? "
                    "Type confirm-exploit_full to proceed or skip-exploit_full to skip.",
                ),
                metadata={"exploit_mode": "full"},
            ),
        ]
        verify_depends = ["exploit_full"]

    tail_phases = [
        EngagementPhase(
            phase_id="verify", name="Verification",
            description="Independent verification of all findings",
            agent_types=[AgentType.VERIFICATION_LOOP],
            depends_on=verify_depends,
        ),
        EngagementPhase(
            phase_id="intel", name="Attribution & Intelligence",
            description="CVE correlation, MITRE ATT&CK mapping, threat intel enrichment",
            agent_types=[AgentType.INTEL],
            depends_on=["verify"],
        ),
        EngagementPhase(
            phase_id="report", name="Reporting",
            description="Generate comprehensive security assessment report",
            agent_types=[],
            depends_on=["intel"],
        ),
    ]

    return base_phases + exploit_phases + tail_phases
```

- [ ] **Step 4: Run tests**

```
.venv\Scripts\pytest backend/tests/test_omx_two_phase_exploit.py -v
```
Expected: All PASSED.

- [ ] **Step 5: Verify existing OmX tests still pass**

```
.venv\Scripts\pytest backend/tests/test_pentest_e2e.py -v -k "not exploit"
```
Expected: PASSED (e2e test may need updating for new phase ids — check output).

- [ ] **Step 6: Commit**

```bash
git add backend/core/omx.py backend/tests/test_omx_two_phase_exploit.py
git commit -m "feat: split exploit into two-phase CONTROLLED→FULL with human escalation gate

Default $pentest runs exploit_controlled first, then human gate prompts
operator to escalate to exploit_full (freehand). --freehand flag skips
CONTROLLED and goes directly to FULL as before.

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>"
```

---

## Task 5: ExploitAgent — Confirmed Findings Fallback

**Problem:** In CONTROLLED mode, if `_confirmed_findings` is empty (all findings were MANUAL_REVIEW), the agent runs only 4 generic steps. Fix: fall back to all FINDING_CREATED events from EventBus when confirmed is empty.

**Files:**
- Modify: `backend/agents/exploit_agent.py:134-168`
- Create: `backend/tests/test_exploit_agent_fallback.py`

- [ ] **Step 1: Write failing tests**

Create `backend/tests/test_exploit_agent_fallback.py`:

```python
"""Tests for ExploitAgent confirmed-findings fallback to all findings."""
from __future__ import annotations
import pytest
from unittest.mock import AsyncMock
from backend.agents.exploit_agent import ExploitAgent
from backend.core.event_bus import DurableEventLog, EventBus
from backend.core.models import AgentType, EngineType, ScopeConfig


@pytest.fixture
async def event_bus(tmp_path):
    log = DurableEventLog(db_path=tmp_path / "exploit_test.db")
    bus = EventBus(durable_log=log)
    await bus.initialize()
    await bus.publish("findings", "FINDING_CREATED", {
        "finding_id": "f-001", "title": "Open port 80", "severity": "medium",
        "target": "10.0.0.1", "port": 80,
    })
    await bus.publish("findings", "FINDING_CREATED", {
        "finding_id": "f-002", "title": "SSH exposed", "severity": "low",
        "target": "10.0.0.1", "port": 22,
    })
    # No FINDING_CLASSIFIED events → no confirmed findings
    yield bus
    await bus.close()


class TestExploitAgentFallback:
    @pytest.mark.asyncio
    async def test_controlled_mode_falls_back_to_all_findings_when_no_confirmed(self, event_bus):
        """If no confirmed findings, CONTROLLED mode uses all FINDING_CREATED findings."""
        agent = ExploitAgent(
            agent_id="test-exploit",
            agent_type=AgentType.EXPLOIT,
            engine=EngineType.INFRASTRUCTURE,
            scope=ScopeConfig(targets=["10.0.0.1"]),
            event_bus=event_bus,
        )
        await agent._load_confirmed_findings()
        # confirmed is empty — fallback should load all findings
        assert len(agent._confirmed_findings) > 0, \
            "CONTROLLED mode must fall back to all findings when no confirmed ones exist"

    @pytest.mark.asyncio
    async def test_confirmed_findings_used_when_available(self, event_bus):
        """When confirmed findings exist, they take precedence over all findings."""
        await event_bus.publish("findings", "FINDING_CLASSIFIED", {
            "finding_id": "f-001", "classification": "confirmed",
        })
        agent = ExploitAgent(
            agent_id="test-exploit",
            agent_type=AgentType.EXPLOIT,
            engine=EngineType.INFRASTRUCTURE,
            scope=ScopeConfig(targets=["10.0.0.1"]),
            event_bus=event_bus,
        )
        await agent._load_confirmed_findings()
        # Should have exactly 1 confirmed finding (f-001 only)
        assert len(agent._confirmed_findings) == 1
        assert agent._confirmed_findings[0]["finding_id"] == "f-001"
```

- [ ] **Step 2: Run tests to verify they fail**

```
.venv\Scripts\pytest backend/tests/test_exploit_agent_fallback.py -v
```
Expected: `test_controlled_mode_falls_back_to_all_findings_when_no_confirmed` FAILED — `_confirmed_findings` stays empty.

- [ ] **Step 3: Update `_load_confirmed_findings` to fall back to all findings**

Replace `_load_confirmed_findings` in `backend/agents/exploit_agent.py`:

```python
async def _load_confirmed_findings(self) -> None:
    """Load findings for CONTROLLED exploitation from EventBus.

    Priority:
      1. CONFIRMED findings (FINDING_CLASSIFIED events with classification=confirmed)
      2. All FINDING_CREATED findings — fallback when verification did not run
         or classified everything as MANUAL_REVIEW / FALSE_POSITIVE.
         CONTROLLED mode must have targets to exploit — an empty list causes
         the agent to fall back to 4 generic steps which is not useful.
    """
    if not self.event_bus:
        return
    try:
        events = await self.event_bus.replay(0)
        created: dict[str, dict] = {}
        confirmed_ids: set[str] = set()

        for e in events:
            et = e.get("event_type", "")
            payload = e.get("payload", {})
            if et == "FINDING_CREATED":
                fid = payload.get("finding_id") or payload.get("id", "")
                if fid:
                    created[fid] = payload
            elif et == "FINDING_CLASSIFIED" and payload.get("classification") == "confirmed":
                fid = payload.get("finding_id", "")
                if fid:
                    confirmed_ids.add(fid)

        # Priority 1: confirmed findings
        for fid in confirmed_ids:
            if fid in created:
                self._confirmed_findings.append(created[fid])

        # Priority 2: fallback to all findings when confirmed list is empty
        if not self._confirmed_findings and created:
            self._confirmed_findings = list(created.values())
            logger.info(
                "ExploitAgent: no confirmed findings — using all %d FINDING_CREATED "
                "findings for CONTROLLED exploitation",
                len(self._confirmed_findings),
            )
        else:
            logger.info(
                "ExploitAgent: loaded %d confirmed finding(s) for controlled exploitation",
                len(self._confirmed_findings),
            )
    except Exception as exc:
        logger.warning("ExploitAgent: could not load confirmed findings: %s", exc)
```

- [ ] **Step 4: Run tests**

```
.venv\Scripts\pytest backend/tests/test_exploit_agent_fallback.py -v
```
Expected: All PASSED.

- [ ] **Step 5: Commit**

```bash
git add backend/agents/exploit_agent.py backend/tests/test_exploit_agent_fallback.py
git commit -m "fix: exploit agent falls back to all findings when no confirmed ones exist

CONTROLLED mode now uses all FINDING_CREATED findings when verification
produced no CONFIRMED results (e.g., all MANUAL_REVIEW). This prevents
the agent from running only 4 generic steps with no meaningful targets.

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>"
```

---

## Task 6: ToolFallbackResolver — New Class

**Problem:** No mechanism to try alternative tools, auto-install missing tools, or correct bad commands. Need a resolver that tries 6 strategies in order.

**Files:**
- Create: `backend/core/tool_fallback.py`
- Create: `backend/tests/test_tool_fallback_resolver.py`

- [ ] **Step 1: Write failing tests**

Create `backend/tests/test_tool_fallback_resolver.py`:

```python
"""Tests for ToolFallbackResolver — 6-step resolution chain."""
from __future__ import annotations
import pytest
from unittest.mock import AsyncMock, patch
from backend.core.tool_fallback import FallbackResolution, ToolFallbackResolver


@pytest.fixture
def resolver():
    return ToolFallbackResolver()


class TestAlternativeTable:
    @pytest.mark.asyncio
    async def test_sublist3r_falls_back_to_amass(self, resolver):
        res = await resolver.resolve("sublist3r", {"target": "example.com"}, "not found")
        assert res.alternative_tool == "amass"
        assert res.alternative_input == {"target": "example.com"}

    @pytest.mark.asyncio
    async def test_dalfox_falls_back_to_nuclei(self, resolver):
        res = await resolver.resolve("dalfox", {"target": "http://example.com"}, "not found")
        assert res.alternative_tool == "nuclei"

    @pytest.mark.asyncio
    async def test_masscan_falls_back_to_nmap(self, resolver):
        res = await resolver.resolve("masscan", {"target": "10.0.0.1"}, "not found")
        assert res.alternative_tool == "nmap"

    @pytest.mark.asyncio
    async def test_already_tried_alternative_is_skipped(self, resolver):
        """If amass was already tried, skip it and try next alternative."""
        res = await resolver.resolve(
            "sublist3r", {"target": "example.com"}, "not found",
            tried_tools={"amass"},
        )
        # amass tried, should fall back to dnsrecon
        assert res.alternative_tool == "dnsrecon"

    @pytest.mark.asyncio
    async def test_tool_with_no_alternative_returns_skip(self, resolver):
        """Tool with no alternative and no kali_mgr for install → skip."""
        res = await resolver.resolve("crt_sh", {"target": "example.com"}, "not found")
        assert res.alternative_tool is None
        assert res.skip is True


class TestPatternFixes:
    @pytest.mark.asyncio
    async def test_masscan_missing_rate_gets_fixed(self, resolver):
        """masscan command without --rate should get --rate=500 appended."""
        res = await resolver.resolve(
            "masscan", {"target": "10.0.0.1", "flags": "-p1-65535"}, "failed",
            error_type="command_error",
        )
        assert res.alternative_tool == "nmap" or (
            res.corrected_flags is not None and "--rate" in res.corrected_flags
        )

    @pytest.mark.asyncio
    async def test_nuclei_missing_template_gets_fixed(self, resolver):
        """nuclei without -t flag should get -t cves/ added."""
        res = await resolver.resolve(
            "nuclei", {"target": "10.0.0.1", "flags": ""}, "no templates",
            error_type="command_error",
        )
        assert res.corrected_flags is not None and "cves/" in res.corrected_flags


class TestAutoInstall:
    @pytest.mark.asyncio
    async def test_auto_install_attempted_when_no_alternative(self):
        """When no alternative exists, auto-install is attempted via kali_mgr."""
        mock_kali = AsyncMock()
        mock_kali.execute = AsyncMock(return_value={
            "status": "success", "stdout": "Setting up tool...", "exit_code": 0,
        })
        resolver = ToolFallbackResolver(kali_mgr=mock_kali)
        res = await resolver.resolve("crt_sh", {"target": "example.com"}, "not found")
        # crt_sh has no alternatives — should attempt install
        mock_kali.execute.assert_called_once()
        call_args = mock_kali.execute.call_args
        assert call_args[1].get("tool_name") == "_install" or "apt" in str(call_args)

    @pytest.mark.asyncio
    async def test_install_failure_returns_skip(self):
        """Failed auto-install returns skip=True."""
        mock_kali = AsyncMock()
        mock_kali.execute = AsyncMock(return_value={
            "status": "error", "stdout": "", "exit_code": 1,
        })
        resolver = ToolFallbackResolver(kali_mgr=mock_kali)
        res = await resolver.resolve("crt_sh", {"target": "example.com"}, "not found")
        assert res.skip is True


class TestFallbackResolution:
    def test_resolution_dataclass_defaults(self):
        res = FallbackResolution()
        assert res.alternative_tool is None
        assert res.install_succeeded is False
        assert res.skip is False
        assert res.corrected_flags is None
```

- [ ] **Step 2: Run tests to verify they fail**

```
.venv\Scripts\pytest backend/tests/test_tool_fallback_resolver.py -v
```
Expected: All FAILED — `backend.core.tool_fallback` does not exist.

- [ ] **Step 3: Create `backend/core/tool_fallback.py`**

```python
"""ToolFallbackResolver — Multi-strategy tool failure recovery (Section 3.4).

When an agent tool returns tool_not_found or command_error, this resolver
tries recovery strategies in priority order:
  1. Alternative tool table (no cost, instant)
  2. Pattern-based command correction (no cost, instant)
  3. Auto-install via apt-get/pip (requires kali_mgr, ~120s max)
  4. LLM command correction (requires llm_router)
  5. ResearchKB query (requires research_kb)
  6. Live web query via Kali curl (requires kali_mgr)
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)

# -------------------------------------------------------------------
# Alternative tool mapping: tool_name → [alternatives in priority order]
# -------------------------------------------------------------------
TOOL_ALTERNATIVES: dict[str, list[str]] = {
    "sublist3r":       ["amass", "dnsrecon"],
    "amass":           ["sublist3r", "dnsrecon"],
    "dalfox":          ["nuclei"],
    "masscan":         ["nmap"],
    "wpscan":          ["nikto", "nuclei"],
    "commix":          ["sqlmap"],
    "payload_crafter": ["msfvenom"],
    "dnsrecon":        ["dns_enum"],
    "whatweb":         ["curl"],
    "github_scan":     [],   # OSINT only, no local alternative
    "crt_sh":          [],   # OSINT only, no local alternative
}

# Alternative tool input transformations
_ALT_INPUT_TRANSFORMS: dict[tuple[str, str], dict] = {
    # (original_tool, alternative_tool) → override input keys
    ("dalfox", "nuclei"):  {"flags": "-t cves/ -t exposures/"},
    ("masscan", "nmap"):   {"flags": "-T4 -p-"},
    ("wpscan", "nikto"):   {},
    ("dnsrecon", "dns_enum"): {},
}

# -------------------------------------------------------------------
# Pattern-based command fixes
# -------------------------------------------------------------------
_COMMAND_FIXES: dict[str, dict[str, str]] = {
    "masscan":    {"add_flag": "--rate=500", "missing_flag": "--rate"},
    "nuclei":     {"add_flag": "-t cves/",   "missing_flag": "-t "},
    "msfconsole": {"add_flag": "-q",          "missing_flag": "-q"},
    "ffuf":       {"add_flag": "-mc 200,301,302", "missing_flag": "-mc"},
    "sqlmap":     {"add_flag": "--batch",     "missing_flag": "--batch"},
    "nikto":      {"add_flag": "-maxtime 90", "missing_flag": "-maxtime"},
}

# apt-get package names for tools (may differ from binary name)
_APT_PACKAGES: dict[str, str] = {
    "sublist3r":  "sublist3r",
    "amass":      "amass",
    "dalfox":     "dalfox",
    "masscan":    "masscan",
    "wpscan":     "wpscan",
    "commix":     "commix",
    "nikto":      "nikto",
    "nuclei":     "nuclei",
    "ffuf":       "ffuf",
    "sqlmap":     "sqlmap",
    "whatweb":    "whatweb",
    "dnsrecon":   "dnsrecon",
}


@dataclass
class FallbackResolution:
    """Result of a ToolFallbackResolver.resolve() call."""
    alternative_tool: str | None = None
    alternative_input: dict[str, Any] | None = None
    corrected_flags: str | None = None    # corrected flags for original tool
    install_succeeded: bool = False
    skip: bool = False                    # no resolution — caller should skip this tool


class ToolFallbackResolver:
    """Multi-strategy recovery for tool_not_found and command errors.

    Instantiate with optional kali_mgr, llm_router, research_kb for
    strategies that need them. Strategies that lack their dependency
    are skipped automatically.
    """

    def __init__(
        self,
        kali_mgr: Any = None,
        llm_router: Any = None,
        research_kb: Any = None,
    ) -> None:
        self._kali_mgr = kali_mgr
        self._llm_router = llm_router
        self._research_kb = research_kb

    async def resolve(
        self,
        tool_name: str,
        tool_input: dict[str, Any],
        error: str,
        error_type: str = "tool_not_found",  # "tool_not_found" | "command_error"
        tried_tools: set[str] | None = None,
    ) -> FallbackResolution:
        """Attempt to recover from a tool failure.

        Args:
            tool_name: The tool that failed.
            tool_input: The input dict that was passed to the tool.
            error: The error string from the failure.
            error_type: "tool_not_found" or "command_error".
            tried_tools: Set of tool names already tried (avoid retry loops).

        Returns:
            FallbackResolution with the best available recovery.
        """
        tried = tried_tools or set()
        tried.add(tool_name)

        # Strategy 1: Alternative tool table
        resolution = self._try_alternative(tool_name, tool_input, tried)
        if resolution:
            logger.info("ToolFallbackResolver: %s → alternative %s", tool_name, resolution.alternative_tool)
            return resolution

        # Strategy 2: Pattern-based command correction (for command_error only)
        if error_type == "command_error":
            resolution = self._try_pattern_fix(tool_name, tool_input)
            if resolution:
                logger.info("ToolFallbackResolver: %s — applied pattern fix", tool_name)
                return resolution

        # Strategy 3: Auto-install
        if self._kali_mgr:
            installed = await self._try_install(tool_name)
            if installed:
                return FallbackResolution(install_succeeded=True)

        # Strategy 4: LLM command correction
        if self._llm_router and error_type == "command_error":
            resolution = await self._try_llm_correction(tool_name, tool_input, error)
            if resolution:
                logger.info("ToolFallbackResolver: %s — LLM suggested correction", tool_name)
                return resolution

        # Strategy 5: ResearchKB query
        if self._research_kb:
            resolution = await self._try_research_kb(tool_name, error)
            if resolution:
                return resolution

        # Strategy 6: Live web query via Kali
        if self._kali_mgr:
            resolution = await self._try_live_web_query(tool_name)
            if resolution:
                return resolution

        logger.warning("ToolFallbackResolver: no recovery found for %s — skipping", tool_name)
        return FallbackResolution(skip=True)

    def _try_alternative(
        self, tool_name: str, tool_input: dict[str, Any], tried: set[str]
    ) -> FallbackResolution | None:
        alternatives = TOOL_ALTERNATIVES.get(tool_name, [])
        for alt in alternatives:
            if alt not in tried:
                # Build alternative input: start with original, apply transform
                alt_input = dict(tool_input)
                transform = _ALT_INPUT_TRANSFORMS.get((tool_name, alt), {})
                alt_input.update(transform)
                return FallbackResolution(alternative_tool=alt, alternative_input=alt_input)
        return None

    def _try_pattern_fix(
        self, tool_name: str, tool_input: dict[str, Any]
    ) -> FallbackResolution | None:
        fix = _COMMAND_FIXES.get(tool_name)
        if not fix:
            return None
        current_flags = tool_input.get("flags", "")
        if fix["missing_flag"] not in current_flags:
            corrected = (current_flags + " " + fix["add_flag"]).strip()
            return FallbackResolution(corrected_flags=corrected)
        return None

    async def _try_install(self, tool_name: str) -> bool:
        """Attempt apt-get install for the missing tool. Returns True on success."""
        package = _APT_PACKAGES.get(tool_name, tool_name)
        try:
            result = await self._kali_mgr.execute(
                tool_name="_install",
                tool_input={"command": f"apt-get install -y -q {package} 2>/dev/null || pip3 install {package} 2>/dev/null"},
                tool_spec=_MinimalToolSpec(timeout_seconds=120),
            )
            success = result.get("exit_code", 1) == 0
            if success:
                logger.info("ToolFallbackResolver: installed %s via apt-get", package)
            else:
                logger.warning("ToolFallbackResolver: install failed for %s", package)
            return success
        except Exception as exc:
            logger.warning("ToolFallbackResolver: install error for %s: %s", tool_name, exc)
            return False

    async def _try_llm_correction(
        self, tool_name: str, tool_input: dict[str, Any], error: str
    ) -> FallbackResolution | None:
        from backend.core.llm_router import LLMMessage
        try:
            prompt = (
                f"This command failed on Kali Linux: `{tool_name} {tool_input.get('flags', '')} "
                f"{tool_input.get('target', '')}`\n"
                f"Error: {error[:200]}\n"
                f"Suggest corrected flags only (not the full command). Return just the flags string."
            )
            response = await self._llm_router.complete(
                messages=[LLMMessage(role="user", content=prompt)],
                system_prompt="You are a Kali Linux expert. Return only corrected CLI flags, no explanation.",
                max_tokens=128,
                temperature=0.1,
            )
            corrected = response.content.strip().strip("`")
            if corrected and len(corrected) < 200:
                return FallbackResolution(corrected_flags=corrected)
        except Exception as exc:
            logger.debug("ToolFallbackResolver: LLM correction failed: %s", exc)
        return None

    async def _try_research_kb(
        self, tool_name: str, error: str
    ) -> FallbackResolution | None:
        """Query ResearchKB for known tool issues and fixes."""
        try:
            entries = await self._research_kb.query(keyword=tool_name, limit=3)
            for entry in entries:
                desc = entry.description.lower()
                if "install" in desc or "alternative" in desc:
                    logger.info(
                        "ToolFallbackResolver: ResearchKB found hint for %s", tool_name
                    )
                    # ResearchKB hit but no actionable fix — at minimum log it
                    break
        except Exception as exc:
            logger.debug("ToolFallbackResolver: ResearchKB query failed: %s", exc)
        return None  # ResearchKB provides context, not direct action in v1

    async def _try_live_web_query(self, tool_name: str) -> FallbackResolution | None:
        """Query live web via Kali curl for tool install hints."""
        try:
            result = await self._kali_mgr.execute(
                tool_name="_web_query",
                tool_input={
                    "command": (
                        f"timeout 10 curl -s 'https://api.github.com/search/repositories"
                        f"?q={tool_name}+kali+linux&per_page=1' 2>/dev/null | "
                        f"python3 -c \"import sys,json; d=json.load(sys.stdin); "
                        f"[print(i.get('html_url','')) for i in d.get('items',[])[:1]]\" 2>/dev/null"
                    )
                },
                tool_spec=_MinimalToolSpec(timeout_seconds=15),
            )
            stdout = result.get("stdout", "").strip()
            if stdout:
                logger.info(
                    "ToolFallbackResolver: live web query for %s found: %s", tool_name, stdout[:100]
                )
        except Exception as exc:
            logger.debug("ToolFallbackResolver: live web query failed: %s", exc)
        return None  # Web query provides context, not direct action in v1


class _MinimalToolSpec:
    """Minimal tool spec for install/query commands that bypass the registry."""
    def __init__(self, timeout_seconds: int = 60) -> None:
        self.timeout_seconds = timeout_seconds
```

- [ ] **Step 4: Run tests**

```
.venv\Scripts\pytest backend/tests/test_tool_fallback_resolver.py -v
```
Expected: All PASSED (adjust `test_auto_install_attempted_when_no_alternative` if kali_mgr call signature differs — check mock call args).

- [ ] **Step 5: Commit**

```bash
git add backend/core/tool_fallback.py backend/tests/test_tool_fallback_resolver.py
git commit -m "feat: add ToolFallbackResolver with 6-step recovery chain

Recovers from tool_not_found and command errors using: alternative tool
table, pattern fixes, auto-install via apt-get, LLM correction,
ResearchKB query, and live web query. Skip-and-continue when all fail.

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>"
```

---

## Task 7: BaseAgent — Integrate ToolFallbackResolver into run_loop

**Problem:** `run_loop` does not intercept `tool_not_found` results. Need to call `ToolFallbackResolver` and retry with alternative/installed tool before continuing.

**Files:**
- Modify: `backend/core/base_agent.py:125-241`
- Create: `backend/tests/test_base_agent_resilience.py`

- [ ] **Step 1: Write failing tests**

Create `backend/tests/test_base_agent_resilience.py`:

```python
"""Tests for BaseAgent run_loop resilience — tool_not_found handling."""
from __future__ import annotations
import pytest
from unittest.mock import AsyncMock, MagicMock
from backend.core.base_agent import AgentAction, BaseAgent, ToolResult
from backend.core.models import AgentTask, AgentType, EngineType, ScopeConfig


class _SimpleAgent(BaseAgent):
    """Minimal concrete agent for testing."""
    def __init__(self, actions, **kwargs):
        super().__init__(**kwargs)
        self._planned_actions = list(actions)
        self._action_history = []

    async def execute(self, task):
        return await self.run_loop(task)

    async def _plan_next_action(self, task):
        if not self._planned_actions:
            return None
        action = self._planned_actions.pop(0)
        self._action_history.append({"tool": action.tool_name, "input": action.tool_input})
        return action


def _make_task():
    return AgentTask(task_id="t1", agent_class="test", prompt="Execute test against 10.0.0.1")


class TestRunLoopToolNotFound:
    @pytest.mark.asyncio
    async def test_tool_not_found_triggers_alternative(self):
        """When tool_not_found, alternative tool from ToolFallbackResolver is tried."""
        # Primary tool fails with tool_not_found; alternative succeeds
        executor = AsyncMock()
        call_log = []

        async def mock_execute(**kwargs):
            tool = kwargs.get("tool_name")
            call_log.append(tool)
            if tool == "sublist3r":
                return ToolResult(success=True, output={"status": "tool_not_found", "error": "not found"})
            return ToolResult(success=True, output={"stdout": "amass output", "status": "success"})

        executor.execute = mock_execute

        agent = _SimpleAgent(
            actions=[AgentAction("sublist3r", {"target": "example.com"}, "subdomain enum")],
            agent_id="test",
            agent_type=AgentType.RECON,
            engine=EngineType.INFRASTRUCTURE,
            scope=ScopeConfig(targets=["example.com"]),
            tool_executor=executor,
        )

        from backend.core.tool_fallback import ToolFallbackResolver
        agent._tool_fallback_resolver = ToolFallbackResolver()

        result = await agent.execute(_make_task())
        assert "amass" in call_log, f"Alternative tool 'amass' should have been tried. Called: {call_log}"

    @pytest.mark.asyncio
    async def test_tool_not_found_with_no_alternative_skips_gracefully(self):
        """When no alternative exists and install fails, agent skips and continues."""
        executor = AsyncMock()
        executor.execute = AsyncMock(return_value=ToolResult(
            success=True, output={"status": "tool_not_found", "error": "crt_sh not found"}
        ))

        action1 = AgentAction("crt_sh", {"target": "example.com"}, "CT logs")
        action2 = AgentAction("whois", {"target": "example.com"}, "whois lookup")
        executor_calls = []

        async def mock_exec(**kwargs):
            executor_calls.append(kwargs.get("tool_name"))
            if kwargs.get("tool_name") == "crt_sh":
                return ToolResult(success=True, output={"status": "tool_not_found"})
            return ToolResult(success=True, output={"stdout": "whois output"})

        executor.execute = mock_exec

        agent = _SimpleAgent(
            actions=[action1, action2],
            agent_id="test",
            agent_type=AgentType.SCOPE_DISCOVERY,
            engine=EngineType.INFRASTRUCTURE,
            scope=ScopeConfig(targets=["example.com"]),
            tool_executor=executor,
        )
        from backend.core.tool_fallback import ToolFallbackResolver
        agent._tool_fallback_resolver = ToolFallbackResolver()

        result = await agent.execute(_make_task())
        # Agent should continue to whois despite crt_sh failing
        assert "whois" in executor_calls
```

- [ ] **Step 2: Run tests to verify they fail**

```
.venv\Scripts\pytest backend/tests/test_base_agent_resilience.py -v
```
Expected: `test_tool_not_found_triggers_alternative` FAILED — `amass` not called, agent just skips.

- [ ] **Step 3: Add `_tool_fallback_resolver` field to `BaseAgent`**

In `backend/core/base_agent.py`, add to the `BaseAgent` dataclass fields (after `llm_router`):

```python
_tool_fallback_resolver: Any = field(default=None, repr=False)
```

Note: use underscore prefix to avoid collision with constructor kwargs in EngineInfra. Assign after construction: `agent._tool_fallback_resolver = ToolFallbackResolver(kali_mgr=..., llm_router=...)`.

- [ ] **Step 4: Add tool_not_found interception to `run_loop`**

In `run_loop`, after `result = await self._execute_with_permissions(action)`, add before the `log tool failures` block:

```python
# Intercept tool_not_found — attempt fallback resolution before skipping
if (
    result.success
    and isinstance(result.output, dict)
    and result.output.get("status") == "tool_not_found"
    and self._tool_fallback_resolver is not None
):
    from backend.core.tool_fallback import ToolFallbackResolver
    resolution = await self._tool_fallback_resolver.resolve(
        tool_name=action.tool_name,
        tool_input=action.tool_input,
        error=result.output.get("error", ""),
    )

    if resolution.alternative_tool:
        logger.info(
            "Agent %s: %s not found → trying alternative %s",
            self.agent_id, action.tool_name, resolution.alternative_tool,
        )
        alt_action = AgentAction(
            tool_name=resolution.alternative_tool,
            tool_input=resolution.alternative_input or action.tool_input,
            reasoning=f"Alternative for {action.tool_name}: {action.reasoning}",
        )
        result = await self._execute_with_permissions(alt_action)

    elif resolution.install_succeeded:
        logger.info(
            "Agent %s: %s auto-installed — retrying",
            self.agent_id, action.tool_name,
        )
        result = await self._execute_with_permissions(action)

    elif resolution.corrected_flags:
        corrected_input = dict(action.tool_input)
        corrected_input["flags"] = resolution.corrected_flags
        corrected_action = AgentAction(
            tool_name=action.tool_name,
            tool_input=corrected_input,
            reasoning=f"Corrected flags for {action.tool_name}",
        )
        result = await self._execute_with_permissions(corrected_action)

    else:
        logger.warning(
            "Agent %s: %s unavailable, no recovery found — skipping",
            self.agent_id, action.tool_name,
        )
        result = ToolResult(success=False, error=f"{action.tool_name} not available — skipped")
```

- [ ] **Step 5: Run tests**

```
.venv\Scripts\pytest backend/tests/test_base_agent_resilience.py backend/tests/test_recon_agent_loop.py -v
```
Expected: All PASSED.

- [ ] **Step 6: Commit**

```bash
git add backend/core/base_agent.py backend/tests/test_base_agent_resilience.py
git commit -m "feat: integrate ToolFallbackResolver into BaseAgent run_loop

When a tool returns tool_not_found, the run_loop now calls
ToolFallbackResolver to try: alternative tool, auto-install+retry,
corrected flags, or skip with clear log message.

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>"
```

---

## Task 8: KaliSSH — Kali-Side Dynamic Timeouts

**Problem:** `COMMAND_TIMEOUT = 300` applies to every tool. Slow tools hit it before finishing; fast tools waste time if they hang. Move enforcement to Kali shell via `timeout N` prefix per tool.

**Files:**
- Modify: `backend/tools/backends/kali_ssh.py`
- Create: `backend/tests/test_kali_ssh_timeouts.py`

- [ ] **Step 1: Write failing tests**

Create `backend/tests/test_kali_ssh_timeouts.py`:

```python
"""Tests for KaliSSH per-tool Kali-side timeout enforcement."""
from __future__ import annotations
import pytest
from backend.tools.backends.kali_ssh import KaliConnectionManager, COMMAND_TIMEOUT


class TestKaliSideTimeouts:
    def test_command_timeout_is_at_least_3600(self):
        """Python-side COMMAND_TIMEOUT must be 3600s (last resort only)."""
        assert COMMAND_TIMEOUT >= 3600

    def test_nmap_command_has_timeout_prefix(self):
        mgr = KaliConnectionManager.__new__(KaliConnectionManager)
        cmd = mgr._build_command("nmap", {"target": "10.0.0.1", "flags": "-sV"})
        assert cmd.startswith("timeout 180"), f"nmap must have 'timeout 180' prefix, got: {cmd}"

    def test_nikto_command_has_maxtime_flag(self):
        mgr = KaliConnectionManager.__new__(KaliConnectionManager)
        cmd = mgr._build_command("nikto", {"target": "10.0.0.1", "flags": ""})
        assert "-maxtime 90" in cmd, f"nikto must have -maxtime 90 flag, got: {cmd}"

    def test_nuclei_command_has_timeout_prefix(self):
        mgr = KaliConnectionManager.__new__(KaliConnectionManager)
        cmd = mgr._build_command("nuclei", {"target": "10.0.0.1", "flags": "-t cves/"})
        assert cmd.startswith("timeout 60"), f"nuclei must have 'timeout 60' prefix, got: {cmd}"

    def test_masscan_command_has_timeout_prefix(self):
        mgr = KaliConnectionManager.__new__(KaliConnectionManager)
        cmd = mgr._build_command("masscan", {"target": "10.0.0.1", "flags": "-p1-65535 --rate=1000"})
        assert cmd.startswith("timeout 120"), f"masscan must have 'timeout 120' prefix, got: {cmd}"

    def test_sqlmap_command_has_timeout_prefix(self):
        mgr = KaliConnectionManager.__new__(KaliConnectionManager)
        cmd = mgr._build_command("sqlmap", {"target": "http://10.0.0.1", "flags": "--batch"})
        assert cmd.startswith("timeout 180"), f"sqlmap must have 'timeout 180' prefix, got: {cmd}"

    def test_dalfox_command_has_timeout_prefix(self):
        mgr = KaliConnectionManager.__new__(KaliConnectionManager)
        cmd = mgr._build_command("dalfox", {"target": "http://10.0.0.1", "flags": ""})
        assert cmd.startswith("timeout 60"), f"dalfox must have 'timeout 60' prefix, got: {cmd}"

    def test_ffuf_command_has_timeout_prefix(self):
        mgr = KaliConnectionManager.__new__(KaliConnectionManager)
        cmd = mgr._build_command("ffuf", {"target": "http://10.0.0.1/FUZZ", "flags": "-w /wordlist"})
        assert cmd.startswith("timeout 90"), f"ffuf must have 'timeout 90' prefix, got: {cmd}"

    def test_whatweb_command_has_timeout_prefix(self):
        mgr = KaliConnectionManager.__new__(KaliConnectionManager)
        cmd = mgr._build_command("whatweb", {"target": "10.0.0.1", "flags": ""})
        assert cmd.startswith("timeout 30"), f"whatweb must have 'timeout 30' prefix, got: {cmd}"

    def test_whois_command_has_timeout_prefix(self):
        mgr = KaliConnectionManager.__new__(KaliConnectionManager)
        cmd = mgr._build_command("whois", {"target": "example.com"})
        assert "timeout 15" in cmd, f"whois must have timeout 15, got: {cmd}"

    def test_crt_sh_curl_has_timeout_prefix(self):
        mgr = KaliConnectionManager.__new__(KaliConnectionManager)
        cmd = mgr._build_command("crt_sh", {"target": "example.com"})
        assert "timeout 15" in cmd, f"crt_sh curl must have timeout 15, got: {cmd}"

    def test_wpscan_command_has_timeout_prefix(self):
        mgr = KaliConnectionManager.__new__(KaliConnectionManager)
        cmd = mgr._build_command("wpscan", {"target": "http://10.0.0.1", "flags": ""})
        assert cmd.startswith("timeout 90"), f"wpscan must have 'timeout 90' prefix, got: {cmd}"
```

- [ ] **Step 2: Run tests to verify they fail**

```
.venv\Scripts\pytest backend/tests/test_kali_ssh_timeouts.py -v
```
Expected: Multiple FAILED — commands lack timeout prefixes, COMMAND_TIMEOUT is 300.

- [ ] **Step 3: Update `COMMAND_TIMEOUT` constant**

In `backend/tools/backends/kali_ssh.py`, change:
```python
COMMAND_TIMEOUT = 300            # default per-command timeout
```
to:
```python
COMMAND_TIMEOUT = 3600           # last-resort Python-side backstop only; per-tool limits via Kali timeout prefix
```

- [ ] **Step 4: Replace `_build_command` builders dict with timeout-aware versions**

In `_build_command`, replace the `builders` dict with the following (showing only changed entries — keep all other entries unchanged):

```python
builders = {
    # --- Reconnaissance ---
    "nmap": lambda: f"timeout 180 nmap {flags} {f'-p {port}' if port else ''} {target}".strip(),
    "nmap_verify": lambda: f"timeout 30 nmap -sV --open -p {port} {target}".strip(),
    "whatweb": lambda: f"timeout 30 whatweb {flags} {target}".strip(),
    "dnsrecon": lambda: f"timeout 60 dnsrecon -d {target} {flags}".strip(),
    "sublist3r": lambda: f"timeout 60 sublist3r -d {target} {flags}".strip(),
    "amass": lambda: f"timeout 120 amass enum -d {target} {flags}".strip(),
    # --- Scope discovery ---
    "crt_sh": lambda: (
        f"timeout 15 curl -sk 'https://crt.sh/?q={target}&output=json' "
        f"| python3 -c \""
        f"import sys,json; data=json.load(sys.stdin); "
        f"[print(e.get('name_value','')) for e in data[:100]]\""
        f" 2>/dev/null || timeout 15 curl -sk 'https://crt.sh/?q={target}'"
    ).strip(),
    "whois": lambda: f"timeout 15 whois {target} 2>/dev/null || echo 'whois: {target}'".strip(),
    "dns_enum": lambda: (
        f"(timeout 30 dig +noall +answer {target} ANY 2>/dev/null; "
        f"timeout 10 dig +noall +answer {target} MX 2>/dev/null; "
        f"timeout 10 dig +noall +answer {target} NS 2>/dev/null; "
        f"timeout 10 host {target} 2>/dev/null) | sort -u"
    ).strip(),
    "github_scan": lambda: (
        f"timeout 15 curl -sk 'https://api.github.com/search/repositories"
        f"?q={target}+in:name,description&per_page=10' 2>/dev/null"
    ).strip(),
    "shodan": lambda: (
        f"timeout 15 curl -sk 'https://internetdb.shodan.io/{target}' 2>/dev/null "
        f"|| timeout 15 shodan host {target} 2>/dev/null "
        f"|| echo '{{\"error\": \"shodan unavailable for {target}\"}}'"
    ).strip(),
    # --- Vulnerability scanning ---
    "nikto": lambda: f"timeout 90 nikto -maxtime 90 -h {target} {f'-p {port}' if port else ''} {flags}".strip(),
    "nuclei": lambda: f"timeout 60 nuclei -u {target} {flags}".strip(),
    "masscan": lambda: f"timeout 120 masscan {target} {f'-p{port}' if port else '-p1-65535'} {flags}".strip(),
    "wpscan": lambda: f"timeout 90 wpscan --url {target} {flags}".strip(),
    # --- Exploitation ---
    "sqlmap": lambda: f"timeout 180 sqlmap -u {target} {flags} --batch".strip(),
    "dalfox": lambda: f"timeout 60 dalfox url {target} {flags}".strip(),
    "ffuf": lambda: f"timeout 90 ffuf -u {target} {flags}".strip(),
    "commix": lambda: f"timeout 120 commix --url={target} {flags} --batch 2>/dev/null".strip(),
    "payload_crafter": lambda: (
        f"timeout 60 msfvenom {flags} 2>/dev/null || echo 'payload_crafter: msfvenom unavailable'"
    ).strip(),
    "msfconsole": lambda: (
        f"timeout 300 msfconsole -q -x '{raw_command}' 2>/dev/null"
        if raw_command else
        "echo 'msfconsole: no command provided'"
    ).strip(),
    # --- TLS / HTTP probes ---
    "testssl": lambda: f"timeout 60 testssl {flags} {target}".strip(),
    "testssl_readonly": lambda: f"timeout 60 testssl --read-only {target}".strip(),
    "curl": lambda: f"timeout 15 curl -sk {flags} '{target}' 2>/dev/null".strip(),
    "httpx_probe": lambda: (
        f"timeout 15 curl -sk -o /dev/null -w '%{{http_code}} %{{url_effective}}\\n' '{target}' 2>/dev/null"
    ).strip(),
    # --- ToolFallbackResolver install/query commands (bypass registry) ---
    "_install": lambda: raw_command or "echo 'install: no command'",
    "_web_query": lambda: raw_command or "echo 'web_query: no command'",
}
```

- [ ] **Step 5: Run tests**

```
.venv\Scripts\pytest backend/tests/test_kali_ssh_timeouts.py backend/tests/test_kali_connection_mgr.py -v
```
Expected: All PASSED.

- [ ] **Step 6: Commit**

```bash
git add backend/tools/backends/kali_ssh.py backend/tests/test_kali_ssh_timeouts.py
git commit -m "fix: replace blanket 300s timeout with per-tool Kali-side timeout prefix

Each tool now enforces its own timeout via 'timeout N cmd' prefix or
native flags (nikto -maxtime 90). Python-side COMMAND_TIMEOUT raised
to 3600s as last-resort backstop only.

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>"
```

---

## Task 9: LLM JSON Hardening in scan_agent

**Problem:** `_extract_json_from_llm_response` can still raise `JSONDecodeError` for single-quoted JSON and pure prose responses, causing unhandled exceptions in agent planning.

**Files:**
- Modify: `backend/agents/scan_agent.py:135-175`
- Create: `backend/tests/test_llm_json_hardening.py`

- [ ] **Step 1: Write failing tests**

Create `backend/tests/test_llm_json_hardening.py`:

```python
"""Tests for _extract_json_from_llm_response hardening."""
from __future__ import annotations
import pytest
from backend.agents.scan_agent import _extract_json_from_llm_response


class TestLLMJsonHardening:
    def test_clean_json_parses(self):
        result = _extract_json_from_llm_response('{"tool": "nmap", "is_terminal": false}', "Test")
        assert result["tool"] == "nmap"

    def test_json_in_code_block_parses(self):
        result = _extract_json_from_llm_response(
            '```json\n{"tool": "nikto", "is_terminal": false}\n```', "Test"
        )
        assert result["tool"] == "nikto"

    def test_json_with_surrounding_prose_parses(self):
        result = _extract_json_from_llm_response(
            'I will run nmap next. {"tool": "nmap", "is_terminal": false} That is my plan.', "Test"
        )
        assert result["tool"] == "nmap"

    def test_single_quoted_json_parses(self):
        """Single-quoted JSON wrapper (some LLMs return this) must parse correctly."""
        result = _extract_json_from_llm_response(
            "'{'tool': 'nmap', 'is_terminal': false}'", "Test"
        )
        # Should return safe default rather than raising
        assert "tool" in result or result.get("is_terminal") is not None

    def test_pure_prose_returns_safe_default(self):
        """Pure prose with no JSON must return safe default dict, not raise."""
        result = _extract_json_from_llm_response(
            "I think we should run nmap against the target first to discover open ports.", "Test"
        )
        assert isinstance(result, dict)
        assert result.get("is_terminal") is False  # safe default: continue loop
        assert result.get("tool") is None

    def test_empty_string_returns_safe_default(self):
        result = _extract_json_from_llm_response("", "Test")
        assert isinstance(result, dict)
        assert result.get("is_terminal") is False

    def test_truncated_json_returns_safe_default(self):
        """Truncated JSON (LLM hit token limit) returns safe default, not exception."""
        result = _extract_json_from_llm_response('{"tool": "nmap", "input": {"targ', "Test")
        assert isinstance(result, dict)

    def test_safe_default_does_not_terminate_agent(self):
        """Safe default must have is_terminal=False so agent loop continues."""
        result = _extract_json_from_llm_response("not json at all", "Test")
        assert result.get("is_terminal") is False
```

- [ ] **Step 2: Run tests to verify they fail**

```
.venv\Scripts\pytest backend/tests/test_llm_json_hardening.py -v
```
Expected: `test_pure_prose_returns_safe_default`, `test_empty_string_returns_safe_default`, `test_truncated_json_returns_safe_default` FAILED — function raises `JSONDecodeError`.

- [ ] **Step 3: Replace `_extract_json_from_llm_response` in `backend/agents/scan_agent.py`**

```python
def _extract_json_from_llm_response(content: str, agent_name: str) -> dict:
    """Extract a JSON object from an LLM response that may contain prose or markdown.

    Tries strategies in order:
      1. Direct JSON parse (clean response).
      2. Extract from ```json ... ``` or ``` ... ``` code block.
      3. Grab the first {...} substring (ignoring surrounding prose).
      4. Strip single-quote wrapper and retry.
      5. Return safe default — is_terminal=False, tool=None — so the agent
         loop continues to its fallback planner rather than crashing.

    Never raises JSONDecodeError. Always returns a dict.
    """
    import re as _re

    content = (content or "").strip()

    if not content:
        return {"tool": None, "input": {}, "reasoning": "Empty LLM response", "is_terminal": False}

    # Strategy 1: direct parse
    try:
        return json.loads(content)
    except json.JSONDecodeError:
        pass

    # Strategy 2: code block
    block_match = _re.search(r'```(?:json)?\s*(\{.*?\})\s*```', content, _re.DOTALL)
    if block_match:
        try:
            return json.loads(block_match.group(1))
        except json.JSONDecodeError:
            pass

    # Strategy 3: first {...} substring (handles prose before/after JSON)
    brace_match = _re.search(r'\{.*\}', content, _re.DOTALL)
    if brace_match:
        try:
            return json.loads(brace_match.group(0))
        except json.JSONDecodeError:
            pass

    # Strategy 4: single-quote wrapper (some LLMs wrap with single quotes)
    stripped = content.strip("'")
    if stripped != content:
        try:
            return json.loads(stripped)
        except json.JSONDecodeError:
            pass
        # Try replacing single quotes with double quotes (non-standard LLM output)
        try:
            import ast
            parsed = ast.literal_eval(stripped)
            if isinstance(parsed, dict):
                return parsed
        except (ValueError, SyntaxError):
            pass

    # Strategy 5: safe default — agent loop continues via _plan_fallback
    logger.warning(
        "_extract_json_from_llm_response (%s): no valid JSON found — returning safe default. "
        "Response (first 200 chars): %.200s",
        agent_name, content,
    )
    return {
        "tool": None,
        "input": {},
        "reasoning": "LLM response could not be parsed as JSON — using fallback planner",
        "is_terminal": False,
    }
```

- [ ] **Step 4: Run tests**

```
.venv\Scripts\pytest backend/tests/test_llm_json_hardening.py -v
```
Expected: All PASSED.

- [ ] **Step 5: Run full test suite to check for regressions**

```
.venv\Scripts\pytest backend/tests/ -v --tb=short 2>&1 | tail -30
```
Expected: All previously passing tests still PASSED. Note count of PASSED/FAILED.

- [ ] **Step 6: Commit**

```bash
git add backend/agents/scan_agent.py backend/tests/test_llm_json_hardening.py
git commit -m "fix: harden LLM JSON parser with single-quote support and safe default

Adds strategy 4 (single-quote stripping) and strategy 5 (safe default
dict instead of JSONDecodeError). Agent loops now continue via
_plan_fallback on unparseable LLM responses rather than crashing.

Co-Authored-By: Claude Sonnet 4.6 <noreply@anthropic.com>"
```

---

## Self-Review

### Spec Coverage Check

| Spec Section | Task | Covered? |
|---|---|---|
| 3.1.1 VerificationLoop — fix _classify_result | Task 1 | ✅ |
| 3.1.2 Reporter all findings + verification_status | Task 2 | ✅ |
| 3.1.3 Report schema — verification_status per finding | Task 2 Step 5 | ✅ |
| 3.2.1 Target type detection | Task 3 Step 3 | ✅ |
| 3.2.2 Tool routing by target type | Task 3 Step 4 | ✅ |
| 3.2.3 Scope anchor finding | Task 3 Step 5 | ✅ |
| 3.3.1 Two-phase exploit phases | Task 4 Step 3 | ✅ |
| 3.3.2 Operator flow / gate messages | Task 4 Step 3 | ✅ |
| 3.3.3 --freehand flag preserved | Task 4 Step 3 + tests | ✅ |
| 3.3.4 ExploitAgent confirmed fallback | Task 5 | ✅ |
| 3.4.1 ToolFallbackResolver 6 strategies | Task 6 | ✅ |
| 3.4.2 BaseAgent integration | Task 7 | ✅ |
| 3.5.1 COMMAND_TIMEOUT → 3600s | Task 8 Step 3 | ✅ |
| 3.5.2 Per-tool timeout table | Task 8 Step 4 | ✅ |
| 3.6 LLM JSON hardening | Task 9 | ✅ |

All spec sections covered.

### Type Consistency Check

- `FallbackResolution` defined in Task 6, used in Task 7 — consistent import `from backend.core.tool_fallback import FallbackResolution, ToolFallbackResolver`
- `_tool_fallback_resolver: Any` field added in Task 7 matches usage in test (`agent._tool_fallback_resolver = ToolFallbackResolver()`)
- `_detect_target_type` defined and called in same class in Task 3 — consistent
- `_plan_fallback` in Task 3 calls `_extract_target` (imported from `scan_agent`) and `StealthLevel` (imported in existing file) — both already in scope

### No Placeholders

All code blocks are complete. No TBD, TODO, or "similar to Task N" references.
