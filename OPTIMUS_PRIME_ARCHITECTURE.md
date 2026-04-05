# Optimus Prime — Complete Architecture Document

## Universal AI Security Platform Built on Agentic Foundations

**Version:** 1.0
**Status:** Authoritative — supersedes all prior Optimus plan documents
**Engines:** 3 | **Security Domains:** 13 | **Features:** 7 | **Issues:** 41

---

## Table of Contents

1. [Executive Summary](#1-executive-summary)
2. [Core Philosophy](#2-core-philosophy)
3. [Three-Layer Coordination System](#3-three-layer-coordination-system)
4. [Engine Architecture](#4-engine-architecture)
5. [Agent System](#5-agent-system)
6. [Tool System](#6-tool-system)
7. [Permission and Safety Architecture](#7-permission-and-safety-architecture)
8. [Session Management and Persistence](#8-session-management-and-persistence)
9. [Memory Architecture](#9-memory-architecture)
10. [Event Bus Architecture](#10-event-bus-architecture)
11. [Hook System](#11-hook-system)
12. [LLM Routing and Token Management](#12-llm-routing-and-token-management)
13. [Verification and Review Architecture](#13-verification-and-review-architecture)
14. [Collaboration and RBAC](#14-collaboration-and-rbac)
15. [Research and Strategy Evolution](#15-research-and-strategy-evolution)
16. [Reporting Architecture](#16-reporting-architecture)
17. [Deployment Architecture](#17-deployment-architecture)
18. [Build Sequence](#18-build-sequence)
19. [Risk Register](#19-risk-register)
20. [Success Metrics](#20-success-metrics)
21. [Decision Record](#21-decision-record)

---

## 1. Executive Summary

Optimus Prime is a universal AI security platform — a conversational, agentic co-pilot that conducts professional-grade security assessments across all 13 major cybersecurity domains. It is built on a three-layer agentic coordination architecture designed for autonomous security operations.

The architecture separates concerns into three layers:

- **OmX (Workflow Layer)** — converts operator directives into structured security engagement protocols
- **clawhip (Event Router)** — keeps monitoring, delivery, and cross-agent signaling outside agent context windows
- **OmO (Multi-Agent Coordination)** — handles planning, handoffs, disagreement resolution, and verification loops across security sub-agents

Every security sub-agent inherits from a `BaseAgent` ABC that carries agentic execution patterns (loop guards, auto-compaction, hook integration) merged with security-specific patterns (engine assignment, tool namespacing, scope enforcement, stealth awareness, credential vault access).

### Coverage — 13 Security Domains

| Field | Engine | Sub-agent |
|-------|--------|-----------|
| Network security | Engine 1 — Optimus Infra | ReconAgent, ScanAgent |
| Application security | Engine 1 | ScanAgent, ExploitAgent |
| Endpoint security | Engine 1 | EndpointAgent |
| Cloud security | Engine 1 | CloudAgent |
| IAM | Engine 1 | IAMAgent |
| Data security and privacy | Engine 1 | DataSecAgent |
| IoT / OT / ICS | Engine 2 — Optimus ICS | ICSAgent (stub) |
| Adversarial ML | Engine 3 — Optimus AI | ModelSecAgent |
| Data poisoning / backdoor | Engine 3 | ModelSecAgent |
| Model privacy and extraction | Engine 3 | ModelSecAgent |
| Generative AI security | Engine 3 | GenAIAgent |
| AI-enabled offense | Engine 1 + 3 | ExploitAgent + GenAIAgent |
| Defensive AI evasion | Engine 3 | GenAIAgent |

### The 7 Standout Features

| # | Feature | Core Capability |
|---|---------|-----------------|
| F1 | Auto Research and Strategy Evolution | Nightly daemon ingests 7 sources. StrategyEvolutionEngine synthesises research into better chains. CustomToolGenerator writes and validates novel exploit tools. |
| F2 | Client Profiles and Engagement Memory | Per-client persistent profile: tech stack, recurring weaknesses, remediation history, report preferences. Auto-match on new engagements. |
| F3 | Autonomous Verification Loop | Every finding verified autonomously before reporting. CONFIRMED / FALSE_POSITIVE / MANUAL_REVIEW classification. Implements OmO Reviewer role. |
| F4 | Real-time Collaboration (RBAC) | Multi-user sessions on local LAN. Full RBAC. Pre-configured in .env. In-session role elevation. Event delivery via clawhip pattern. |
| F5 | Threat Intelligence and Attribution | Every finding linked to threat actor TTPs via MITRE ATT&CK + CISA KEV. Optional commercial TI feed. Dark web attribution via Tor. |
| F6 | Report Mode Suite | 6 formats: Executive, Technical, Remediation Roadmap, Developer Handoff, Compliance Mapping, Regression. 5 frameworks: GDPR, PCI-DSS, ISO 27001, SOC 2, NIST CSF. |
| F7 | Autonomous Scope Discovery | Passive-only enumeration from seed. Full operator review and approval before any active testing. |

---

## 2. Core Philosophy

> **"Operators set direction; agents perform the labor."**

This is the founding principle of the agentic architecture — adapted for security operations. The operator is a security professional who provides:

- **Architectural clarity** — what is the target, what are the constraints
- **Task decomposition judgment** — which domains matter for this engagement
- **Taste and conviction** — what risk appetite, what stealth level, which compliance frameworks
- **Approval gates** — scope approval, tool promotion, finding review

The agents handle everything else: reconnaissance, scanning, exploitation, verification, attribution, reporting.

**The bottleneck is no longer scanning speed.** When agent systems can assess an entire attack surface in hours, the scarce resource becomes the operator's judgment about what matters, what to pursue, and when to stop.

### Direction vs Labor Separation

| Operator (Direction) | Agents (Labor) |
|---------------------|----------------|
| Define target scope | Passive scope discovery and enumeration |
| Set stealth level and constraints | Select rate-limited, stealth-appropriate tools |
| Approve discovered assets | Execute active scanning on approved assets only |
| Review MANUAL_REVIEW findings | Autonomously verify CONFIRMED and FALSE_POSITIVE |
| Approve custom tool promotion | Generate, sandbox-test, and track tool effectiveness |
| Select report format and framework | Generate full reports with compliance mappings |
| Provide cloud credentials | Inject via CredentialVault — never logged, never in XAI |

---

## 3. Three-Layer Coordination System

```
Operator Direction
(Chat UI / WebSocket)
        |
        v
+-------------------+
|  OmX Workflow     |  Converts directives into structured engagement protocols
|  Planner          |  Planning keywords: $pentest, $cloud-audit, $genai-probe
+-------------------+
        |
        v
+-------------------+     +-------------------+
|  OmO Multi-Agent  |<--->|  clawhip Event    |
|  Coordinator      |     |  Router           |
|                   |     |                   |
|  Architect role:  |     |  Monitors:        |
|    Orchestrator   |     |    Agent lifecycle |
|    EngineRouter   |     |    Finding events  |
|    StrategyEngine |     |    Intel events    |
|                   |     |    Phase changes   |
|  Executor role:   |     |                   |
|    All sub-agents |     |  Delivers to:     |
|                   |     |    Frontend WS     |
|  Reviewer role:   |     |    CollabWS (RBAC) |
|    Verification   |     |    XAI audit trail |
|    ExplainableAI  |     |    Research daemon |
+-------------------+     +-------------------+
        |                         |
        v                         v
+------------------------------------------+
|         Agent Execution Context           |
|  BaseAgent -> ToolExecutor -> HookRunner  |
|  -> PermissionEnforcer -> EventBus        |
+------------------------------------------+
        |
        v
+------------------------------------------+
|         Tool Backends                     |
|  Local | Kali SSH | ml-runtime IPC |      |
|  Tor SOCKS5 | Sandbox (on-demand)        |
+------------------------------------------+
```

### 3.1 OmX — Security Workflow Planner

OmX converts operator directives into structured execution protocols. In Optimus Prime, it is the engagement planner that decomposes a natural language instruction into a phased, multi-agent security workflow.

**Planning keywords** become security workflow templates:

| Keyword | Workflow |
|---------|----------|
| `$pentest` | Full penetration test: scope discovery -> recon -> scan -> exploit -> verify -> report |
| `$cloud-audit` | Cloud security assessment: credential setup -> CloudAgent (ScoutSuite/Prowler/Pacu) -> verify -> report |
| `$genai-probe` | GenAI security: target type detection -> Promptfoo OWASP preset -> canary injection -> RAG poison test -> report |
| `$recon` | Reconnaissance only: passive enum -> active recon -> no exploitation |
| `$scope-discover` | Scope discovery: CT logs, WHOIS, Shodan, DNS, GitHub -> operator approval |
| `$iam-audit` | IAM assessment: jwt-tool, oauthscan, saml-raider -> verify -> report |
| `$endpoint` | Endpoint assessment: MSF post-exploit -> priv-esc -> LOtL -> AV bypass -> report |

**Execution modes** map to the three engines:

| Mode | Engine | Dispatch Condition |
|------|--------|--------------------|
| Infrastructure | Engine 1 — Optimus Infra | Default for IP/domain/URL/cloud targets |
| Industrial | Engine 2 — Optimus ICS | Modbus/DNP3/SCADA targets (stub — notification only) |
| AI/ML | Engine 3 — Optimus AI | Model file, API endpoint, LLM, RAG pipeline targets |

**Verification loops** — OmX's persistent verification pattern becomes the Autonomous Verification Loop (F3). Every workflow ends with verification before reporting. No finding reaches a report without a CONFIRMED, FALSE_POSITIVE, or MANUAL_REVIEW classification.

**Example decomposition:**

```
Operator: "Audit acme.com — cloud + app security, stealth mode"

OmX Workflow Planner decomposes into:

Phase 1 — Scope Discovery (passive, stealth_level: high)
  Agent: ScopeDiscoveryAgent
  Tools: crt.sh, WHOIS, DNS enum (Shodan SKIPPED at stealth: high)
  Gate: Operator approval required

Phase 2 — Reconnaissance (on approved assets)
  Agents: ReconAgent + IntelAgent (parallel)
  Tools: nmap (rate-limited), whatweb
  IntelAgent: concurrent CVE correlation

Phase 3 — Application Scanning
  Agent: ScanAgent
  Tools: nikto, nuclei, wpscan
  Parallel: IntelAgent enriches findings in real-time via EventBus

Phase 4 — Cloud Assessment
  Agent: CloudAgent
  Tools: ScoutSuite, Prowler
  Credentials: injected via CredentialVault

Phase 5 — Exploitation (validated only)
  Agent: ExploitAgent
  Tools: sqlmap, dalfox, commix, ffuf
  StrategyEvolutionEngine: enriches exploit chains with ResearchKB

Phase 6 — Verification
  Agent: VerificationLoop (OmO Reviewer role)
  Classification: CONFIRMED / FALSE_POSITIVE / MANUAL_REVIEW
  Scope: benign proof + minimal data extraction only

Phase 7 — Attribution
  Agent: ThreatAttributionEngine
  Sources: ATT&CK, CISA KEV, ResearchKB, dark web (if available)

Phase 8 — Reporting
  Agent: IntelligentReporter
  Format: operator-selected (default: Technical)
  Output: WeasyPrint PDF
```

### 3.2 clawhip — Unified Event Router

clawhip keeps monitoring and delivery outside the coding agent's context window. In Optimus Prime, this means security sub-agents stay focused on their tool execution — they never format status messages, deliver WebSocket frames, or poll for cross-agent signals.

clawhip manages all event routing through the unified EventBus (Section 10). It monitors:

- Agent lifecycle events (spawning, running, finished, failed)
- Finding creation and verification state changes
- Intel enrichment events (CVE correlation, ATT&CK mapping)
- Phase transitions in the engagement workflow
- Research daemon alerts (new CVEs, PoCs, technique deltas)
- Collaboration events (user joins, role elevation, commands)

clawhip delivers to:

- Frontend WebSocket — streaming tokens, finding cards, intel feed
- CollabWebSocket — role-filtered broadcast (Lead/Analyst/Observer)
- XAI audit trail — every decision logged with reasoning
- Research daemon — new findings trigger research context queries

**Key benefit:** An ExploitAgent running sqlmap against a target never has its context window polluted with "Broadcast finding to 3 users" or "Update progress bar to 67%". It produces a finding, publishes to EventBus, and clawhip handles everything else.

### 3.3 OmO — Security Agent Coordination

OmO handles planning, handoffs, disagreement resolution, and verification loops across agents. In Optimus Prime, its three roles map to:

| OmO Role | Optimus Prime Implementation | Responsibility |
|----------|------------------------------|----------------|
| **Architect** | Orchestrator + EngineRouter + StrategyEvolutionEngine | Task decomposition, engine selection, exploit chain planning, research-backed strategy |
| **Executor** | All sub-agents (ReconAgent, ScanAgent, ExploitAgent, CloudAgent, IAMAgent, DataSecAgent, EndpointAgent, ModelSecAgent, GenAIAgent) | Tool execution against targets within namespace and scope |
| **Reviewer** | VerificationLoop + ExplainableAI | Finding verification, false positive elimination, XAI audit trail |

**Disagreement resolution protocol:**

When agents produce conflicting results, OmO applies structured convergence:

1. **Identify disagreement** — ScanAgent rates a finding HIGH; ExploitAgent cannot reproduce
2. **Gather additional context** — VerificationLoop runs autonomous re-test with different technique
3. **Classify** — CONFIRMED (reproduced), FALSE_POSITIVE (not reproducible), MANUAL_REVIEW (ambiguous)
4. **Escalate if needed** — MANUAL_REVIEW findings surfaced to operator in chat
5. **Record decision** — XAI log entry with full reasoning chain for audit trail
6. **Continue execution** — workflow proceeds with classified finding

**Handoff protocol:**

Agents hand off work through the TaskRegistry:

```
ReconAgent completes -> publishes findings to EventBus
    |
OmO Coordinator receives lifecycle event
    |
Creates ScanAgent task in TaskRegistry (status: Created)
    |
ScanAgent picks up task (status: Running)
    |
ScanAgent completes -> publishes findings (status: Completed)
    |
OmO Coordinator routes to ExploitAgent or VerificationLoop
```

---

## 4. Engine Architecture

### 4.1 EngineInterface ABC

Every engine implements a common interface based on the tool executor pattern:

```python
class EngineInterface(ABC):
    """Base interface for all Optimus Prime execution engines."""

    engine_type: EngineType          # INFRASTRUCTURE, ICS, MLAI
    agents: list[type[BaseAgent]]    # Registered agent classes
    status: EngineStatus             # ACTIVE, STUB, DISABLED

    @abstractmethod
    async def dispatch(self, task: EngineTask) -> EngineResult:
        """Route a task to the appropriate sub-agent."""
        ...

    @abstractmethod
    async def get_available_agents(self) -> list[AgentSpec]:
        """Return agent specs for Orchestrator planning."""
        ...
```

### 4.2 EngineRouter

The EngineRouter detects target type and dispatches to the correct engine:

```python
class EngineRouter:
    """Routes tasks to Engine 1, 2, or 3 based on target characteristics."""

    engines: dict[EngineType, EngineInterface]

    async def route(self, target: Target) -> EngineInterface:
        if target.is_modbus or target.is_dnp3 or target.is_scada:
            engine = self.engines[EngineType.ICS]
            if engine.status == EngineStatus.STUB:
                # Surface notification — no execution
                await self.event_bus.publish("lifecycle", ICSNotification(target))
                raise ICSStubError("ICS engine is stub-only. No tool execution.")
            return engine

        if target.is_model_file or target.is_llm_endpoint or target.is_rag_pipeline:
            return self.engines[EngineType.MLAI]

        return self.engines[EngineType.INFRASTRUCTURE]
```

### 4.3 Engine 1 — Optimus Infra

**Status:** Build now
**Scope:** Network, Application, Endpoint, Cloud, IAM, Data Security
**Agents:** ReconAgent, ScanAgent, ExploitAgent, CloudAgent, IAMAgent, DataSecAgent, EndpointAgent
**Execution backend:** Kali SSH (kali:22 on internal Docker network)

### 4.4 Engine 2 — Optimus ICS

**Status:** Stub — future
**Scope:** IoT / OT / ICS industrial control systems
**Agents:** ICSAgent (implements BaseAgent, raises NotImplementedError on execute)
**Behavior:** EngineRouter surfaces notification on Modbus/DNP3 targets. No tool execution under any circumstances. HumanConfirmGate ABC defined for future use.

### 4.5 Engine 3 — Optimus AI

**Status:** After Engine 1
**Scope:** Adversarial ML, GenAI Security (OWASP LLM Top 10 2025)
**Agents:** ModelSecAgent, GenAIAgent
**Execution backend:** ml-runtime container (no network, filesystem IPC via task.json/findings.json)

---

## 5. Agent System

### 5.1 BaseAgent ABC

Every Optimus Prime sub-agent inherits from BaseAgent, which merges agentic execution patterns with security-specific patterns:

```python
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from typing import ClassVar


class EngineType(Enum):
    INFRASTRUCTURE = "engine_1"
    ICS = "engine_2"
    MLAI = "engine_3"


class AgentRole(Enum):
    """OmO role assignment."""
    ARCHITECT = "architect"
    EXECUTOR = "executor"
    REVIEWER = "reviewer"


class StealthLevel(Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


@dataclass
class BaseAgent(ABC):
    """
    Base class for all Optimus Prime security sub-agents.

    Merges agentic execution patterns with security-specific patterns.
    """

    # --- Identity (Optimus) ---
    ENGINE: ClassVar[EngineType]
    ALLOWED_TOOLS: ClassVar[list[str]]

    # --- OmO role ---
    ROLE: ClassVar[AgentRole] = AgentRole.EXECUTOR

    # --- Agentic execution patterns ---
    max_iterations: int = 50
    auto_compaction_threshold: int = 100_000  # tokens

    # --- Optimus security patterns ---
    scope: ScopeConfig = field(default_factory=ScopeConfig)
    stealth_level: StealthLevel = StealthLevel.MEDIUM
    credential_vault: CredentialVault = field(default_factory=CredentialVault)

    # --- Runtime state ---
    session: Session = field(default_factory=Session)
    event_bus: EventBus = field(default_factory=EventBus)
    hook_runner: HookRunner = field(default_factory=HookRunner)
    tool_executor: ToolExecutor = field(default_factory=ToolExecutor)
    xai_logger: XAILogger = field(default_factory=XAILogger)

    @abstractmethod
    async def execute(self, task: AgentTask) -> AgentResult:
        """Execute the agent's primary function."""
        ...

    async def run_loop(self, task: AgentTask) -> AgentResult:
        """
        Core agentic loop — planning, execution, review, retry.

        1. PLAN: Build execution plan from task + session context
        2. EXECUTE: Run tools via ToolExecutor with permission checking
        3. REVIEW: Process results through hooks and verification
        4. RETRY/CONTINUE: Loop until completion or max iterations
        """
        iterations = 0

        while iterations < self.max_iterations:
            iterations += 1

            # Auto-compaction when context grows too large
            if self.session.token_count > self.auto_compaction_threshold:
                await self.session.compact()

            # Plan next action
            action = await self._plan_next_action(task)
            if action is None:
                break  # Agent considers task complete

            # Execute tool with full permission pipeline
            result = await self._execute_with_permissions(action)

            # Log to XAI
            await self.xai_logger.log_decision(
                agent=self.__class__.__name__,
                action=action,
                result=result,
                reasoning=action.reasoning,
            )

            # Publish result to EventBus
            await self.event_bus.publish(
                channel="findings" if result.is_finding else "lifecycle",
                event=result.to_event(),
            )

            # Check if task is complete
            if result.is_terminal:
                return result.to_agent_result()

        return AgentResult(status="max_iterations_reached")

    async def _execute_with_permissions(self, action: AgentAction) -> ToolResult:
        """
        Full permission pipeline — merged PermissionEnforcer
        and Optimus scope/stealth/credential enforcement.

        Flow:
          PermissionEnforcer.check()
            -> ScopeEnforcer.check(scope.yaml)
            -> CredentialVault.inject()
            -> StealthEnforcer.check(stealth_level)
            -> HookRunner.run_pre_tool_use()
            -> ToolExecutor.execute()
            -> HookRunner.run_post_tool_use()
        """
        # 1. Permission check (base layer)
        perm = await self.permission_enforcer.check(action.tool_name, action.tool_input)
        if perm.denied:
            raise ToolPermissionError(perm.reason)

        # 2. Scope check (Optimus layer)
        scope_ok = await self.scope_enforcer.check(action.target, self.scope)
        if not scope_ok:
            raise ScopeViolationError(f"Target {action.target} not in scope")

        # 3. Credential injection (Optimus layer)
        enriched_input = await self.credential_vault.inject(action.tool_input)

        # 4. Stealth check (Optimus layer)
        stealth_ok = await self.stealth_enforcer.check(
            action.tool_name, self.stealth_level
        )
        if not stealth_ok:
            raise StealthViolationError(
                f"Tool {action.tool_name} not allowed at stealth_level={self.stealth_level}"
            )

        # 5. Pre-tool hook
        hook_result = await self.hook_runner.run_pre_tool_use(
            action.tool_name, enriched_input
        )
        if hook_result.denied:
            raise HookDeniedError(hook_result.reason)
        if hook_result.updated_input:
            enriched_input = hook_result.updated_input

        # 6. Execute tool
        result = await self.tool_executor.execute(action.tool_name, enriched_input)

        # 7. Post-tool hook
        await self.hook_runner.run_post_tool_use(
            action.tool_name, enriched_input, result, is_error=result.is_error
        )

        return result
```

### 5.2 Agent Registry

All agents are registered in a global registry:

| Agent | Engine | ALLOWED_TOOLS namespace | OmO Role |
|-------|--------|------------------------|----------|
| ReconAgent | Engine 1 | nmap, whatweb, dnsrecon, sublist3r, amass | Executor |
| ScanAgent | Engine 1 | nmap, nikto, nuclei, masscan, wpscan | Executor |
| ExploitAgent | Engine 1 | sqlmap, dalfox, commix, ffuf, msfconsole, payload_crafter | Executor |
| IntelAgent | Engine 1 | shodan, cve_search, exploit_db, dark_web_query | Executor |
| CloudAgent | Engine 1 | scoutsuite, prowler, pacu | Executor |
| IAMAgent | Engine 1 | jwt_tool, oauthscan, saml_raider, modlishka, o365spray | Executor |
| DataSecAgent | Engine 1 | trufflehog, gitleaks, testssl, pii_parser, exfil_sim | Executor |
| EndpointAgent | Engine 1 | msfconsole, sharp_edr_checker, lotl_crafter | Executor |
| ModelSecAgent | Engine 3 | art_fgsm, art_pgd, art_cw, model_extract, membership_infer, model_audit | Executor |
| GenAIAgent | Engine 3 | promptfoo, canary_inject, rag_poison, agent_hijack | Executor |
| ICSAgent | Engine 2 | (none — stub) | Executor |
| ScopeDiscoveryAgent | Engine 1 | crt_sh, whois, shodan, dns_enum, github_scan, job_posting | Executor |
| VerificationLoop | (cross-engine) | (re-uses executor agent tools with restricted policy) | Reviewer |

**Namespace enforcement:** An agent calling a tool outside its ALLOWED_TOOLS raises ToolPermissionError. BaseAgent namespace scoping is enforced on all security tooling.

### 5.3 Worker State Machine

Each agent instance follows this state machine:

```
Spawning -> TrustRequired -> ReadyForPrompt -> Running -> Finished
                                                  |
                                                  v
                                                Failed
```

- **Spawning:** Agent class instantiated, dependencies injected
- **TrustRequired:** Awaiting scope confirmation and credential vault population
- **ReadyForPrompt:** Ready to receive task from OmO coordinator
- **Running:** Actively executing tools against targets
- **Finished:** Task complete, findings published to EventBus
- **Failed:** Error state — OmO coordinator handles retry or escalation

### 5.4 Task Registry

The TaskRegistry tracks all agent task lifecycles:

```python
@dataclass
class AgentTask:
    task_id: str
    agent_class: str              # "ScanAgent", "ExploitAgent", etc.
    prompt: str                   # Natural language task description
    status: TaskStatus            # Created, Running, Completed, Failed, Stopped
    messages: list[TaskMessage]   # Execution log
    output: str                   # Structured findings
    team_id: str | None           # For parallel agent groups
    parent_task_id: str | None    # For sub-task chains

class TaskStatus(Enum):
    CREATED = "created"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    STOPPED = "stopped"
```

---

## 6. Tool System

### 6.1 ToolSpec

Every tool has a typed specification:

```python
@dataclass(frozen=True)
class ToolSpec:
    name: str                              # Unique tool identifier
    description: str                       # What the tool does
    input_schema: dict                     # JSON Schema for input validation
    required_permission: PermissionMode    # Permission level required
    backend: ToolBackend                   # Where the tool executes
    stealth_profile: StealthProfile        # Which stealth levels allow this tool
    engine_scope: list[EngineType]         # Which engines can use this tool
```

### 6.2 Tool Backends

Optimus Prime extends the base subprocess execution with four additional backends:

| Backend | Transport | Isolation | Tools |
|---------|-----------|-----------|-------|
| **LocalSubprocess** | Direct subprocess on backend container | Process-level | File ops, search, web fetch, report generation |
| **KaliSSH** | SSH to kali:22 on internal Docker network | Container-level | nmap, nikto, nuclei, sqlmap, dalfox, masscan, msfconsole, commix, ffuf, wpscan, trufflehog, gitleaks, testssl, jwt_tool, oauthscan, saml_raider, scoutsuite, prowler, pacu, etc. |
| **MLRuntimeIPC** | Filesystem IPC via task.json / findings.json | Container-level (no network) | ART attacks (FGSM/PGD/C&W), Promptfoo, ModelAudit, membership inference, model extraction |
| **TorSOCKS5** | Proxied HTTP/HTTPS via tor:9050 | Network-level | Dark web research, forum monitoring, threat intel queries |
| **SandboxOnDemand** | Unix socket to sandbox_manager.py on host | Host-sidecar + ephemeral container | Custom tool validation against DVWA |

### 6.3 ToolExecutor

```python
class ToolExecutor:
    """
    Dispatches tool calls to the appropriate backend.
    Dispatches tool calls to the appropriate backend.
    """

    backends: dict[ToolBackend, BackendHandler]
    tool_registry: dict[str, ToolSpec]

    async def execute(self, tool_name: str, tool_input: dict) -> ToolResult:
        spec = self.tool_registry.get(tool_name)
        if spec is None:
            raise UnknownToolError(f"Tool '{tool_name}' not registered")

        handler = self.backends[spec.backend]
        return await handler.run(spec, tool_input)
```

### 6.4 Backend Handlers

**KaliSSH handler:**

```python
class KaliSSHHandler(BackendHandler):
    """Executes security tools on the Kali container via SSH."""

    ssh_client: paramiko.SSHClient    # Persistent connection to kali:22
    shell_manager: ShellManager       # Session multiplexing
    command_safety: CommandSafety     # Validates commands before execution

    async def run(self, spec: ToolSpec, tool_input: dict) -> ToolResult:
        command = self.build_command(spec, tool_input)

        # CommandSafety validates (no rm -rf, no out-of-scope targets)
        await self.command_safety.validate(command, scope=self.scope)

        stdin, stdout, stderr = self.ssh_client.exec_command(
            command, timeout=tool_input.get("timeout", 300)
        )

        output = stdout.read().decode()
        error = stderr.read().decode()

        return ToolResult(
            tool_name=spec.name,
            output=output,
            error=error if error else None,
            is_error=stdout.channel.recv_exit_status() != 0,
        )
```

**MLRuntimeIPC handler:**

```python
class MLRuntimeIPCHandler(BackendHandler):
    """Executes ML/AI tools via filesystem IPC with the ml-runtime container."""

    ipc_path: Path    # Shared volume mount

    async def run(self, spec: ToolSpec, tool_input: dict) -> ToolResult:
        task_file = self.ipc_path / "task.json"
        findings_file = self.ipc_path / "findings.json"

        # Write task
        task_file.write_text(json.dumps({
            "tool": spec.name,
            "input": tool_input,
            "timeout": 60,
        }))

        # Wait for runner.py in ml-runtime to process
        result = await self._poll_for_result(findings_file, timeout=60)

        return ToolResult(
            tool_name=spec.name,
            output=json.dumps(result),
            is_error=result.get("status") == "error",
        )
```

### 6.5 Stealth Profiles

Each tool has a stealth profile that determines when it can be used:

| Stealth Level | Allowed Tools | Blocked Tools |
|---------------|---------------|---------------|
| low | All tools, no rate limiting | None |
| medium | All tools, rate-limited active scanning | None |
| high | Passive tools only + rate-limited targeted scans | masscan, aggressive nmap, Shodan API queries |

```python
@dataclass(frozen=True)
class StealthProfile:
    min_stealth: StealthLevel        # Minimum level where tool is available
    rate_limit: int | None           # Requests per second (None = unlimited)
    passive_only: bool               # True = no active probing
```

---

## 7. Permission and Safety Architecture

The permission system merges the 9-lane PermissionEnforcer with security-specific gates into a layered pipeline.

### 7.1 Permission Pipeline

```
Tool Call
    |
    v
[Layer 1] PermissionEnforcer.check()          -- Base layer
    |     - Path traversal prevention
    |     - Symlink escape detection
    |     - Workspace boundary validation
    |     - Binary detection
    |     - Size limits (MAX_READ_SIZE, MAX_WRITE_SIZE)
    |     - Command validation (9 bash validation submodules)
    |
    v
[Layer 2] ScopeEnforcer.check(scope.yaml)     -- Optimus layer
    |     - Target IP/domain in scope?
    |     - Port in scope?
    |     - Protocol in scope?
    |     - verify_mode setting respected?
    |
    v
[Layer 3] CredentialVault.inject()             -- Optimus layer
    |     - Cloud credentials (AWS/Azure/GCP)
    |     - API keys (Shodan, commercial TI)
    |     - Never logged, never in XAI entries
    |
    v
[Layer 4] StealthEnforcer.check(stealth_level) -- Optimus layer
    |     - Tool allowed at current stealth level?
    |     - Rate limiting applied?
    |     - Passive-only enforcement?
    |
    v
[Layer 5] NamespaceEnforcer.check(ALLOWED_TOOLS) -- Optimus layer
    |     - Agent calling tool within its namespace?
    |     - ToolPermissionError on violation
    |
    v
[Layer 6] HookRunner.run_pre_tool_use()       -- Hook layer
    |     - Plugin validation hooks
    |     - Custom tool sandbox gate
    |     - Can deny, modify input, or add context
    |
    v
Tool Execution (backend-specific handler)
    |
    v
[Layer 7] HookRunner.run_post_tool_use()      -- Hook layer
          - Verification hook
          - XAI logging hook
          - Effectiveness tracking hook (custom tools)
```

### 7.2 ScopeConfig

```python
@dataclass
class ScopeConfig:
    """Parsed from scope.yaml — auto-detected and confirmed in first reply."""

    targets: list[str]                  # IPs, domains, CIDRs, URLs
    excluded_targets: list[str]         # Explicitly out-of-scope
    ports: list[int] | str              # Port list or "all"
    protocols: list[str]                # tcp, udp, http, https
    stealth_level: StealthLevel         # low, medium, high
    verify_mode: VerifyMode             # auto, manual
    cloud_provider: str | None          # aws, azure, gcp
    compliance_frameworks: list[str]    # gdpr, pci-dss, iso27001, soc2, nist-csf
    notes: str                          # Free-text engagement notes
```

### 7.3 CredentialVault

```python
class CredentialVault:
    """
    Secure credential storage. Credentials are:
    - Injected into tool inputs at execution time
    - NEVER written to logs
    - NEVER included in XAI entries
    - NEVER sent to LLM context
    - Stored in Docker secrets volume
    """

    async def inject(self, tool_input: dict) -> dict:
        """Inject credentials into tool input, returning enriched copy."""
        ...

    async def store(self, key: str, value: str, provider: str) -> None:
        """Store a credential. Operator-initiated only."""
        ...
```

---

## 8. Session Management and Persistence

Session management with security-specific extensions.

### 8.1 Session Structure

```python
@dataclass
class Session:
    """
    Conversation state with auto-compaction and fork support.
    auto-compaction and fork support.
    """

    session_id: str
    version: int = 1
    created_at: datetime = field(default_factory=datetime.utcnow)
    updated_at: datetime = field(default_factory=datetime.utcnow)
    messages: list[ConversationMessage] = field(default_factory=list)
    compaction: SessionCompaction | None = None
    fork: SessionFork | None = None

    # Optimus extensions
    engagement_id: str | None = None
    client_id: str | None = None
    scope: ScopeConfig | None = None

    @property
    def token_count(self) -> int:
        """Estimated token count across all messages."""
        ...

    async def compact(self) -> None:
        """
        Auto-compaction when token count exceeds threshold.

        Auto-compaction:
        1. Identify older messages to summarise
        2. Generate summary via Mistral (budget-friendly)
        3. Replace detailed messages with summary
        4. Preserve recent context (last N messages)
        """
        ...

    def fork(self, branch_name: str) -> "Session":
        """
        Fork session for parallel exploration.

        Use case: try two exploit chains simultaneously,
        merge the successful one back.
        """
        ...


@dataclass
class ConversationMessage:
    role: MessageRole                    # system, user, assistant, tool
    blocks: list[ContentBlock]
    usage: TokenUsage | None = None
    timestamp: datetime = field(default_factory=datetime.utcnow)


@dataclass
class ContentBlock:
    """Union type for message content."""
    pass

@dataclass
class TextBlock(ContentBlock):
    text: str

@dataclass
class ToolUseBlock(ContentBlock):
    id: str
    name: str
    input: str

@dataclass
class ToolResultBlock(ContentBlock):
    tool_use_id: str
    tool_name: str
    output: str
    is_error: bool = False
```

### 8.2 Persistence Strategy

JSONL append-only persistence:

```
Active Session
    |
    v
Disk Persistence (data/sessions/)
    - JSONL format for append-only writes
    - Rotation after 256KB
    - Max 3 rotated files per session
    |
    v
Resume on Demand
    - Load messages
    - Restore scope and engagement context
    - Continue conversation
```

### 8.3 Session Compaction

This directly mitigates the #1 production risk identified in the Optimus deep-research: context blowout causing $200+ Claude costs on long loops.

```
Token count at 60k (ConversationSummariser threshold):
    -> Summarise older messages via Mistral (cheap)
    -> Preserve recent 10 messages
    -> Summary becomes new system context

Token count at 100k (auto-compaction threshold):
    -> Aggressive compaction
    -> Preserve recent 5 messages
    -> Discard tool call details, keep findings

Token budget at 80%:
    -> Warning published to EventBus
    -> Frontend shows TokenBudgetBar alert

Token budget at 100%:
    -> Mistral-only mode activated
    -> No Claude calls until new budget window
```

---

## 9. Memory Architecture

Three-tier persistence model combining session state with Optimus memory systems:

### 9.1 Tier 1 — Session State

| Property | Value |
|----------|-------|
| Purpose | Conversation history, tool call log, compaction |
| Format | JSONL, append-only |
| Storage | `data/sessions/` on backend volume |
| Lifecycle | Per-engagement, resumable |
| Compaction | Auto at 100k tokens |

### 9.2 Tier 2 — Semantic Memory (SmartMemory)

| Property | Value |
|----------|-------|
| Purpose | Finding embeddings, prior engagement recall, adaptive learning |
| Format | SQLite + nomic-embed-text vectors |
| Storage | `optimus_memory` Docker volume |
| Lifecycle | Persistent across all engagements |
| Search | Semantic similarity via nomic-embed-text (Ollama) |

**AdaptiveLearning:** Session 2 with a target shows memory-informed tool selection. If nuclei found the most vulnerabilities last time, prioritise nuclei this time.

**CampaignIntelligence:** Cross-engagement pattern detection. If the same client has the same weakness across 3 engagements, flag it as systemic.

### 9.3 Tier 3 — Client Profiles (ClientProfileDB)

| Property | Value |
|----------|-------|
| Purpose | Per-client tech stack, recurring weaknesses, remediation history, report preferences |
| Format | Separate `client_profiles.db` (SQLite) |
| Storage | `client_profiles` Docker volume |
| Lifecycle | Persistent, separate from SmartMemory |
| Identification | Auto-match by domain/IP + operator confirmation |

```python
@dataclass
class ClientProfile:
    client_id: str
    name: str
    domains: list[str]
    ip_ranges: list[str]
    tech_stack: dict                  # Detected and confirmed technologies
    recurring_weaknesses: list[dict]  # Weaknesses found across engagements
    remediation_history: list[dict]   # What was fixed and when
    report_preferences: dict          # Preferred format, framework, etc.
    engagement_count: int
    last_seen: datetime
```

**Auto-match flow:**
```
New engagement: "Pentest api.acme.com"
    |
ClientProfileManager queries client_profiles.db by domain
    |
Match found (87% confidence):
    "Optimus detected this may be Acme Corp. Confirm?
     Last engagement found 3 unpatched issues."
    |
Operator confirms -> profile attached to session
    |
Welcome-back context loaded into agent planning
```

---

## 10. Event Bus Architecture

The unified EventBus merges the clawhip event routing pattern with the IntelBus into a single typed, channel-based system.

### 10.1 EventBus Core

```python
class EventBus:
    """
    Unified event bus — clawhip pattern extended with security channels.

    Design principles (from clawhip):
    - Events stay OUTSIDE agent context windows
    - Agents publish and forget — delivery is EventBus responsibility
    - TTL cache on all channels prevents redundant processing
    - Async — publishers never block on subscriber processing
    """

    channels: dict[str, Channel]
    ttl_cache: TTLCache

    async def publish(self, channel: str, event: Event) -> None:
        """Publish event to channel. Non-blocking."""
        ...

    async def subscribe(self, channel: str, handler: EventHandler) -> Subscription:
        """Subscribe to channel events."""
        ...
```

### 10.2 Channel Definitions

| Channel | Event Types | Publishers | Subscribers |
|---------|-------------|-----------|-------------|
| `findings` | FindingCreated, FindingVerified, FindingClassified | ScanAgent, ExploitAgent, CloudAgent, IAMAgent, DataSecAgent, EndpointAgent, ModelSecAgent, GenAIAgent | VerificationLoop, IntelligentReporter, Frontend, CollabWS |
| `intel` | CVECorrelated, ATTACKMapped, KEVMatched, ThreatActorLinked | IntelAgent, ThreatAttributionEngine, ResearchDaemon | ExploitChainer, StrategyEvolutionEngine, Frontend |
| `lifecycle` | AgentSpawned, AgentRunning, AgentFinished, AgentFailed, PhaseChanged | All agents, EngineRouter, OmO Coordinator | Frontend, CollabWS, XAI Logger |
| `collab` | UserJoined, UserLeft, RoleElevated, RoleRevoked, CommandIssued | CollabManager | CollabWebSocket (role-filtered) |
| `research` | NewCVEIngested, NewPoCFound, TechniqueDelta, DarkWebAlert, ToolGenerated | ResearchDaemon, CustomToolGenerator | StrategyEvolutionEngine, SmartMemory |
| `xai` | DecisionLogged, ReasoningRecorded, VerificationResult | All agents (via XAILogger) | IntelligentReporter, Audit Trail, Frontend |
| `budget` | WarningAt80Pct, MistralOnlyActivated, ResearchBudgetExhausted | TokenBudgetManager | Frontend (TokenBudgetBar), All agents |

### 10.3 TTL Cache

```python
class TTLCache:
    """
    Prevents redundant processing of identical events.
    Same CVE correlated by IntelAgent and ResearchDaemon?
    Second publish is a cache hit — subscribers not re-notified.
    """

    default_ttl: int = 300      # 5 minutes
    storage: dict[str, CacheEntry]
```

---

## 11. Hook System

The hook architecture provides intervention points for validation and modification at tool execution boundaries.

### 11.1 Hook Events

```python
class HookEvent(Enum):
    PRE_TOOL_USE = "pre_tool_use"
    POST_TOOL_USE = "post_tool_use"
    POST_TOOL_USE_FAILURE = "post_tool_use_failure"
```

### 11.2 HookRunner

```python
class HookRunner:
    """
    Runs registered hooks at tool execution boundaries.
    Runs registered hooks at tool execution boundaries.
    """

    hooks: dict[HookEvent, list[Hook]]

    async def run_pre_tool_use(
        self, tool_name: str, tool_input: dict
    ) -> HookRunResult:
        """
        Run before tool execution. Can:
        - Deny execution (denied=True)
        - Override permissions
        - Modify tool input (updated_input)
        - Add context messages
        """
        result = HookRunResult()
        for hook in self.hooks.get(HookEvent.PRE_TOOL_USE, []):
            hook_output = await hook.run(tool_name, tool_input)
            if hook_output.denied:
                result.denied = True
                result.reason = hook_output.reason
                return result
            if hook_output.updated_input:
                tool_input = hook_output.updated_input
                result.updated_input = tool_input
        return result

    async def run_post_tool_use(
        self, tool_name: str, tool_input: dict, result: ToolResult, is_error: bool
    ) -> None:
        """Run after tool execution. Used for verification, XAI logging, effectiveness tracking."""
        event = (
            HookEvent.POST_TOOL_USE_FAILURE if is_error
            else HookEvent.POST_TOOL_USE
        )
        for hook in self.hooks.get(event, []):
            await hook.run(tool_name, tool_input, result)


@dataclass
class HookRunResult:
    denied: bool = False
    reason: str | None = None
    permission_override: PermissionOverride | None = None
    updated_input: dict | None = None
    messages: list[str] = field(default_factory=list)
```

### 11.3 Security-Specific Hooks

| Hook | Event | Purpose |
|------|-------|---------|
| ScopeValidationHook | PRE_TOOL_USE | Validates target is in scope before any tool execution |
| StealthEnforcementHook | PRE_TOOL_USE | Blocks tools that violate stealth_level |
| CredentialInjectionHook | PRE_TOOL_USE | Injects credentials from vault into tool input |
| XAILoggingHook | POST_TOOL_USE | Logs decision and result to ExplainableAI trail |
| FindingVerificationHook | POST_TOOL_USE | Routes findings to VerificationLoop |
| EffectivenessTrackingHook | POST_TOOL_USE | Tracks custom tool success rate for promotion |
| SandboxValidationHook | PRE_TOOL_USE | Gates custom tools through sandbox validation |

---

## 12. LLM Routing and Token Management

### 12.1 LLM Router

Two-tier LLM routing with provider abstraction:

```python
class LLMRouter:
    """
    Two-tier LLM routing.
    Primary: Claude claude-sonnet-4-6 — orchestration, XAI, reply composition, tool generation
    Fallback: Mistral 7B via Ollama — classification, summarisation, budget fallback
    """

    primary: ClaudeProvider          # Anthropic API
    fallback: MistralProvider        # Ollama at ollama:11434

    async def route(self, request: LLMRequest) -> LLMResponse:
        if request.task_type in (TaskType.ORCHESTRATION, TaskType.XAI, TaskType.TOOL_GENERATION):
            try:
                return await self.primary.complete(request)
            except (RateLimitError, BudgetExhaustedError):
                # Fallback within 1 retry cycle
                return await self.fallback.complete(request)

        # Classification, summarisation always use Mistral (cheap)
        return await self.fallback.complete(request)
```

### 12.2 TokenBudgetManager

```python
class TokenBudgetManager:
    """
    Dual budget tracking — session and research daemon are independent.
    """

    session_budget: int                # SESSION_TOKEN_BUDGET env var
    research_budget: int               # RESEARCH_DAEMON_TOKEN_BUDGET env var (default: 100k/night)
    session_used: int = 0
    research_used: int = 0

    async def check_and_track(self, tokens: int, budget_type: BudgetType) -> BudgetStatus:
        if budget_type == BudgetType.SESSION:
            self.session_used += tokens
            pct = self.session_used / self.session_budget

            if pct >= 1.0:
                await self.event_bus.publish("budget", MistralOnlyActivated())
                return BudgetStatus.MISTRAL_ONLY
            elif pct >= 0.8:
                await self.event_bus.publish("budget", WarningAt80Pct(pct))
                return BudgetStatus.WARNING
            return BudgetStatus.OK

        elif budget_type == BudgetType.RESEARCH:
            self.research_used += tokens
            if self.research_used >= self.research_budget:
                await self.event_bus.publish("budget", ResearchBudgetExhausted())
                return BudgetStatus.EXHAUSTED
            return BudgetStatus.OK
```

---

## 13. Verification and Review Architecture

The VerificationLoop implements OmO's Reviewer role. It is the architectural embodiment of "every finding verified before reporting."

### 13.1 VerificationLoop

```python
class VerificationLoop(BaseAgent):
    """
    OmO Reviewer role — autonomous finding verification.
    Implements the persistent verification loop pattern.
    """

    ENGINE = None  # Cross-engine — verifies findings from any engine
    ALLOWED_TOOLS = []  # Dynamically set per-finding from originating agent
    ROLE = AgentRole.REVIEWER

    async def verify(self, finding: Finding) -> VerifiedFinding:
        """
        Verification strategy:
        1. Benign proof — reproduce with minimal impact
        2. Data extraction — minimal (DB user, server version, not real data)
        3. No destructive payloads
        4. No exfiltration of real data
        5. Respects scope.yaml verify_mode setting
        """
        if self.scope.verify_mode == VerifyMode.MANUAL:
            return VerifiedFinding(
                finding=finding,
                classification=Classification.MANUAL_REVIEW,
                reason="verify_mode=manual in scope.yaml"
            )

        # Attempt autonomous verification
        verification_result = await self._run_verification(finding)

        return VerifiedFinding(
            finding=finding,
            classification=verification_result.classification,
            evidence=verification_result.evidence,
            reason=verification_result.reasoning,
        )


class Classification(Enum):
    CONFIRMED = "confirmed"           # Reproduced with benign proof + extraction
    FALSE_POSITIVE = "false_positive"  # Not reproducible
    MANUAL_REVIEW = "manual_review"    # Ambiguous — needs operator judgment
```

### 13.2 ExplainableAI (XAI)

```python
class XAILogger:
    """
    Logs every agent decision with full reasoning chain.
    Logs every agent decision with full reasoning chain. Every tool call
    and routing decision is recorded for audit trail.
    """

    async def log_decision(
        self,
        agent: str,
        action: AgentAction,
        result: ToolResult,
        reasoning: str,
    ) -> XAIEntry:
        entry = XAIEntry(
            timestamp=datetime.utcnow(),
            agent=agent,
            tool=action.tool_name,
            target=action.target,
            reasoning=reasoning,
            result_summary=result.summary,
            # NEVER include credentials
            # NEVER include raw sensitive data
        )
        await self.event_bus.publish("xai", entry)
        return entry
```

**Query interface:** Operator asks "Why did you use sqlmap?" — XAI returns the specific entry with reasoning chain.

---

## 14. Collaboration and RBAC

Merges the clawhip delivery pattern with local LAN RBAC (F4).

### 14.1 User Configuration

Users defined in .env (no registration UI):

```env
COLLAB_USERS=alice:lead:$2b$12$hash1,bob:analyst:$2b$12$hash2,charlie:observer:$2b$12$hash3
COLLAB_JWT_SECRET=<random-32-char-string>
```

### 14.2 RBAC Roles

| Role | Permissions |
|------|-------------|
| **Lead** | Full control — all commands, session management, role elevation, scope changes |
| **Analyst** | Run tasks, view all findings, cannot change session scope |
| **Observer** | Read-only — sees findings and intel feed, cannot issue commands, chat hidden |

### 14.3 CollabWebSocket

Adapted from clawhip's delivery pattern with role-based filtering:

```python
class CollabWebSocket:
    """
    Multi-user WebSocket broadcast with role-filtered streams.
    Adapted from clawhip event delivery — events delivered
    outside agent context windows via EventBus subscription.
    """

    connections: dict[str, WebSocketConnection]  # user_id -> connection

    async def broadcast(self, event: Event) -> None:
        for user_id, conn in self.connections.items():
            if self._is_allowed(conn.role, event):
                await conn.send(event.serialize())

    def _is_allowed(self, role: RBACRole, event: Event) -> bool:
        if isinstance(event, FindingEvent):
            return True  # All roles see findings
        if isinstance(event, ChatEvent):
            return role in (RBACRole.LEAD, RBACRole.ANALYST)
        if isinstance(event, LifecycleEvent):
            return True
        return role == RBACRole.LEAD
```

### 14.4 In-Session Role Elevation

```
Lead: !elevate @bob lead      -> Bob gets Lead JWT for this session
Lead: !revoke @bob             -> Bob returns to Analyst baseline
```

No container restart required. Elevation JWTs are session-scoped, signed with COLLAB_JWT_SECRET, and logged in XAI trail.

---

## 15. Research and Strategy Evolution

### 15.1 Research Daemon Architecture

Research daemon scheduling via the CronRegistry pattern:

```
Schedule:

  Nightly cron (02:00 local) — 6 sources:
    ExploitDB + NVD     -> new CVEs with CVSS, affected products
    GitHub PoC          -> new exploit repositories
    MITRE ATT&CK        -> technique delta since last run
    HackerOne           -> newly disclosed public reports
    Security blogs      -> Portswigger, ProjectDiscovery RSS
    CISA KEV            -> Known Exploited Vulnerabilities feed

  Weekly cron (Sunday 03:00) — 1 source:
    Dark web forums     -> Tor SOCKS5, 60s timeout per query
```

Each source ingestion is a tracked task in the TaskRegistry. The ResearchScheduler manages cron entries via the CronRegistry pattern.

### 15.2 ResearchKB

```python
# SQLite schema
class ResearchKBEntry:
    entry_id: str
    source: str                      # exploitdb, nvd, github_poc, attack, hackerone, blogs, cisa_kev, dark_web
    cve_id: str | None
    technique_id: str | None         # ATT&CK technique
    poc_url: str | None
    affected_products: list[str]
    cvss_score: float | None
    description: str
    raw_data: dict
    ingested_at: datetime
    sources_merged: list[str]        # Deduplication — same CVE from multiple sources
```

### 15.3 StrategyEvolutionEngine

```python
class StrategyEvolutionEngine:
    """
    Queries ResearchKB when ExploitChainer builds attack graphs.
    Enriches each chain step with relevant PoCs, ATT&CK techniques,
    and historical success rates from SmartMemory.
    """

    research_kb: ResearchKB
    smart_memory: SmartMemory
    exploit_chainer: ExploitChainer

    async def enrich_chain(self, chain: AttackChain) -> EnrichedAttackChain:
        for node in chain.nodes:
            # Query ResearchKB for relevant PoCs
            pocs = await self.research_kb.query(cve=node.cve_id)
            # Query SmartMemory for historical success rate
            history = await self.smart_memory.query_similar(node.technique)
            # Enrich node
            node.poc_urls = [poc.poc_url for poc in pocs]
            node.attack_technique_id = pocs[0].technique_id if pocs else None
            node.historical_success_rate = history.success_rate if history else None

        return EnrichedAttackChain(chain=chain)
```

### 15.4 Custom Tool Generation Flow

Custom tool generation leverages the plugin system (manifests, lifecycle, hook integration):

```
1. ExploitAgent encounters vulnerability with no suitable ALLOWED_TOOL
2. StrategyEvolutionEngine queries ResearchKB for similar exploits
3. CustomToolGenerator prompts Claude: synthesise tool from research context
4. Language detection: check shebang/imports -> verify runtime in Kali
   If compiled (Go/Rust): compile in sandbox, promote binary not source
5. SandboxManager.spin_up() -> DVWA container on internal Docker network
6. Generated tool runs against DVWA — pass/fail assessment
7. SandboxManager.tear_down() — container removed immediately
8. If pass: human review prompt in chat (PreToolUse hook gates future use)
9. Operator approves -> tool registered as plugin in CustomToolRegistry
   - ToolSpec (name, schema, permissions)
   - PreToolUse hook (sandbox validation gate)
   - PostToolUse hook (effectiveness tracking)
10. After N successful uses + confidence >= threshold:
    Auto-suggest promotion -> operator confirms -> added to ALLOWED_TOOLS
```

### 15.5 SandboxManager (Host Sidecar)

```python
class SandboxManager:
    """
    Runs on Docker host as sidecar process.
    Communicates via Unix socket — no Docker socket exposed to any container.
    """

    socket_path: str = "/var/run/optimus_sandbox.sock"

    async def spin_up(self) -> SandboxInstance:
        """Start DVWA container on internal Docker network."""
        ...

    async def tear_down(self, instance: SandboxInstance) -> None:
        """Remove container immediately after validation."""
        ...

    async def execute_in_sandbox(
        self, tool_path: str, target: str = "dvwa"
    ) -> SandboxResult:
        """Run tool against DVWA, return pass/fail."""
        ...
```

---

## 16. Reporting Architecture

### 16.1 Six Report Modes

| Mode | Content | Phase |
|------|---------|-------|
| **Executive** | High-level risk summary, business impact, strategic recommendations | Phase 7 |
| **Technical** | Full finding details, evidence, reproduction steps, tool output | Phase 7 |
| **Remediation Roadmap** | Prioritised fix plan, effort estimates, dependency ordering | Phase 7 |
| **Developer Handoff** | Per-finding code-level fix suggestions with example patches | Phase 8 |
| **Compliance Mapping** | Findings mapped to framework controls with gap analysis | Phase 8 |
| **Regression** | Delta vs last engagement: new, remediated, persistent findings | Phase 8 |

### 16.2 ComplianceMappingDB

Pre-populated SQLite with control-to-finding mappings for 5 frameworks:

| Framework | Control Count |
|-----------|--------------|
| GDPR | Data protection articles |
| PCI-DSS | Requirements and sub-requirements |
| ISO 27001 | Annex A controls |
| SOC 2 | Trust service criteria |
| NIST CSF | Functions, categories, subcategories |

### 16.3 Report Generation Flow

```
Operator: "Export compliance report PCI-DSS"
    |
IntelligentReporter:
    1. Gather all CONFIRMED findings from session
    2. Query ComplianceMappingDB for PCI-DSS control mappings
    3. Map each finding to relevant controls
    4. Identify gaps (controls with no findings = untested)
    5. Generate report via Jinja2 template
    6. Render PDF via WeasyPrint
    7. Publish download link to EventBus -> Frontend
```

---

## 17. Deployment Architecture

### 17.1 Docker Compose Service Map

| Service | Image | Port | Role |
|---------|-------|------|------|
| frontend | node:20-alpine | 3000 | Next.js 14 chat UI — split-pane: ChatPane (40%) + LivePanel (60%) |
| backend | python:3.12-slim | 8000 | FastAPI, all agents, OmX/OmO/clawhip coordination, RBAC |
| ollama | ollama/ollama | 11434 | Mistral:7b-instruct + nomic-embed-text |
| kali | custom kali-rolling | 22 (internal SSH) | All infrastructure attack tooling |
| ml-runtime | custom python:3.12-slim | none (filesystem IPC) | ART, Promptfoo — no network access |
| tor | dperson/torproxy | 9050 (internal SOCKS5) | Dark web intel + research |
| sandbox (on-demand) | vulnerables/web-dvwa | 80 (internal, ephemeral) | Custom tool validation target |
| sandbox_manager (host sidecar) | host process | unix socket | Manages sandbox lifecycle — not a container |

### 17.2 Network Topology

```
                    External Network
                          |
                    [frontend:3000]
                          |
                    [backend:8000]
                     /    |    \
              [ollama]  [kali]  [tor]
              :11434    :22     :9050
                          |
                    [ml-runtime]
                    (no network)

    Host sidecar: sandbox_manager.py
         |
    unix socket: /var/run/optimus_sandbox.sock
         |
    [sandbox:80] (ephemeral, on-demand)
```

### 17.3 Auth

| Mode | Mechanism |
|------|-----------|
| Single user | Static Bearer token in .env |
| Collaboration | JWT per user with role claim, signed with COLLAB_JWT_SECRET |

### 17.4 Resource Limits

All services have top-level `mem_limit` and `cpus` constraints (Docker Compose v1 compatibility):

```yaml
services:
  backend:
    mem_limit: 4g
    cpus: 2.0
  kali:
    mem_limit: 2g
    cpus: 1.5
  ml-runtime:
    mem_limit: 4g
    cpus: 2.0
    network_mode: "none"    # No network access — verified each compose change
  ollama:
    mem_limit: 4g
    cpus: 2.0
```

---

## 18. Build Sequence

### 18.1 All 41 Issues — Dependency Order

Phase 0 through Phase 9, unchanged from the original plan. The agentic patterns are adopted as architectural foundations within existing issues, not as new issues.

| Phase | Issues | Weeks | Agentic Integration |
|-------|--------|-------|----------------------|
| Phase 0 — Pre-build | #1-4 | 1-2 | Adapt ToolSpec/ToolExecutor patterns. Define EventBus channels. Establish BaseAgent ABC with OmO roles. Docker Compose skeleton includes all 8 services. |
| Phase 1 — Core agent loop | #5-9 | 3-4 | LLM Router uses provider abstraction. ConversationCore adopts Session + compaction. Orchestrator implements OmX workflow planning. HookRunner wired into tool execution. |
| Phase 2 — Full sub-agent suite | #10-13 | 2-3 | All agents inherit BaseAgent with ALLOWED_TOOLS namespace. IntelBus replaced by unified EventBus with typed channels. |
| Phase 3 — Memory and learning | #14-16 | 2-3 | SmartMemory uses three-tier persistence. Session fork enabled for parallel exploration. XAI logging via hook system. |
| Phase 4 — Core reporting | #17 | 1 | Reporter subscribes to EventBus findings channel. |
| Phase 5 — Frontend | #18 | 1-2 | WebSocket receives events via clawhip delivery pattern. |
| Phase 6 — Engine 1 expansion + F3/F5/F7 | #19-23, #36, #39, #40 | 5-6 | VerificationLoop implements OmO Reviewer role. ThreatAttribution publishes to EventBus intel channel. ScopeDiscovery uses Worker state machine. |
| Architecture — E2 stub | #27 | 0.5 | ICSAgent stub, HumanConfirmGate ABC, EngineRouter notification. |
| Phase 7 — Reports + Engine 3 | #41, #24-26 | 4-5 | All 6 report formats. MLRuntimeIPC backend handler. |
| Phase 8 — Research + Client Profiles | #28-35 | 6-7 | ResearchScheduler uses CronRegistry. CustomToolGenerator uses plugin manifest. TaskRegistry tracks research tasks. |
| Phase 9 — Collaboration | #37-38 | 2-3 | CollabWebSocket uses clawhip delivery with RBAC filtering. |
| **TOTAL** | **41 issues** | **33-39 weeks** | |

---

## 19. Risk Register

| Risk | L | I | Mitigation |
|------|---|---|------------|
| Context blowout on long engagements ($200+ Claude cost) | H | H | **Auto-compaction** at 100k tokens. ConversationSummariser at 60k. Two-tier LLM routing (Mistral for cheap tasks). TokenBudgetManager with 80% warning and 100% Mistral-only cutoff. |
| Nightly research daemon token cost (3M tokens/month) | M | M | RESEARCH_DAEMON_TOKEN_BUDGET hard cap. Incremental-only ingestion. Deduplication across sources. |
| Generated tool in wrong language for Kali runtime | M | M | Language detection checks shebang/imports. Claude re-prompted if runtime unavailable. Compiled binaries built in sandbox. |
| Sandbox sidecar Docker socket exposure | L | H | sandbox_manager.py on HOST, not in container. Unix socket. No container has Docker socket mounted. |
| Agent context window pollution from status/delivery | M | H | **clawhip pattern** — all monitoring and delivery outside agent context. Agents publish to EventBus and forget. |
| Sub-agent calling out-of-namespace tools | M | H | **NamespaceEnforcer** — ALLOWED_TOOLS checked before every execution. ToolPermissionError on violation. |
| Disagreement between ScanAgent and ExploitAgent on severity | M | M | **OmO disagreement resolution** — VerificationLoop re-tests, classifies, escalates to operator if ambiguous. |
| Scope discovery Shodan queries logged (stealth risk) | M | M | Shodan skipped at stealth_level: high. StealthEnforcer hook blocks. |
| RBAC elevation JWT manipulation | L | H | Session-scoped, short-lived, signed with COLLAB_JWT_SECRET, XAI logged. |
| Client profile auto-match misidentification | M | H | Auto-match is suggestion only. Operator always confirms. Confidence score displayed. |
| VerificationLoop unexpected deep exploitation | L | H | Verification limited to benign proof + minimal extraction. VerificationPolicy dataclass enforces constraints. |
| 33-39 weeks solo build scope creep | H | M | 41 issues fixed scope. Phase gates prevent forward movement without passing acceptance criteria. |

---

## 20. Success Metrics

| Metric | Target |
|--------|--------|
| First streaming token after message | <= 3 seconds |
| "Scan X" to first structured findings | <= 120 seconds |
| CVE correlation latency | <= 30 seconds |
| PDF report export | <= 60 seconds |
| Orchestrator structured JSON reliability | >= 95% of validation suite |
| Claude API fallback to Mistral | Within 1 retry cycle |
| Token budget warning accuracy | 80% +/- 1% |
| Session compaction prevents context blowout | Zero $200+ runaway sessions |
| SmartMemory persistence across restart | 100% data retention |
| Semantic search relevance | Top-3 for all 10 test queries |
| ml-runtime network isolation | No outbound connection verified |
| Full workflow via chat only | Zero CLI required |
| Research daemon nightly completion | Within 3 hours, all 6 sources |
| Custom tool sandbox validation cycle | < 120 seconds |
| Client profile auto-match accuracy | >= 90% returning clients |
| Verification loop false positive elimination | >= 80% reduction vs raw scanner |
| Threat attribution coverage | ATT&CK technique for >= 70% CONFIRMED findings |
| Scope discovery asset coverage | >= 5 asset types from seed |
| Compliance mapping completeness | >= 90% findings mapped to >= 1 control |
| Multi-user broadcast latency | <= 200ms to all connected users |
| Agent context window stays clean | Zero status/delivery messages in agent context |
| EventBus end-to-end latency | <= 50ms publish-to-subscriber |
| Hook pipeline overhead | <= 10ms per tool call |
| Disagreement resolution | <= 3 iterations to classify |

---

## 21. Decision Record

| Session | Decisions |
|---------|-----------|
| Original Optimus Plan | Claude as primary LLM. Two-tier routing. Docker Compose 8 services. nomic-embed-text. Static Bearer + JWT auth. YAML scope file. WeasyPrint PDF. Kali base image. 13 domains, 3 engines, 7 features. 41 issues, 33-39 weeks. |
| Agentic Architecture Review | Three-layer coordination (OmX/clawhip/OmO). 40-tool Rust runtime. ToolSpec/ToolExecutor/GlobalToolRegistry. 9-lane PermissionEnforcer. Session persistence with JSONL + auto-compaction. Hook system (Pre/Post ToolUse). TaskRegistry/WorkerRegistry/CronRegistry. Plugin system with manifests and lifecycle. |
| Optimus Prime Merge | OmX becomes Security Workflow Planner. clawhip becomes unified EventBus with typed channels. OmO roles (Architect/Executor/Reviewer) map to Orchestrator/SubAgents/VerificationLoop. ToolExecutor extended with 5 backends (Local, Kali SSH, ml-runtime IPC, Tor SOCKS5, Sandbox). Permission pipeline: 7 layers merging agentic + security gates. Three-tier memory (Session + SmartMemory + ClientProfiles). Session compaction mitigates #1 production risk