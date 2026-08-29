# Optimus Prime

## What This Is

A personal-use AI security platform that orchestrates autonomous penetration testing engagements through a multi-agent system. The operator interacts via a browser-based chat UI; the system routes intent through LLM-driven agents (Recon, Scan, Exploit, Verify, Cloud, IAM, ICS, etc.) that execute real tools on a Kali Linux backend over SSH. Built for a single operator running structured, AI-guided engagements against defined targets.

## Core Value

A solo operator can run a complete structured pentest engagement — from scoping through exploitation through reporting — with AI agents handling tool chaining and the operator reviewing findings, not running commands.

## Requirements

### Validated

<!-- These capabilities exist in the codebase today and are the foundation to build on. -->

- ✓ FastAPI WebSocket server with `/ws/chat` endpoint and REST `/api/chat` fallback — `backend/app.py`, `backend/api/`
- ✓ Bearer token authentication (static token from .env) — `backend/auth.py`
- ✓ LLM routing: Claude primary, Ollama/Mistral fallback with automatic error recovery — `backend/agent/llm_router.py`
- ✓ EngagementSession dataclass with ConversationHistory (40-message context window) — `backend/session/engagement_session.py`
- ✓ SessionStore (in-memory session registry keyed by UUID) — `backend/session/session_store.py`
- ✓ EngineRouter dispatching to ML/AI, ICS, and Infrastructure execution engines — `backend/agent/engine_router.py`
- ✓ BaseAgent abstract loop (keep as-is — mentor confirmed) — `backend/agent/sub_agents/base.py`
- ✓ 12 domain-specific security agents (Cloud, IAM, Recon, Scan, Exploit, Intel, Endpoint, ModelSec, GenAI, ICS, DataSec, Physical) — `backend/agent/sub_agents/`
- ✓ ToolSelector and tool registry with permission checking — `backend/agent/tool_selector.py`
- ✓ Paramiko-based Kali SSH client — `backend/execution/ssh_client.py`
- ✓ CredentialVault injection pattern — `backend/agent/credential_vault.py`
- ✓ XAILogger (explainable AI decision log) — `backend/reporting/explainable_ai.py`
- ✓ Docker sandbox isolation for generated tool execution (DooD) — `backend/tools/backends/sandbox.py` — Validated in Phase 2: Security Hardening (unwired — zero live callers, correct-and-ready per D-02)
- ✓ Per-engagement Kali workdir scoping in SSHClient/ShellManager — `backend/execution/ssh_client.py`, `backend/execution/shell_manager.py` — Validated in Phase 2: Security Hardening
- ✓ SQLite WAL mode on ClientProfileDB and ResearchKB connections — `backend/memory/client_profile.py`, `backend/intelligence/research_kb.py` — Validated in Phase 2: Security Hardening
- ✓ VerificationLoop engagement-scoped budget stub — `backend/verification/verification_loop.py` — Validated in Phase 2: Security Hardening (scoping-only; full classification logic deferred to v1.1 Phase 5)
- ✓ React frontend operator UI (App.jsx — single-file monolith) — `frontend/`

### Active

<!-- Building toward these. Current milestone: stabilize and harden the foundation. -->

**Milestone 1 — Critical Bug Fixes & Dead Code Removal**
- [x] Delete old backend system (`backend/main.py`, `backend/core/`, `backend/agents/`) and migrate tests that import from them — Validated in Phase 1: Cleanup & Configuration
- [x] Fix model string: `claude_model` is now `"claude-sonnet-4-6"` — Validated in Phase 1: Cleanup & Configuration
- [x] Docker sandbox for generated tool execution — Validated in Phase 2: Security Hardening
- [x] SQLite WAL mode on every connection — Validated in Phase 2: Security Hardening
- [x] Per-engagement Kali working directories — Validated in Phase 2: Security Hardening
- [x] VerificationLoop `_request_counts` scoped by `engagement_id` — minimal stub built in Phase 2 (full CONFIRMED/FALSE_POSITIVE/MANUAL_REVIEW logic deferred to v1.1 Phase 5)

**Milestone 2 — Orchestration Upgrade**
- [ ] PHASE_FAILED event propagation through the agent loop
- [ ] LLMRouter extended to multi-provider task-based routing (Claude + Ollama + DeepSeek/other API providers as needed) — not a wholesale swap off Claude
- [ ] OmX template-first planner: 8-directive planning DAG, separate from OmO coordinator
- [ ] Session persistence to disk + reconnect (currently pure in-memory; process restart loses all sessions)

**Milestone 3 — Frontend Split**
- [ ] Wire `ChatPane.tsx` into `App.jsx` (currently orphaned, not imported)
- [ ] Extract `TerminalPanel`, `FindingsPanel`, `ScopePanel` into separate components
- [ ] Wrap each panel in an error boundary
- [ ] Add `SessionProvider` context for session state

### Out of Scope

- **SaaS / multi-tenancy** — personal use only; architecture must be session-aware but not multi-tenant billing/isolation
- **Cloud-hosted Kali** — operator runs their own Kali instance; no managed Kali provisioning
- **Browser-based target scanning** — requires separate legal/authorization context outside this tool's scope
- **Real-time collaboration** — single operator per engagement; no multi-user session sharing

## Context

**Architecture state (Phase 1 complete):** Single canonical backend system. Old system (`backend/core/`, `backend/agents/`, `backend/main.py`) deleted. All tests unified under `tests/` — 144 passing, 2 skipped, 15 xfailed (known stubs). `backend/intelligence/custom_tool_generator.py` has NotImplementedError stubs for tool registration (requires Phase 2 tool registry).

**Model config:** `claude_model = "claude-sonnet-4-6"` — Claude API calls now succeed. Human verification of live API (no Ollama fallback) is pending (tracked in 01-HUMAN-UAT.md).

**Security risk (resolved Phase 2):** Tool execution sandbox previously used `asyncio.create_subprocess_exec("python3", ...)` running generated code directly on the host process. Now runs in an isolated Docker container (DooD). Still unwired — zero live callers until v1.1 Phase 9.

**Correction (2026-08-29, during v1.1 milestone gap analysis):** The "Validated" bullets for `ReportGenerator`/`ResearchKB`+`ResearchDaemon` were inaccurate — code exists on disk (`backend/reporting/intelligent_reporter.py`, `backend/intelligence/research_daemon.py`, `backend/intelligence/research_kb.py`) but neither is imported anywhere in the live orchestrator/api/app path. Same is true of `intel_bus.py`, `dark_web_intel.py`, `source_adapters.py`, `client_profile.py`, `custom_tool_generator.py`, and `compliance_mapping.py` — all orphaned. Removed from Validated; wiring these up is v1.1 milestone scope (see planned Phases 7–10: Semantic Memory & Client Profiles, Threat Intel & Attribution, Auto Research & Strategy Evolution, Report Mode Suite).

**LLM stack (revised 2026-08-29):** Claude (Anthropic SDK) + Ollama/Mistral fallback today. Mentor's original recommendation was to *swap* orchestration to DeepSeek-V3 — that conflicted with the project's Anthropic+Ollama-only constraint. Resolved during Phase 3 planning: constraint updated to explicitly allow multi-provider routing (operator's call, not a swap). LLMRouter becomes task-based multi-provider (Claude for complex reasoning, Ollama/Qwen for compaction, DeepSeek or other API providers as additional options) rather than replacing Claude outright.

**Mentor architecture target:** 7-layer design — Operator → Gateway → EngagementSession → Coordination (OmO+OmX) → Agents → Tool Execution → Data.

## Constraints

- **Personal use:** Single operator, no auth hardening beyond static bearer token required for now
- **Tech stack:** Python/FastAPI backend, React frontend — no stack changes
- **Kali connection:** SSH via Paramiko — operator manages their own Kali instance
- **LLM providers:** Multi-provider by design — Anthropic SDK + Ollama local + additional pay-per-call API providers (e.g. DeepSeek) as orchestration needs dictate. No rented/provisioned cloud GPU infrastructure — API-metered spend only. (Revised 2026-08-29 — see Key Decisions)
- **No breaking changes to BaseAgent loop** — mentor confirmed this abstraction is correct; all agents inherit from it

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| New `backend/agent/` system is canonical; old `backend/core/` is dead | Dual systems cause import confusion and test failures | ✓ Completed — Phase 1 |
| Docker sandbox for tool execution, not subprocess | Generated code on host = RCE risk during real engagements | ✓ Good — Phase 2 |
| WAL mode for all SQLite connections | Concurrent reads/writes during active engagement need non-blocking I/O | ✓ Good — Phase 2 |
| Multi-provider LLMRouter (not a Claude swap) | Original mentor recommendation was to replace Claude with DeepSeek-V3 wholesale, which conflicted with the Anthropic+Ollama-only constraint. Operator chose multi-provider routing instead — DeepSeek and others become additional options, task-routed, not a replacement | ✓ Good — decided during Phase 3 planning |
| Per-engagement Kali workdirs | Commands from different sessions must not bleed into same filesystem state | ✓ Good — Phase 2 (component-level; orchestrator still doesn't call sub-agents, pre-existing gap outside Phase 2 scope) |
| Docker-outside-of-Docker (DooD) for sandbox isolation | Smaller change than a host-level sidecar process; backend container gains host Docker access as a tradeoff, accepted given single-operator use and zero live callers this phase | ✓ Good — Phase 2 (D-10) |
| Frontend component split after backend stabilizes | App.jsx monolith acceptable until backend is correct; don't split before foundation is solid | — Pending |

## Evolution

This document evolves at phase transitions and milestone boundaries.

**After each phase transition** (via `/gsd:transition`):
1. Requirements invalidated? → Move to Out of Scope with reason
2. Requirements validated? → Move to Validated with phase reference
3. New requirements emerged? → Add to Active
4. Decisions to log? → Add to Key Decisions
5. "What This Is" still accurate? → Update if drifted

**After each milestone** (via `/gsd:complete-milestone`):
1. Full review of all sections
2. Core Value check — still the right priority?
3. Audit Out of Scope — reasons still valid?
4. Update Context with current state

---
*Last updated: 2026-08-29 after Phase 2: Security Hardening*
