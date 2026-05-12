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
- ✓ ReportGenerator (multi-format output) — `backend/reporting/intelligent_reporter.py`
- ✓ ResearchKB + ResearchDaemon (vulnerability knowledge base + nightly crawler) — `backend/knowledge/`
- ✓ React frontend operator UI (App.jsx — single-file monolith) — `frontend/`

### Active

<!-- Building toward these. Current milestone: stabilize and harden the foundation. -->

**Milestone 1 — Critical Bug Fixes & Dead Code Removal**
- [x] Delete old backend system (`backend/main.py`, `backend/core/`, `backend/agents/`) and migrate tests that import from them — Validated in Phase 1: Cleanup & Configuration
- [x] Fix model string: `claude_model` is now `"claude-sonnet-4-6"` — Validated in Phase 1: Cleanup & Configuration
- [ ] Docker sandbox for generated tool execution (replace `asyncio.create_subprocess_exec` host subprocess — RCE risk)
- [ ] SQLite WAL mode on every connection (`PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;`)
- [ ] Per-engagement Kali working directories (`/engagements/{engagement_id}/` on SSH host)
- [ ] VerificationLoop `_request_counts` scoped by `engagement_id` (currently instance-level, cross-contaminates findings)

**Milestone 2 — Orchestration Upgrade**
- [ ] PHASE_FAILED event propagation through the agent loop
- [ ] DeepSeek-V3 as primary orchestration LLM in LLMRouter; Qwen 7B for compaction
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

**Security risk:** Tool execution sandbox is `asyncio.create_subprocess_exec("python3", ...)` running generated code directly on the host process. Docker isolation is required before using this against real targets.

**LLM stack:** Claude (Anthropic SDK) + Ollama/Mistral fallback. Mentor recommendation: switch orchestration to DeepSeek-V3, Qwen 7B for compaction. Retain Claude for specific analysis tasks.

**Mentor architecture target:** 7-layer design — Operator → Gateway → EngagementSession → Coordination (OmO+OmX) → Agents → Tool Execution → Data.

## Constraints

- **Personal use:** Single operator, no auth hardening beyond static bearer token required for now
- **Tech stack:** Python/FastAPI backend, React frontend — no stack changes
- **Kali connection:** SSH via Paramiko — operator manages their own Kali instance
- **LLM providers:** Anthropic SDK + Ollama local — no cloud GPU spend beyond API calls
- **No breaking changes to BaseAgent loop** — mentor confirmed this abstraction is correct; all agents inherit from it

## Key Decisions

| Decision | Rationale | Outcome |
|----------|-----------|---------|
| New `backend/agent/` system is canonical; old `backend/core/` is dead | Dual systems cause import confusion and test failures | ✓ Completed — Phase 1 |
| Docker sandbox for tool execution, not subprocess | Generated code on host = RCE risk during real engagements | — Pending |
| WAL mode for all SQLite connections | Concurrent reads/writes during active engagement need non-blocking I/O | — Pending |
| DeepSeek-V3 for orchestration (future) | Better performance/cost ratio for long-context pentest reasoning vs Claude | — Pending |
| Per-engagement Kali workdirs | Commands from different sessions must not bleed into same filesystem state | — Pending |
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
*Last updated: 2026-05-12 after Phase 1: Cleanup & Configuration*
