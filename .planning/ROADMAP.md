# Roadmap: Optimus Prime

**Created:** 2026-05-12
**Phases:** 4
**Requirements:** 13 v1 requirements

---

## Phases

- [x] **Phase 1: Cleanup & Configuration** — Remove dead backend system, fix critical model string so the platform actually runs as intended (completed 2026-05-12)
- [x] **Phase 2: Security Hardening** — Sandbox tool execution, isolate engagement filesystems, scope data correctly, and apply WAL mode (completed 2026-08-29)
- [ ] **Phase 3: Orchestration Upgrade** — Wire PHASE_FAILED propagation, upgrade LLM stack, implement OmX planner, persist sessions to disk
- [ ] **Phase 4: Frontend Split** — Wire ChatPane, extract panel components, introduce SessionProvider context

---

## Phase Overview

| # | Phase | Goal | Requirements | Plans |
|---|-------|------|--------------|-------|
| 1 | Cleanup & Configuration | 4/4 | Complete   | 2026-05-12 |
| 2 | Security Hardening | 4/4 | Complete   | 2026-08-29 |
| 3 | Orchestration Upgrade | 5/9 | In Progress|  |
| 4 | Frontend Split | UI componentized, orphaned component wired, session state centralized | UI-01, UI-02, UI-03 | TBD |

---

## Phase Details

### Phase 1: Cleanup & Configuration
**Goal:** The operator can start the backend knowing exactly one system is running, tests pass without import conflicts, and every Claude API call succeeds with the correct model.
**Depends on:** Nothing (prerequisite for all other phases)
**Requirements:** CLEAN-01, CLEAN-02
**Success Criteria** (what must be TRUE):
  1. `backend/main.py`, `backend/core/`, and `backend/agents/` are absent from the filesystem; `ls backend/` shows no legacy directories
  2. All tests under `backend/tests/` that previously imported from `backend/core/` or `backend/agents/` have been migrated and pass under the new `backend/agent/` paths
  3. `backend/config.py` `claude_model` reads `"claude-sonnet-4-6"`; a direct API call to Claude returns a 200 response (not a 404 that silently falls back to Ollama)
  4. The LLM router logs confirm Claude is being used for orchestration — no silent fallback events in the log during normal operation
**Plans:** 4/4 plans complete
- [x] 01-01-PLAN.md — Fix Claude model identifier in backend/config.py and add regression test
- [x] 01-02-PLAN.md — Delete 17 dead-code test files and repoint pyproject.toml testpaths at tests/
- [x] 01-03-PLAN.md — Migrate 9 preserved tests, delete backend/main.py + backend/core/ + backend/agents/ + backend/tests/
**UI hint**: no

### Phase 2: Security Hardening
**Goal:** The operator can run real engagements against real targets without generated code executing on the host, without Kali artifacts bleeding between engagements, and without concurrent DB writes corrupting findings.
**Depends on:** Phase 1
**Requirements:** SEC-01, SEC-02, DATA-01, DATA-02
**Success Criteria** (what must be TRUE):
  1. Executing a generated tool script launches a Docker container (`docker ps` shows a short-lived `--network=none --memory=256m --rm` container) — no Python process spawned directly on the host
  2. Starting two concurrent engagements and issuing Kali SSH commands in each produces output files in `/engagements/{engagement_id_A}/` and `/engagements/{engagement_id_B}/` respectively, with no cross-contamination
  3. Every SQLite connection in the application responds to `PRAGMA journal_mode;` with `wal` — verified via a startup health log entry or direct DB query
  4. Verifying the same finding ID from two separate concurrent engagements does not exhaust or share each other's request budget — each engagement's counter is independent
**Plans:** 4/4 plans complete
- [x] 02-01-PLAN.md — SEC-01: Docker container isolation in sandbox.py via docker-py (DooD per D-10)
- [x] 02-02-PLAN.md — SEC-02: per-engagement Kali workdir scoping in ShellManager + 7 sub-agents
- [x] 02-03-PLAN.md — DATA-01: WAL + synchronous=NORMAL pragmas in ClientProfileDB and ResearchKB
- [x] 02-04-PLAN.md — DATA-02: engagement-scoped VerificationLoop budget stub
**UI hint**: no

### Phase 3: Orchestration Upgrade
**Goal:** The operator sees phase failures surface in the chat UI instead of silent drops, the LLMRouter supports multi-provider task-based routing (Claude + Ollama + additional API providers like DeepSeek, not a wholesale swap off Claude), the OmX planner operates independently of the OmO coordinator, and restarting the backend does not lose an active engagement.
**Depends on:** Phase 2
**Requirements:** ORCH-01, ORCH-02, ORCH-03, PERSIST-01
**Success Criteria** (what must be TRUE):
  1. When an agent phase fails, the operator receives a `PHASE_FAILED` event in the WebSocket stream naming which phase failed and why — the failure is never silently swallowed
  2. `LLMRouter` supports task-based routing across multiple configured providers (Claude, Ollama, and at least one additional API provider such as DeepSeek); a successful chat message's logs show which provider handled orchestration vs. compaction — Claude remains a fully supported, non-removed provider (exact provider-per-task mix is an operator/CONTEXT.md decision, not a fixed swap)
  3. An OmX planning request produces a logged 8-directive DAG and the OmO coordinator log shows it consuming that plan — the two components are traceable as separate concerns in logs
  4. After a deliberate backend process restart mid-engagement, the operator can reconnect with the same session ID and the conversation history, scope, and phase status are restored from disk
**Plans:** 5/9 plans executed
- [x] 03-01-PLAN.md — Foundation defect fixes: config fields + SmartMemory/ConversationSummariser stubs (ORCH-02 prereq)
- [ ] 03-02-PLAN.md — LLMRouter multi-provider routing: compaction→Qwen, optional DeepSeek (ORCH-02)
- [x] 03-03-PLAN.md — SQLite+WAL SessionStore persistence + EngagementSession serialization (PERSIST-01)
- [ ] 03-04-PLAN.md — TaskRegistry directive handoff store + restart crash-detection (PERSIST-01)
- [x] 03-05-PLAN.md — clawhip typed-event router (WS + XAI audit trail) (ORCH-01)
- [x] 03-06-PLAN.md — OmX planner: forced-tool-use DAG generation + validation retry (ORCH-03)
- [x] 03-07-PLAN.md — InstructionParser reconciliation: dedupe EngineRouter, EngagementSession signature (ORCH-03/D-02)
- [ ] 03-08-PLAN.md — OmO coordinator: sequential dispatch, scope/plan gates, PHASE_FAILED emission (ORCH-01/ORCH-03)
- [ ] 03-09-PLAN.md — Orchestrator wiring: OmX→OmO→ResponseComposer pipeline (ORCH-01/ORCH-03)
**UI hint**: no

### Phase 4: Frontend Split
**Goal:** The React frontend is componentized — ChatPane is the active chat interface, panels are independently rendered and fault-isolated, and session state flows through context rather than prop-drilling.
**Depends on:** Phase 3
**Requirements:** UI-01, UI-02, UI-03
**Success Criteria** (what must be TRUE):
  1. `App.jsx` imports and renders `ChatPane.tsx`; the chat interface visible in the browser is served by `ChatPane.tsx` — confirmed by React DevTools component tree
  2. `TerminalPanel`, `FindingsPanel`, and `ScopePanel` each exist as standalone files under `frontend/components/`; deliberately throwing an error in one panel does not crash the others (error boundary isolates the failure)
  3. Session state (session ID, connection status, engagement metadata) is available via `useContext(SessionContext)` in any component without prop-drilling — a new component added to the tree can access session state with a single context hook call
**Plans:** TBD
**UI hint**: yes

---

## Progress

| Phase | Plans Complete | Status | Completed |
|-------|----------------|--------|-----------|
| 1. Cleanup & Configuration | 0/3 | Planned | - |
| 2. Security Hardening | 0/4 | Planned | - |
| 3. Orchestration Upgrade | 0/0 | Not started | - |
| 4. Frontend Split | 0/0 | Not started | - |
