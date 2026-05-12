# Roadmap: Optimus Prime

**Created:** 2026-05-12
**Phases:** 4
**Requirements:** 13 v1 requirements

---

## Phases

- [ ] **Phase 1: Cleanup & Configuration** — Remove dead backend system, fix critical model string so the platform actually runs as intended
- [ ] **Phase 2: Security Hardening** — Sandbox tool execution, isolate engagement filesystems, scope data correctly, and apply WAL mode
- [ ] **Phase 3: Orchestration Upgrade** — Wire PHASE_FAILED propagation, upgrade LLM stack, implement OmX planner, persist sessions to disk
- [ ] **Phase 4: Frontend Split** — Wire ChatPane, extract panel components, introduce SessionProvider context

---

## Phase Overview

| # | Phase | Goal | Requirements | Plans |
|---|-------|------|--------------|-------|
| 1 | Cleanup & Configuration | 2/3 | In Progress|  |
| 2 | Security Hardening | No host RCE, engagements filesystem-isolated, findings correctly scoped, DB durable | SEC-01, SEC-02, DATA-01, DATA-02 | TBD |
| 3 | Orchestration Upgrade | Failures surface, LLM stack upgraded, planner decoupled from coordinator, sessions survive restarts | ORCH-01, ORCH-02, ORCH-03, PERSIST-01 | TBD |
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
**Plans:** 2/3 plans executed
- [x] 01-01-PLAN.md — Fix Claude model identifier in backend/config.py and add regression test
- [x] 01-02-PLAN.md — Delete 17 dead-code test files and repoint pyproject.toml testpaths at tests/
- [ ] 01-03-PLAN.md — Migrate 9 preserved tests, delete backend/main.py + backend/core/ + backend/agents/ + backend/tests/
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
**Plans:** TBD
**UI hint**: no

### Phase 3: Orchestration Upgrade
**Goal:** The operator sees phase failures surface in the chat UI instead of silent drops, the platform uses DeepSeek-V3 for orchestration reasoning, the OmX planner operates independently of the OmO coordinator, and restarting the backend does not lose an active engagement.
**Depends on:** Phase 2
**Requirements:** ORCH-01, ORCH-02, ORCH-03, PERSIST-01
**Success Criteria** (what must be TRUE):
  1. When an agent phase fails, the operator receives a `PHASE_FAILED` event in the WebSocket stream naming which phase failed and why — the failure is never silently swallowed
  2. A successful chat message processed by the backend logs show `LLMRouter: using DeepSeek-V3` for orchestration and `Qwen-7B` for compaction; Claude is invoked only for designated analysis tasks
  3. An OmX planning request produces a logged 8-directive DAG and the OmO coordinator log shows it consuming that plan — the two components are traceable as separate concerns in logs
  4. After a deliberate backend process restart mid-engagement, the operator can reconnect with the same session ID and the conversation history, scope, and phase status are restored from disk
**Plans:** TBD
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
| 2. Security Hardening | 0/0 | Not started | - |
| 3. Orchestration Upgrade | 0/0 | Not started | - |
| 4. Frontend Split | 0/0 | Not started | - |
