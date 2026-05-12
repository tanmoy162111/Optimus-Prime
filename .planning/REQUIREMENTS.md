# Requirements: Optimus Prime

**Defined:** 2026-05-12
**Core Value:** A solo operator can run a complete structured pentest engagement — from scoping through exploitation through reporting — with AI agents handling tool chaining and the operator reviewing findings, not running commands.

## v1 Requirements

### CLEAN — Dead Code & Configuration

- [ ] **CLEAN-01**: Old backend system (`backend/main.py`, `backend/core/`, `backend/agents/`) is deleted and all tests previously importing from those paths are migrated to new module paths under `backend/agent/`
- [ ] **CLEAN-02**: `claude_model` config value is corrected to `"claude-sonnet-4-6"` so all Claude API calls succeed without falling back to Ollama silently

### SEC — Security & Execution Isolation

- [ ] **SEC-01**: Generated tool code executes inside a Docker container (`--network=none --memory=256m --rm`) — no host subprocess execution of untrusted code
- [ ] **SEC-02**: Each engagement's Kali SSH commands run inside `/engagements/{engagement_id}/` working directory, isolating filesystem state between engagements

### DATA — Persistence & Engagement Scoping

- [ ] **DATA-01**: Every SQLite connection opened in the application applies `PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;` immediately after connection
- [ ] **DATA-02**: `VerificationLoop._request_counts` dictionary keys are prefixed with `{engagement_id}:` so finding counts do not bleed across concurrent engagements

### ORCH — Orchestration Upgrade

- [ ] **ORCH-01**: `PHASE_FAILED` events are propagated through the agent execution loop and surfaced to the operator via the WebSocket event stream
- [ ] **ORCH-02**: DeepSeek-V3 is configured as the primary orchestration LLM in `LLMRouter`; Qwen 7B handles compaction; Claude retained for specific analysis tasks
- [ ] **ORCH-03**: `OmX` planner implements template-first planning with an 8-directive phase DAG, operating as a separate component from the `OmO` coordinator

### PERSIST — Session Durability

- [ ] **PERSIST-01**: Engagement sessions are serialized to disk and can be reloaded on reconnect after a process restart (currently pure in-memory; restart loses all session state)

### UI — Frontend Component Split

- [ ] **UI-01**: `ChatPane.tsx` is imported and rendered in `App.jsx` as the primary chat interface (currently the component exists but is not imported anywhere)
- [ ] **UI-02**: `TerminalPanel`, `FindingsPanel`, and `ScopePanel` are extracted from `App.jsx` into separate component files, each wrapped in an error boundary
- [ ] **UI-03**: `SessionProvider` context is introduced to manage session state, replacing prop-drilling in `App.jsx`

## v2 Requirements

### Hardening

- **HARD-01**: Multi-tenant auth hardening — rate limiting, per-user tokens, audit log (personal use only for now; static bearer token is sufficient)
- **HARD-02**: Operator-visible XAI log review panel — surface `XAILogger` decisions in the frontend

### Intelligence

- **INTEL-01**: Custom tool generator (three-gate pipeline in `backend/tools/backends/sandbox.py`) validated and surfaced to operators
- **INTEL-02**: Compliance report export — NIST-CSF, PCI-DSS, GDPR, ISO27001, SOC2 mapping from `backend/reporting/`

## Out of Scope

| Feature | Reason |
|---------|--------|
| SaaS / multi-tenancy | Personal use only; billing isolation and tenant separation are future considerations, not current scope |
| Cloud-hosted Kali provisioning | Operator manages their own Kali instance; managed provisioning adds ops complexity with no near-term value |
| Browser-based scanning UI | Separate legal/authorization context — target specification happens via chat, not a dedicated scan UI |
| Real-time multi-operator collaboration | Single operator per engagement; shared sessions add complexity and aren't needed for personal use |
| Mobile app | Web-first; operator console is not a mobile-friendly use case |

## Traceability

| Requirement | Phase | Status |
|-------------|-------|--------|
| CLEAN-01 | Phase 1 — Cleanup & Configuration | Pending |
| CLEAN-02 | Phase 1 — Cleanup & Configuration | Pending |
| SEC-01 | Phase 2 — Security Hardening | Pending |
| SEC-02 | Phase 2 — Security Hardening | Pending |
| DATA-01 | Phase 2 — Security Hardening | Pending |
| DATA-02 | Phase 2 — Security Hardening | Pending |
| ORCH-01 | Phase 3 — Orchestration Upgrade | Pending |
| ORCH-02 | Phase 3 — Orchestration Upgrade | Pending |
| ORCH-03 | Phase 3 — Orchestration Upgrade | Pending |
| PERSIST-01 | Phase 3 — Orchestration Upgrade | Pending |
| UI-01 | Phase 4 — Frontend Split | Pending |
| UI-02 | Phase 4 — Frontend Split | Pending |
| UI-03 | Phase 4 — Frontend Split | Pending |

**Coverage:**
- v1 requirements: 13 total
- Mapped to phases: 13
- Unmapped: 0 ✓

---
*Requirements defined: 2026-05-12*
*Last updated: 2026-05-12 — traceability populated by roadmapper*
