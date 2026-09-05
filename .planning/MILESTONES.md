# Milestones

## v1.0 Foundation Stabilization (Shipped: 2026-09-05)

**Phases completed:** 4 phases, 24 plans, 31 tasks

**Delivered:** Stabilized the platform's foundation end-to-end — fixed the defect that silently broke every Claude API call, removed the entire dead legacy backend, closed the RCE risk in tool execution, built the real OmX→OmO orchestration pipeline with session durability, and componentized the frontend around a protocol-correct chat interface.

**Key accomplishments:**

- Fixed silent Claude API 404 by correcting `claude_model` from the non-existent `"claude-opus-4-7"` to `"claude-sonnet-4-6"`, and deleted the entire dead legacy backend (`backend/core/`, `backend/agents/`, `backend/main.py`) — 144 tests pass, zero residual imports
- Closed the RCE risk in tool execution: generated code now runs in an isolated, resource-capped Docker container instead of a host subprocess; added per-engagement Kali workdir isolation and SQLite WAL mode across all connections
- Built the real orchestration pipeline: OmX (forced-tool-use planner producing a validated, DAG-shaped `EngagementPlan`) → OmO (sequential dispatch coordinator enforcing scope/registry/cycle checks, guaranteeing a `PHASE_FAILED` event for every failure) → wired end-to-end into the Orchestrator, replacing the old LLM-completion-only path
- Added session durability — engagements now survive a backend restart via SQLite-backed serialization and reconnect (`SessionStore` + `TaskRegistry`)
- Componentized the frontend: `App.jsx` went from a 1505-line monolith to a slim composition root; rewrote `ChatPane` into the real, protocol-correct chat interface (fixed 3 simultaneous integration bugs: wrong WS URL, missing auth, multiplexed message routing); extracted all 9 panels into standalone files, each individually fault-isolated via `ErrorBoundary`; session state flows through a memoized `SessionContext`

**Known gaps carried forward** (see Deferred Items in STATE.md): live-backend verification for Phase 01 (Claude API smoke test) and Phase 04 (chat round-trip) requires the operator's own running backend + Kali instance — not verifiable in the sandbox this milestone was executed in.

---
