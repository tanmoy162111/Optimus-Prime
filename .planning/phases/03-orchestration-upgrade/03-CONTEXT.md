# Phase 3: Orchestration Upgrade - Context

**Gathered:** 2026-09-01
**Status:** Ready for planning

<domain>
## Phase Boundary

The operator sees phase failures surface in the chat UI instead of silent drops, the LLMRouter supports multi-provider task-based routing (Claude + Ollama + additional API providers like DeepSeek — not a wholesale swap off Claude), the OmX planner operates independently of the OmO coordinator, and restarting the backend does not lose an active engagement. Requirements: ORCH-01, ORCH-02, ORCH-03, PERSIST-01.

**Scope note (locked during this discussion):** OmX/OmO/clawhip do not exist — they were deleted in Phase 1 cleanup as dead code with zero callers. This phase is a from-scratch build, not an upgrade. The operator explicitly chose full 3-layer architecture reconstruction (per `OPTIMUS_PRIME_ARCHITECTURE.md` §3) over a minimal DAG-planner-only approach — expect this phase's plans to be large; a planner-recommended split into sub-phases (e.g. 03a/03b) is an expected, acceptable outcome, not a failure.

</domain>

<decisions>
## Implementation Decisions

### LLM provider constraint (resolved before this discussion — see CLAUDE.md/PROJECT.md commit b502bcb)
- **D-00:** The original "switch orchestration to DeepSeek-V3" goal conflicted with the Anthropic+Ollama-only constraint. Resolved: constraint updated to explicitly allow multi-provider routing. This is NOT a Claude replacement.

### OmX / OmO / clawhip reconstruction scope
- **D-01:** Full 3-layer architecture reconstruction per `OPTIMUS_PRIME_ARCHITECTURE.md` §3 (OmX Workflow Planner, clawhip Event Router, OmO Multi-Agent Coordinator) — not a minimal stand-in. Operator chose this explicitly after being told the minimal-scope alternative.
- **D-02:** Wire the real agent dispatch loop as part of OmO's Executor role — OmO's execution IS the multi-step loop: parse intent → route to engine → select tools → invoke sub-agents → track `EngagementState.phase_status`. This reconciles two existing inconsistencies as part of the same work:
  - `instruction_parser.py` contains a duplicate `EngineRouter` class and its `InstructionParser.parse()` expects `backend.agent.conversation.SessionState`, not the `EngagementSession` the orchestrator actually holds — these must be reconciled (dedupe `EngineRouter`, fix the session-type mismatch) as part of wiring the loop, not left as-is.
  - Currently `Orchestrator.process()`/`process_stream()` never call `EngineRouter`, `InstructionParser`, `ToolSelector`, or any sub-agent — it is LLM-completion-only. This phase makes those real calls.
  - **D-02a (resolved after planning — deliberate supersession, not an oversight):** OmX's LLM-driven DAG generation (D-06) naturally supersedes `InstructionParser`'s regex intent/target detection and `EngineRouter`'s regex engine-selection — Claude decomposes the operator's directive directly into `Directive.engine`/`Directive.agent`/`Directive.tools`, doing that job more capably than the regex layer it replaces. `ToolSelector`'s tool-picking role is likewise subsumed: each `Directive.tools` (from OmX's DAG) is what `OmO.dispatch()` passes straight to `BaseAgent.execute()` — a separate `ToolSelector` call would be redundant re-selection over data OmX already produced. **Real call sites are NOT added for `InstructionParser.parse()`, `ToolSelector`, or the standalone `EngineRouter.dispatch()`** — the `instruction_parser.py` reconciliation (dedupe + retype, per the bullet above) still happens for code hygiene, but the class stays uncalled in production. This is a conscious architectural choice confirmed with the operator after plan-checker review flagged the literal-wording gap — not a silent scope reduction.
- **D-09 (clawhip delivery targets):** clawhip delivers to the frontend WebSocket and XAI audit trail. It does **NOT** deliver to `CollabWebSocket (RBAC)` — multi-user collaboration is explicitly out of scope for this project (`PROJECT.md` Out of Scope: "Real-time collaboration — single operator per engagement"). Do not build a CollabWebSocket delivery path even as a stub.
- **D-10 (not-yet-built dependency handling):** `OPTIMUS_PRIME_ARCHITECTURE.md`'s OmO/clawhip spec references components that don't exist yet:
  - `StrategyEvolutionEngine` (OmO's Architect role) — orphaned today (`backend/intelligence/strategy_evolution.py`, v1.1 Phase 9 scope). Build a **minimal stub** now (e.g. a no-op or pass-through class OmO's Architect role can call) rather than skipping the integration point entirely.
  - Research-daemon delivery (a clawhip monitoring/delivery target) — orphaned today (`backend/intelligence/research_daemon.py`, v1.1 Phase 9 scope). Build a **minimal stub** delivery channel (no real listener yet).
  - `TaskRegistry` (the OmO handoff protocol's task-state store) — does not exist anywhere. Build this **for real** (not a stub) — it's core to this phase's own coordination logic, not a dependency on future work.

### OmX plan generation
- **D-06:** LLM-driven. OmX asks Claude (via `LLMRouter`, mode="orchestration") to decompose the operator's request into a directive DAG. Not rule/template-based matching.

### PHASE_FAILED event granularity
- **D-07:** One OmX directive is the failure unit. If a sub-agent/tool call within a directive fails, OmO reports that whole directive as `PHASE_FAILED` over the WebSocket with the underlying error attached. Not per-individual-tool-call granularity.

### OmO dispatch model
- **D-08:** Sequential only for this phase. Directives execute one at a time in DAG order, even when the DAG has independent directives that could theoretically run in parallel. Parallel dispatch (concurrency-safety for shared `EngagementSession` mutation, concurrent SSH sessions) is deferred to a later phase.

### Session persistence (PERSIST-01)
- **D-03:** SQLite-backed. Matches Phase 2's DATA-01 WAL-mode hardening pattern (this project already uses SQLite for `client_profile.py`/`research_kb.py`). One connection, `PRAGMA journal_mode=WAL` applied on connect (per the Phase 2 pattern), straightforward reconnect-by-session_id query.

### Multi-provider LLMRouter (ORCH-02)
- **D-04:** Claude = orchestration (current behavior, unchanged). Ollama/Qwen = compaction (new mode). DeepSeek = wired as a configurable additional provider option, not required to be exercised by default — Claude is never removed as a provider.

### Claude's Discretion
- Exact TaskRegistry schema (in-memory dict vs. SQLite-backed alongside session persistence — planner's call given D-03 already introduces SQLite in this phase)
- Exact WebSocket message schema for `PHASE_FAILED` (beyond: names which directive failed and why)
- Whether clawhip is implemented as a distinct module/class or as a thin routing layer inside the existing `ConnectionManager` — planner's call given the "no CollabWebSocket" scope reduction

</decisions>

<specifics>
## Specific Ideas

No specific product/UX references from this discussion — this phase is backend coordination architecture. The one strong signal from the operator: don't build "good enough" stand-ins for OmX/OmO/clawhip — build the real 3-layer system per the architecture doc, even knowing it's a larger phase as a result.

</specifics>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Architecture specification (the reconstruction target)
- `OPTIMUS_PRIME_ARCHITECTURE.md` §3 (lines 110-289) — Three-Layer Coordination System: OmX (§3.1), clawhip (§3.2), OmO (§3.3). This is the primary spec for D-01/D-02/D-06/D-07/D-08/D-09/D-10.
- `OPTIMUS_PRIME_ARCHITECTURE.md` §5 — Agent System (BaseAgent ABC, referenced by OmO's Executor role)
- `OPTIMUS_PRIME_ARCHITECTURE.md` §10 — Event Bus Architecture (clawhip routes through "the unified EventBus (Section 10)" per §3.2 — this section defines what that means concretely)

### Project state and prior findings
- `.planning/PROJECT.md` — Constraints (multi-provider LLM decision, resolved 2026-08-29), Out of Scope (real-time collaboration exclusion — governs D-09), Key Decisions table
- `.planning/ROADMAP.md` §"Phase 3: Orchestration Upgrade" — Goal, success criteria, requirement IDs (ORCH-01, ORCH-02, ORCH-03, PERSIST-01)
- `.planning/REQUIREMENTS.md` — Full requirement text for ORCH-01, ORCH-02, ORCH-03, PERSIST-01
- `.planning/phases/02-security-hardening/02-CONTEXT.md` and `02-SUMMARY.md` files — Phase 2's SQLite WAL pattern (D-03 reuses this), and the confirmed fact that `Orchestrator.process()` doesn't call any sub-agent (found during Phase 2 research, re-confirmed during this discussion)

### Live code this phase touches
- `backend/agent/orchestrator.py` — currently LLM-completion-only; becomes (or delegates to) OmO
- `backend/agent/instruction_parser.py` — contains duplicate `EngineRouter` + `SessionState`-typed `InstructionParser.parse()`, must be reconciled per D-02
- `backend/agent/engine_router.py` — the canonical `EngineRouter` (duplicate of the one inside `instruction_parser.py`)
- `backend/agent/tool_selector.py`, `backend/agent/response_composer.py` — constructed but unused in `Orchestrator.__init__`, must actually be called per D-02
- `backend/agent/llm_router.py` — `LLMRouter.complete(mode=...)` currently supports only "orchestration"→Claude and else→Ollama; extend per D-04
- `backend/session/engagement_session.py` — `EngagementState.phase_status: Dict[str, str]` exists but nothing calls `set_phase_status()` today
- `backend/session/session_store.py` — pure in-memory `Dict[str, EngagementSession]`; becomes SQLite-backed per D-03
- `backend/api/ws_handler.py` — `ConnectionManager.send()` is the existing WS delivery mechanism; `PHASE_FAILED` events route through here (directly, or via clawhip per Claude's Discretion above)
- `backend/intelligence/strategy_evolution.py`, `backend/intelligence/research_daemon.py` — orphaned; stub integration points per D-10

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- Phase 2's SQLite WAL pattern (`PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;` immediately after connect) — directly reusable for PERSIST-01's session store.
- `InstructionParser._detect_intent()`/`_detect_phase()` — existing regex-based intent/phase detection could inform (but per D-06, does NOT replace) OmX's LLM-driven plan generation; may still be useful for engine dispatch within a directive.
- `EngineRouter.dispatch()` (both copies) — working ML/ICS/Infrastructure engine selection logic, ready to be called for real once deduplicated.

### Established Patterns
- Every existing SQLite-backed class (`ClientProfileDB`, `ResearchKB`, and now the session store) follows the same connect→WAL-pragma→row_factory pattern from Phase 2.
- Sub-agents (`ReconAgent` etc.) already have working `execute(target, **kwargs)` methods reachable via `BaseAgent` — OmO's Executor role calls these directly, no new sub-agent interface needed.

### Integration Points
- `Orchestrator.__init__` already constructs `EngineRouter`, `InstructionParser`, `ToolSelector`, `ResponseComposer` — the wiring gap is entirely in `process()`/`process_stream()` never calling them, not in missing instantiation.
- `ws_handler.py`'s `manager.send(session_id, payload)` is the existing delivery primitive `PHASE_FAILED` events (and clawhip, if built as a routing layer per Claude's Discretion) will use.

</code_context>

<deferred>
## Deferred Ideas

- Parallel OmO dispatch for independent DAG directives — this phase is sequential-only (D-08); revisit once sequential is proven correct
- Full `StrategyEvolutionEngine` and `ResearchDaemon` wiring (beyond the minimal stubs in D-10) — v1.1 Phase 9 (Auto Research & Strategy Evolution)
- CollabWebSocket / multi-user RBAC delivery — explicitly out of scope (D-09), matches the project-wide exclusion

</deferred>

---

*Phase: 03-orchestration-upgrade*
*Context gathered: 2026-09-01*
