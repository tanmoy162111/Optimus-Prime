# Phase 3: Orchestration Upgrade - Research

**Researched:** 2026-09-01
**Domain:** Backend coordination architecture (Python/FastAPI) — hand-rolled multi-stage agent dispatch, no new AI framework
**Confidence:** HIGH (all findings verified directly against live source files in this repo; no external library research needed beyond what 03-AI-SPEC.md already locked)

> **Scope note:** `03-AI-SPEC.md` (Sections 2, 3, 4, 4b) already locks the OmX/OmO Pydantic schema, forced-tool-use pattern, sequential dispatch loop, SQLite+WAL session-store pattern, project structure, 5 pitfalls, and eval strategy. This document does **not** repeat that content — it answers the 6 gap questions the orchestrator specifically asked for, plus the standard RESEARCH.md scaffolding (pitfalls found in the *existing* code, Wave 0 test gaps, security domain). Read 03-AI-SPEC.md first; treat it as ground truth.

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions

- **D-00:** The original "switch orchestration to DeepSeek-V3" goal conflicted with the Anthropic+Ollama-only constraint. Resolved: constraint updated to explicitly allow multi-provider routing. This is NOT a Claude replacement.
- **D-01:** Full 3-layer architecture reconstruction per `OPTIMUS_PRIME_ARCHITECTURE.md` §3 (OmX Workflow Planner, clawhip Event Router, OmO Multi-Agent Coordinator) — not a minimal stand-in. Operator chose this explicitly after being told the minimal-scope alternative.
- **D-02:** Wire the real agent dispatch loop as part of OmO's Executor role — OmO's execution IS the multi-step loop: parse intent → route to engine → select tools → invoke sub-agents → track `EngagementState.phase_status`. This reconciles two existing inconsistencies as part of the same work:
  - `instruction_parser.py` contains a duplicate `EngineRouter` class and its `InstructionParser.parse()` expects `backend.agent.conversation.SessionState`, not the `EngagementSession` the orchestrator actually holds — these must be reconciled (dedupe `EngineRouter`, fix the session-type mismatch) as part of wiring the loop, not left as-is.
  - Currently `Orchestrator.process()`/`process_stream()` never call `EngineRouter`, `InstructionParser`, `ToolSelector`, or any sub-agent — it is LLM-completion-only. This phase makes those real calls.
- **D-09 (clawhip delivery targets):** clawhip delivers to the frontend WebSocket and XAI audit trail. It does **NOT** deliver to `CollabWebSocket (RBAC)` — multi-user collaboration is explicitly out of scope for this project (`PROJECT.md` Out of Scope: "Real-time collaboration — single operator per engagement"). Do not build a CollabWebSocket delivery path even as a stub.
- **D-10 (not-yet-built dependency handling):**
  - `StrategyEvolutionEngine` (OmO's Architect role) — orphaned today. Build a **minimal stub** now.
  - Research-daemon delivery (a clawhip monitoring/delivery target) — orphaned today. Build a **minimal stub** delivery channel (no real listener yet).
  - `TaskRegistry` (the OmO handoff protocol's task-state store) — does not exist anywhere. Build this **for real** (not a stub) — it's core to this phase's own coordination logic.
- **D-06:** LLM-driven. OmX asks Claude (via `LLMRouter`, mode="orchestration") to decompose the operator's request into a directive DAG. Not rule/template-based matching.
- **D-07:** One OmX directive is the failure unit. If a sub-agent/tool call within a directive fails, OmO reports that whole directive as `PHASE_FAILED` over the WebSocket with the underlying error attached. Not per-individual-tool-call granularity.
- **D-08:** Sequential only for this phase. Directives execute one at a time in DAG order, even when the DAG has independent directives that could theoretically run in parallel. Parallel dispatch is deferred.
- **D-03:** SQLite-backed session persistence. Matches Phase 2's DATA-01 WAL-mode hardening pattern. One connection, `PRAGMA journal_mode=WAL` applied on connect, straightforward reconnect-by-session_id query.
- **D-04:** Claude = orchestration (unchanged). Ollama/Qwen = compaction (new mode). DeepSeek = wired as a configurable additional provider option, not required to be exercised by default — Claude is never removed as a provider.

### Claude's Discretion

- Exact `TaskRegistry` schema (in-memory dict vs. SQLite-backed alongside session persistence — planner's call given D-03 already introduces SQLite in this phase)
- Exact WebSocket message schema for `PHASE_FAILED` (beyond: names which directive failed and why)
- Whether clawhip is implemented as a distinct module/class or as a thin routing layer inside the existing `ConnectionManager` — planner's call given the "no CollabWebSocket" scope reduction

### Deferred Ideas (OUT OF SCOPE)

- Parallel OmO dispatch for independent DAG directives — this phase is sequential-only (D-08); revisit once sequential is proven correct
- Full `StrategyEvolutionEngine` and `ResearchDaemon` wiring (beyond the minimal stubs in D-10) — v1.1 Phase 9 (Auto Research & Strategy Evolution)
- CollabWebSocket / multi-user RBAC delivery — explicitly out of scope (D-09), matches the project-wide exclusion
</user_constraints>

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| ORCH-01 | `PHASE_FAILED` events are propagated through the agent execution loop and surfaced to the operator via the WebSocket event stream | Architecture Patterns §1 (clawhip design) resolves the concrete delivery mechanism (`ConnectionManager` extension + `ClawhipEvent` schema). Common Pitfalls documents the exact silent-drop point (`process_stream()` never calls `OmO`) this requirement must close. |
| ORCH-02 | `LLMRouter` supports task-based routing across multiple configured providers (Claude, Ollama, DeepSeek) — Claude retained | Common Pitfalls documents `config.py`'s missing `qwen_model`/`deepseek_*` fields (must be added before D-04 can be implemented) and `.env.example`'s existing `MISTRAL_MODEL` field the current Ollama fallback already uses. |
| ORCH-03 | `OmX` planner implements an 8-directive phase DAG, operating as a separate component from `OmO` | 03-AI-SPEC.md Section 3/4 fully specifies this; this doc adds no new content here per scope note — see Architecture Patterns §5 (wiring path) for how `Orchestrator.process_stream()` calls it without breaking `ws_handler.py`. |
| PERSIST-01 | Engagement sessions are serialized to disk and reloaded on reconnect after a process restart | Architecture Patterns §2 (TaskRegistry schema) and Common Pitfalls (`SessionStore` identity-semantics break, `EngagementSession` has no serialization helpers) directly address the concrete implementation gaps. |
</phase_requirements>

## Summary

This phase's AI/LLM design is fully specified by 03-AI-SPEC.md — nothing here contradicts or re-derives it. What AI-SPEC.md does not cover is the **concrete shape of the plain-Python glue code** connecting six pieces of *already-existing* code that were never wired together, plus several **pre-existing defects in that code** the planner must account for or the phase will fail at integration time regardless of how correct the new OmX/OmO/clawhip code is.

Three findings drive this research's recommendations. First, `instruction_parser.py`'s `EngineRouter` (lines 11–36) is a byte-for-byte duplicate of the canonical `engine_router.py`'s `EngineRouter` — dedup is a pure deletion-plus-import-fix, not a merge. Second, `InstructionParser.parse()` has **zero callers anywhere in the codebase** (confirmed by full-repo grep) — it can be freely re-signed to accept `EngagementSession` instead of `SessionState` with no call-site breakage beyond the file itself. Third, and most consequential for planning: two components AI-SPEC.md's Section 4b explicitly directs this phase to reuse — `backend/agent/conversation_summariser.py` (Context Window Management) and `backend/intelligence/strategy_evolution.py` (OmO's Architect role, D-10) — are **currently broken** if invoked as-is. `ConversationSummariser.__init__` reads `settings.summariser_threshold`, a field that does not exist on `backend/config.py`'s `Settings` class (it only exists as an unused `.env.example` comment) — instantiating it today raises `AttributeError`. `StrategyEvolutionEngine._enrich_node()` calls `self._memory.get_best_tools(...)`, a method `SmartMemory` (the stub built in Phase 1) does not implement — calling `enrich_chain()` today raises `AttributeError`. Both must be fixed (a one-line config field addition; a stub method on `SmartMemory`) before this phase's own code can safely call them, or the planner must gate those specific calls behind explicit try/except with the stub-fallback D-10 already permits.

**Primary recommendation:** Build `clawhip` as a thin typed-event layer bolted onto the existing `ConnectionManager` (not a distinct module) — introduce a `ClawhipEvent` Pydantic model with an `event_type` field, keep `ConnectionManager.send()` as the sole WebSocket write path, and route XAI delivery through a new `ExplainableAI.log_decision()` call site (currently zero callers — this phase gives it its first). Build `TaskRegistry` as a fourth table in the same SQLite database and connection as the new `SessionStore` (not a separate DB file or process) — transactional consistency with `phase_status` writes matters more here than component isolation, and D-03 already pays the SQLite-integration cost once. Reconcile `instruction_parser.py` by deleting its duplicate `EngineRouter` (import the canonical one instead) and changing `InstructionParser.parse()`'s type annotation from `SessionState` to `EngagementSession` — this is a signature change with zero live callers to break.

## Architectural Responsibility Map

| Capability | Primary Tier | Secondary Tier | Rationale |
|------------|-------------|----------------|-----------|
| OmX plan decomposition (DAG generation) | API/Backend | — | Pure server-side LLM call; no client involvement until the plan or its failure is reported |
| OmO sequential dispatch (agent execution loop) | API/Backend | — | Calls `BaseAgent.execute()` directly; runs inside the same FastAPI process as the WebSocket handler, per pitfall #2 in AI-SPEC.md Section 3 (must never spawn a nested event loop) |
| clawhip event routing (PHASE_FAILED, lifecycle) | API/Backend | Browser/Client (consumer) | Formats and pushes events; the browser only renders what it receives over the existing `/ws/chat` socket — no new client-side protocol logic needed beyond handling new `type` values in the existing `iter_json()`-style message loop |
| TaskRegistry (directive handoff state) | Database/Storage | API/Backend (writer) | Must survive a process restart to fulfill PERSIST-01's "detect crash mid-directive" purpose — an in-memory dict cannot do this; SQLite is the only tier that satisfies both D-03's precedent and PERSIST-01's requirement |
| SessionStore persistence | Database/Storage | API/Backend (writer) | Same reasoning — D-03 explicit |
| Multi-provider LLM routing (ORCH-02) | API/Backend | — | `LLMRouter.complete()` is a server-side facade; no client visibility into which provider handled a given call except via server logs |
| XAI audit trail | Database/Storage (future) / API/Backend (this phase) | — | `ExplainableAI` is in-memory only today (`self.audit_log: List[Dict]`, no persistence) — this phase's minimum bar is "clawhip calls `log_decision()` for real," not "XAI survives a restart" (that's AI-SPEC.md Section 7's *future* escalation path, not a phase requirement) |

## Standard Stack

### Core

No new packages. Every dependency this phase needs is already pinned in `backend/requirements.txt`:

| Library | Version | Purpose | Why Standard |
|---------|---------|---------|---------------|
| `anthropic` | 0.38.0 | OmX forced tool-use DAG generation | Already the project's sole Claude SDK client; AI-SPEC.md Section 3 confirms `ToolChoiceToolParam`/`disable_parallel_tool_use` compatibility |
| `pydantic` | 2.9.2 | `Directive`/`EngagementPlan`/`ClawhipEvent` schema definition + validation | Already the project's validation library (`backend/config.py`, `backend/session/engagement_session.py` use dataclasses today, but `pydantic` is already a direct dependency for `Settings`) |
| stdlib `sqlite3` + `asyncio.to_thread` | — | `SessionStore` and `TaskRegistry` persistence | Verbatim pattern already used by `backend/memory/client_profile.py` and `backend/intelligence/research_kb.py` |
| stdlib `asyncio` | — | `OmO.dispatch()` sequential loop, `asyncio.wait_for()` per-directive timeout | No new dependency; every async layer in this codebase already uses it |

**Installation:**
```bash
# Nothing to install — verified against backend/requirements.txt:
grep -E "^(anthropic|pydantic)" backend/requirements.txt
# anthropic==0.38.0
# pydantic==2.9.2
# pydantic-settings==2.6.1
```

**Version verification:** `pip index versions anthropic` and `pip index versions pydantic` were not run — both packages are already installed and pinned in this repo's own lockfile; re-verifying registry currency is unnecessary since no version change is proposed. [VERIFIED: backend/requirements.txt]

## Package Legitimacy Audit

**Not applicable — this phase installs zero new external packages.** Every library used (`anthropic`, `pydantic`, stdlib `sqlite3`/`asyncio`) is already present in `backend/requirements.txt` and already running in production code elsewhere in this repo (`client_profile.py`, `research_kb.py`, `llm_router.py`). The Package Legitimacy Gate protocol is skipped per its own trigger condition ("Every phase that installs external packages").

**Packages removed due to slopcheck verdict:** none (no packages evaluated — none installed)
**Packages flagged as suspicious:** none

## Architecture Patterns

### System Architecture Diagram

```
Operator message (WS "chat" event)
        |
        v
ws_handler.websocket_chat()  ──────────────────────────────────┐
        |                                                       │
        v                                                       │
Orchestrator.process_stream(message, session, mode)             │
        |                                                       │
        │ (1) OmX.plan(directive_text, session)                 │
        │       -> Claude forced-tool-use call                  │
        │       -> validated EngagementPlan (or                 │
        │          OmXPlanValidationError after 3 attempts)     │
        v                                                       │
   pre-dispatch validation gate (Section 5/6 of AI-SPEC.md)     │
        │  scope-membership + agent-registry + cycle checks     │
        │  FAIL -> clawhip.emit(PLAN_REJECTED) --------------→ ConnectionManager.send()
        │  PASS                                                 │        |
        v                                                       │        v
   OmO.dispatch(plan, session, agents)                          │   frontend WebSocket
        │  for each directive (sequential, D-08):                │   (operator sees event)
        │    TaskRegistry.mark(directive.id, "running")          │
        │    session.state.set_phase_status(directive.id,        │
        │                                    "running")          │
        │    try: await asyncio.wait_for(                        │
        │           agent.execute(directive.target, ...),        │
        │           timeout=...)                                 │
        │    on success:                                         │
        │       TaskRegistry.mark(directive.id, "completed")      │
        │       session.state.add_finding(result)                 │
        │       clawhip.emit(PHASE_COMPLETED) ------------------→│
        │    on exception/timeout:                                │
        │       TaskRegistry.mark(directive.id, "failed")         │
        │       session.state.set_phase_status(directive.id,      │
        │                                       "failed")         │
        │       clawhip.emit(PHASE_FAILED, directive, error) ---→│
        v                                                        │
   ResponseComposer.compose(...)                                 │
        │  turns completed/failed directive results into          │
        │  operator-facing chat reply                             │
        v                                                        │
   yield chunks back through process_stream() -------------------┘
        |
        v
SessionStore.save(session)  (SQLite WAL write — PERSIST-01)
```

### Recommended Project Structure

Matches 03-AI-SPEC.md Section 3's "Recommended Project Structure" verbatim — see that document. This research adds one clarification: `clawhip.py` should be a **new small module** (`backend/agent/clawhip.py`), not folded directly into `ws_handler.ConnectionManager` — see Pattern 1 below for why "distinct module, thin dependency on ConnectionManager" beats both extremes.

### Pattern 1: clawhip as a thin typed-event module wrapping `ConnectionManager`

**What:** A small `Clawhip` class in `backend/agent/clawhip.py` that (a) defines a `ClawhipEvent` Pydantic model, (b) holds a reference to the existing `ws_handler.manager` (`ConnectionManager` singleton) and the `ExplainableAI` instance, and (c) exposes one method, `emit(session_id, event)`, that both calls `manager.send(session_id, event.model_dump())` and calls `xai.log_decision(...)` when the event represents a decision worth auditing (not every lifecycle tick — see Common Pitfalls).

**Why not "fold into ConnectionManager" (the other CONTEXT.md discretion option):** `ConnectionManager` today is purely transport (`active: Dict[str, WebSocket]`, `send()`). Folding event *formatting* and *XAI delivery* into it would make a transport class responsible for domain semantics (what a `PHASE_FAILED` payload looks like, when to audit-log), which the existing codebase's layering explicitly avoids elsewhere (`ResponseComposer` is a separate class from `ConnectionManager` for the same reason — formatting is not transport). A 15–30 line `clawhip.py` costs nothing and keeps `ConnectionManager` a pure WebSocket registry, matching this codebase's existing single-responsibility pattern (`ToolSelector` vs `EngineRouter` vs `ResponseComposer` are all separate small classes already).

**Why not "fully distinct module with its own delivery abstraction":** AI-SPEC.md's Section 2 rationale (hand-rolled, no framework) and D-09's scope reduction (no CollabWebSocket) both argue against building a generic pub/sub abstraction — there is exactly one live delivery target (frontend WS) plus one audit sink (XAI), so `Clawhip.emit()` can be a direct two-call method, not an event-bus-with-subscribers pattern. `OPTIMUS_PRIME_ARCHITECTURE.md`'s "unified EventBus (Section 10)" reference is aspirational architecture-doc language; this codebase has no live EventBus implementation today (confirmed: no `event_bus.py`/`EventBus` class exists under `backend/`; `research_daemon.py`'s constructor accepts an *optional* `event_bus: Any = None` and treats it as inert when absent). Building a real EventBus is out of this phase's scope per D-01/D-09 (full 3-layer reconstruction of OmX/clawhip/OmO specifically — not a new pub/sub subsystem the architecture doc merely gestures at).

**Recommended shape:**
```python
# backend/agent/clawhip.py
from enum import Enum
from typing import Any, Optional
from pydantic import BaseModel


class ClawhipEventType(str, Enum):
    PHASE_STARTED = "PHASE_STARTED"
    PHASE_COMPLETED = "PHASE_COMPLETED"
    PHASE_FAILED = "PHASE_FAILED"
    PLAN_REJECTED = "PLAN_REJECTED"  # pre-dispatch validation gate failure


class ClawhipEvent(BaseModel):
    event_type: ClawhipEventType
    directive_id: Optional[str] = None
    detail: str = ""
    error: Optional[str] = None


class Clawhip:
    """Routes lifecycle/finding/phase events to the frontend WS and XAI audit trail.
    Does NOT deliver to CollabWebSocket (D-09 — out of scope)."""

    def __init__(self, connection_manager, xai_logger):
        self._manager = connection_manager   # ws_handler.manager
        self._xai = xai_logger               # ExplainableAI instance

    async def emit(self, session_id: str, event: ClawhipEvent) -> None:
        await self._manager.send(session_id, event.model_dump(mode="json"))
        if event.event_type in (ClawhipEventType.PHASE_FAILED, ClawhipEventType.PLAN_REJECTED):
            self._xai.log_decision(
                decision_type=event.event_type.value,
                reasoning=event.detail,
                confidence=1.0,
                factors=[event.directive_id or "plan-level"],
            )
```

This keeps the existing `{"chunk": ..., "done": ...}` ad-hoc-dict pattern for the streaming chat reply (unchanged — `ResponseComposer` output), and introduces the **typed** `ClawhipEvent` model only for the new lifecycle/failure event class, which is exactly what CONTEXT.md's discretion note asks the planner to decide (typed vs. ad-hoc) — the answer is: type the new thing, don't retrofit the old thing.

### Pattern 2: TaskRegistry as a table in the same SQLite connection as SessionStore

**What:** `TaskRegistry` (backend/agent/task_registry.py, per AI-SPEC.md's project structure) persists directive-level handoff state (`Created`/`Running`/`Completed`/`Failed`) to a `task_registry` table in the **same** SQLite database file `SessionStore` uses (e.g. `data/sessions/sessions.db`), reusing the same connection object and WAL pragma pair — not a separate `.db` file, not a separate `sqlite3.connect()` call.

**Why same DB, same connection (not "genuinely separate concern" per the alternative CONTEXT.md floated):** AI-SPEC.md Section 4 states `TaskRegistry` exists specifically to let OmO "detect a directive that was dispatched but never reported a terminal status... after a crash mid-directive" — this is fundamentally a **consistency problem between two writes** (a `phase_status` update and a `task_registry` status update happening for the same directive transition). If these live in separate SQLite files/connections, a crash between the two commits produces exactly the ambiguous state TaskRegistry was built to eliminate (WAL mode makes a *single* connection's writes atomic per-statement, but gives no cross-database atomicity guarantee). Sharing one connection means both tables can, if the planner chooses, be updated inside a single `BEGIN...COMMIT` transaction — the only way to make "TaskRegistry disagrees with phase_status after a crash" structurally impossible rather than merely unlikely. This directly serves PERSIST-01's "resumed session state must be trustworthy" requirement, not just TaskRegistry's own D-10 mandate.

**Minimal schema:**
```sql
CREATE TABLE IF NOT EXISTS task_registry (
    session_id    TEXT NOT NULL,
    directive_id  TEXT NOT NULL,
    agent_name    TEXT NOT NULL,
    status        TEXT NOT NULL CHECK(status IN ('created','running','completed','failed')),
    created_at    TEXT NOT NULL,
    updated_at    TEXT NOT NULL,
    error_detail  TEXT,
    PRIMARY KEY (session_id, directive_id)
);
CREATE INDEX IF NOT EXISTS idx_task_registry_session ON task_registry(session_id);
```

`session_id` + `directive_id` as a composite primary key is sufficient — directive IDs are only unique within one `EngagementPlan`/session, matching `Directive.id: str`'s scope in AI-SPEC.md's schema. `agent_name` is stored (not just looked up from the plan) specifically so a post-crash reconciliation pass can log which agent a stalled directive was assigned to without needing the original `EngagementPlan` object in memory.

**Crash-detection query on session resume** (the concrete mechanism PERSIST-01 + D-10 require):
```python
# On SessionStore.resolve() / reconnect:
stale = conn.execute(
    "SELECT directive_id, agent_name FROM task_registry "
    "WHERE session_id = ? AND status = 'running'",
    (session_id,),
).fetchall()
# Any row here means a directive was dispatched but never reported completed/failed
# before the process died — surface as a PHASE_FAILED-equivalent "unknown outcome"
# event via clawhip, per the Guardrails table's "Any session-resume mismatch -> ERROR,
# halt further dispatch" rule in AI-SPEC.md Section 7.
```

### Pattern 3: `instruction_parser.py` reconciliation — the exact diff shape

**What was verified (full-repo grep, not assumed):**
- `backend/agent/instruction_parser.py`'s `EngineRouter` class (lines 11–36) is **byte-identical** to `backend/agent/engine_router.py`'s `EngineRouter` class — same method bodies, same regex patterns, same `_is_ml_target` helper. [VERIFIED: direct file comparison]
- `grep -rn "InstructionParser" backend/` returns exactly two hits: the class definition itself, and `orchestrator.py`'s `self.parser = InstructionParser()` — the constructor is called, but `.parse()` is never invoked anywhere in `orchestrator.py`'s `process()`/`process_stream()`, nor in any test file. [VERIFIED: grep]
- `grep -rn "EngineRouter" backend/` shows the canonical `engine_router.py` version is also only ever *constructed* (`self.engine_router = EngineRouter()` in `orchestrator.py`), never `.dispatch()`-called. [VERIFIED: grep]

**What this means for the planner:** the reconciliation D-02 requires is **not risky** — there is no live call site whose behavior could regress from a signature change. The concrete diff:

```python
# backend/agent/instruction_parser.py — BEFORE
from backend.agent.conversation import SessionState

class EngineRouter:              # DELETE — duplicate of engine_router.py
    def dispatch(self, intent, target=None): ...
    def _is_ml_target(self, target): ...

class InstructionParser:
    def parse(self, message: str, session: SessionState, mode=None) -> Dict[str, Any]:
        ...
        return {..., "mode": mode or session.mode}
```

```python
# backend/agent/instruction_parser.py — AFTER
from backend.session.engagement_session import EngagementSession
# EngineRouter class removed entirely — callers import from backend.agent.engine_router

class InstructionParser:
    def parse(self, message: str, session: EngagementSession, mode=None) -> Dict[str, Any]:
        ...
        return {..., "mode": mode or "InfrastructureEngine"}  # see note below
```

**Note on the `session.mode` field mapping gap:** `SessionState.mode` (the old type) defaults to `"InfrastructureEngine"` and is set once per session. `EngagementSession` has **no equivalent field** — the closest analog is `EngineRouter.dispatch(intent, target)`'s *return value*, which is computed per-message, not stored per-session. This is not a like-for-like rename: `InstructionParser.parse()`'s `mode` key in its return dict should be re-derived from calling `EngineRouter.dispatch(intent, target)` inline (the intent/target this same `parse()` call just computed), not read from a session field that doesn't exist on `EngagementSession`. This makes `InstructionParser.parse()` a genuine merge point for `EngineRouter.dispatch()` — which is exactly what D-02's "route to engine" step in OmO's Executor-role loop needs it to be. **This is the one place in D-02's reconciliation that is a real design decision, not a mechanical rename** — flag it for the plan's task breakdown.

### Pattern 4: `Orchestrator.process_stream()` → OmO wiring, minimal diff against `ws_handler.py`

**What must not change:** `ws_handler.py` line 73 calls `async for chunk in orchestrator.process_stream(message=text, session=session, mode=mode): await manager.send(session_id, {"chunk": chunk, "done": False})`. This calling convention — an async generator yielding `str` chunks — must be preserved exactly, since `ws_handler.py` is out of this phase's touch list per CONTEXT.md's canonical refs (it's listed only as "the existing delivery primitive `PHASE_FAILED` events... will use", not as a file this phase rewrites).

**Minimal-diff restructuring:**
```python
# backend/agent/orchestrator.py — process_stream(), AFTER
async def process_stream(self, message, session, mode=None):
    session.conv_history.add_message("user", message)

    plan = await self.omx.plan(message, session)              # stage 1
    await self.omo.dispatch(plan, session, self._agents)        # stage 2 (emits clawhip
                                                                  #  events internally, does
                                                                  #  NOT yield chunks itself)
    reply = self.composer.compose(                              # stage 3
        decision={"intent": ..., "engine": ..., ...},
        findings=session.state.findings,
        session_state=session.state.__dict__,
    )
    session.conv_history.add_message("assistant", reply)

    for word in reply.split():          # preserves the existing word-by-word yield
        yield word + " "                # contract ws_handler.py already depends on
```

`Orchestrator.__init__` gains `self.omx = OmX(self.llm_router)`, `self.omo = OmO(self._agents, self.clawhip, self.task_registry)`, and `self._agents = {"ReconAgent": ReconAgent(), "ScanAgent": ScanAgent(), ...}` — a dict built once from the 11 concrete `BaseAgent` subclasses already in `backend/agent/sub_agents/` (`cloud_agent.py`, `data_sec_agent.py`, `endpoint_agent.py`, `exploit_agent.py`, `genai_agent.py`, `iam_agent.py`, `ics_agent.py`, `intel_agent.py`, `model_sec_agent.py`, `recon_agent.py`, `scan_agent.py` — confirmed via `ls backend/agent/sub_agents/*.py`). Each subclass's `__init__` takes zero arguments (verified against `ReconAgent.__init__`) — the registry can be built as simple no-arg construction, no factory needed.

`Orchestrator.process()` (the non-streaming REST path used by `chat_routes.py`) should get the identical 3-stage restructuring for consistency, collapsing the final `reply` into a single dict return instead of yielding chunks — not researched further here since AI-SPEC.md's Core Pattern (Section 4) already describes this pipeline generically for "per operator message," covering both entry points.

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|--------------|-----|
| Structured DAG output from Claude | A JSON-prose parser with regex extraction | Anthropic SDK forced tool use (`tool_choice={"type": "tool", ...}`) — already locked in AI-SPEC.md Section 3 | Prose parsing is exactly the failure mode `disable_parallel_tool_use` was designed to eliminate; re-deriving this here would contradict AI-SPEC.md ground truth |
| Generic pub/sub event bus for clawhip | A new `EventBus` class with subscribe/publish semantics | Direct two-call `Clawhip.emit()` (Pattern 1 above) | Exactly one delivery target (WS) + one audit sink (XAI) exist today; a subscriber-list abstraction is speculative generality for a single-operator system with `CollabWebSocket` explicitly excluded (D-09) |
| Cross-process directive-crash detection | A separate heartbeat/watchdog process | The `task_registry` `status='running'` query on session resume (Pattern 2) | The existing SQLite-on-resume pattern already answers "did this survive a restart cleanly" for `SessionStore`/`ClientProfileDB`; a watchdog process is unneeded infrastructure for a personal-use, restart-triggered-by-the-operator system |
| Token counting for the `max_tokens=2048` OmX call sizing | A custom tokenizer | `tiktoken` (already a pinned dependency, already used by `conversation_summariser.py`'s `_estimate_tokens`) | No new dependency; the estimate-then-cap pattern is already established in this codebase |

**Key insight:** every "don't hand-roll" temptation in this phase is a temptation to build infrastructure for scale (multi-subscriber events, watchdog processes, custom tokenizers) that a single-operator, personal-use, sequential-only (D-08) system does not need. The theme across this whole research: reuse the SQLite-WAL pattern once, reuse the Pydantic-forced-tool-use pattern once, and resist generalizing either into a framework.

## Common Pitfalls

### Pitfall 1: `ConversationSummariser` is broken today — instantiating it raises `AttributeError`
**What goes wrong:** `backend/agent/conversation_summariser.py:12` reads `settings.summariser_threshold`. `backend/config.py`'s `Settings` class (the pydantic-settings model) has no `summariser_threshold` field — only `bearer_token`, `anthropic_api_key`, `ollama_host`, `claude_model`, `mistral_model`, `embed_model`, `kali_host/port/user/password`. `.env.example` has a `SUMMARISER_THRESHOLD=60000` line, but pydantic-settings only exposes *declared* fields — an undeclared env var is silently ignored, not auto-added as an attribute.
**Why it happens:** the field was documented in `.env.example` during an earlier phase but never added to `Settings`, and `ConversationSummariser` has zero test coverage (confirmed: no `test_*summari*` file exists under `tests/`) so the break was never caught.
**How to avoid:** add `summariser_threshold: int = 60000` to `backend/config.py`'s `Settings` class *before* any code in this phase calls `ConversationSummariser()`. This is a one-line fix but must land as an explicit task — AI-SPEC.md Section 4b's "Context Window Management" strategy depends on this class working.
**Warning signs:** `AttributeError: 'Settings' object has no attribute 'summariser_threshold'` the first time `ConversationSummariser()` is instantiated in a test or at runtime.
**Verified:** `grep -rn "summariser_threshold" backend/` returns exactly one hit (the read site itself) — confirms the field is genuinely absent, not just hard to find.

### Pitfall 2: `StrategyEvolutionEngine.enrich_chain()` is broken today — `SmartMemory.get_best_tools()` does not exist
**What goes wrong:** `backend/intelligence/strategy_evolution.py`'s `_enrich_node()` calls `await self._memory.get_best_tools(target_type=..., top_k=10)`. `backend/memory/smart_memory.py`'s `SmartMemory` class (the Phase-1-confirmed stub) only implements `store()`, `_save()`, `search()`, `get_session_memory()` — no `get_best_tools` method anywhere.
**Why it happens:** `SmartMemory` was deliberately left as a minimal stub in Phase 1 (STATE.md: "SmartMemory needs full implementation (embedding_fn, store_finding, detect_systemic, get_best_tools) — 11 tests xfailed"), and `StrategyEvolutionEngine` was written against the *intended* full interface, not the actual stub.
**How to avoid:** since D-10 only requires a "minimal stub" for `StrategyEvolutionEngine`'s integration point this phase (not full functionality), the safest path is: **do not call `StrategyEvolutionEngine.enrich_chain()` for real this phase.** Build OmO's Architect-role stub as a no-op wrapper that either (a) never calls `_enrich_node`'s tool-lookup branch, or (b) adds a minimal `get_best_tools()` stub to `SmartMemory` that returns `[]` (matching `search()`'s existing "return what little I have" pattern) so the call doesn't crash but also doesn't pretend to enrich anything. Option (b) is lower-risk — it makes the *existing* `StrategyEvolutionEngine` code path safe to call rather than requiring the planner to special-case around it.
**Warning signs:** `AttributeError: 'SmartMemory' object has no attribute 'get_best_tools'` the moment any chain node with a `tool` field is enriched.

### Pitfall 3: `SessionStore`'s existing test suite assumes in-memory object identity — migrating to SQLite breaks 2 of 8 tests by design
**What goes wrong:** `tests/session/test_session_store.py::test_resolve_returns_same_object` asserts `resolved is created` (Python object identity). A SQLite-backed `SessionStore.resolve()` that reconstructs an `EngagementSession` from a disk row on every call cannot satisfy `is` identity unless an in-memory cache is layered on top. `test_multiple_sessions_are_independent` also implicitly relies on live object references (`a.conv_history.add_message(...)` then asserting `b.conv_history.messages == []` — this still passes under a reconstruct-from-disk model since `a` and `b` are genuinely different sessions, but only if `resolve()` is called once and the returned object is mutated in-place for the remainder of that request, not re-fetched from disk mid-request).
**Why it happens:** the current `SessionStore` is a pure `Dict[str, EngagementSession]` — the existing tests were written against that semantics and never anticipated a persistence-backed rewrite.
**How to avoid:** decide explicitly (and document in the plan) whether `SessionStore` becomes **cache-plus-persistence** (keep an in-memory `Dict[str, EngagementSession]` as the hot path, SQLite as the write-behind/restart-recovery layer — `resolve()` checks memory first, falls back to SQLite reconstruction only on a cache miss, e.g. after restart) or **pure SQLite** (every `resolve()` hits disk, `test_resolve_returns_same_object` gets rewritten to assert equality of `session_id`/`scope`/`conv_history` contents instead of identity). The cache-plus-persistence model is recommended — it matches `ws_handler.py`'s per-message `session_store.resolve(session_id)` call pattern (called on every single "chat" message; hitting SQLite on every message when the session is already resident in memory is unnecessary I/O for a personal-use system) and requires touching only 1 test assertion instead of rewriting the whole suite's mental model.
**Warning signs:** `test_resolve_returns_same_object` failing after the SQLite migration lands — this is an expected, plannable test update, not a regression, provided the cache-plus-persistence model is chosen; if it fails and no cache exists, that's a real design gap.

### Pitfall 4: `EngagementSession`/`ScopeConfig`/`EngagementState` have no `to_dict()`/`from_dict()` — unlike `SessionState`
**What goes wrong:** `backend/agent/conversation.py`'s (old, `SessionState`) class has a hand-written `to_dict()`. `backend/session/engagement_session.py`'s `EngagementSession` (the one actually in use) has **no serialization helper at all** — it's a plain `@dataclass` with a `datetime` field (`created_at`, `last_active`) and nested dataclasses (`ScopeConfig`, `ConversationHistory`, `EngagementState`). `dataclasses.asdict()` will recurse into the nested dataclasses correctly, but will leave `datetime` objects as Python `datetime` instances, not JSON-serializable strings — a naive `json.dumps(asdict(session))` will raise `TypeError: Object of type datetime is not JSON serializable`.
**Why it happens:** `EngagementSession` was built for pure in-memory use (Phase 1/2 scope); PERSIST-01 is the first requirement that needs it to cross a serialization boundary.
**How to avoid:** write an explicit `EngagementSession.to_row()`/`from_row()` pair (or a `json.dumps(asdict(session), default=str)` for the datetime fields specifically) as part of `SessionStore`'s SQLite implementation — don't assume `dataclasses.asdict()` + `json.dumps()` works out of the box.
**Warning signs:** `TypeError: Object of type datetime is not JSON serializable` the first time a session is persisted.

### Pitfall 5: "XAILogger" (the name used throughout `PROJECT.md`/`OPTIMUS_PRIME_ARCHITECTURE.md`) does not exist as a class — it is `ExplainableAI`, and it has zero callers and zero persistence
**What goes wrong:** every planning document (`PROJECT.md`'s Validated bullet, `OPTIMUS_PRIME_ARCHITECTURE.md` §3.3's Reviewer role) refers to "XAILogger." The actual class in `backend/reporting/explainable_ai.py` is named `ExplainableAI`, with a `log_decision(decision_type, reasoning, confidence, factors)` method. `grep -rln "explainable_ai\|ExplainableAI" backend/ tests/` returns exactly **one** file — the definition itself. It has never been instantiated or called anywhere, in code or tests. Its `audit_log` is a plain in-process `List[Dict]` — there is no persistence; a restart loses the entire audit trail (AI-SPEC.md Section 7 flags extending it to SQLite as a *future* escalation, not this phase's requirement, but this phase does give it its first real caller).
**Why it happens:** the class was scaffolded early and never wired to anything real, consistent with this codebase's broader pattern of orphaned intelligence/reporting modules (`STATE.md`'s 2026-08-29 correction: `intelligent_reporter.py`, `research_daemon.py`, `research_kb.py`, `intel_bus.py`, `dark_web_intel.py`, `source_adapters.py`, `client_profile.py`, `custom_tool_generator.py`, `compliance_mapping.py` are all similarly orphaned).
**How to avoid:** when writing plan tasks, refer to the actual class name `ExplainableAI` (import as `from backend.reporting.explainable_ai import ExplainableAI`), not "XAILogger" — a task that greps for `XAILogger` to find where to hook in will find nothing. Wire `Clawhip.emit()` (Pattern 1) as its first real caller for `PHASE_FAILED`/`PLAN_REJECTED` events only — not every lifecycle tick, per the Guardrails table in AI-SPEC.md Section 6 ("every decision logged with reasoning" for gate/failure events specifically, not high-frequency `PHASE_STARTED`/`PHASE_COMPLETED` noise).

### Pitfall 6: `config.py` has no `qwen_model`, `deepseek_api_key`, or `deepseek_model` fields — ORCH-02/D-04 cannot be implemented without adding them first
**What goes wrong:** D-04 requires `mode="compaction"` to route to "Ollama/Qwen" and an optional DeepSeek provider gated by `config.settings.deepseek_api_key` presence (per AI-SPEC.md Section 4's Model Configuration). `backend/config.py`'s `Settings` class today only has `mistral_model` (used by the existing, unconditional Ollama fallback path in `LLMRouter._ollama_complete`) — no `qwen_model` field exists, and no `deepseek_*` fields exist at all.
**Why it happens:** `config.py` predates the multi-provider decision (D-00, resolved during this phase's own discussion per `CLAUDE.md`'s commit reference).
**How to avoid:** add `qwen_model: str = "qwen2.5:7b"` (or whatever local Ollama tag the operator has pulled — flag as an `[ASSUMED]` default needing confirmation, see Assumptions Log), `deepseek_api_key: str = ""`, `deepseek_model: str = "deepseek-chat"`, `deepseek_base_url: str = "https://api.deepseek.com"` to `Settings` as part of this phase's ORCH-02 work — this is a prerequisite, not incidental to `LLMRouter.complete()`'s mode-dispatch extension.
**Warning signs:** `AttributeError: 'Settings' object has no attribute 'qwen_model'` when `LLMRouter.complete(mode="compaction")` is first exercised.

### Pitfall 7: OmX-generated `target` strings flow directly into f-string-interpolated shell commands in sub-agents — a pre-existing, explicitly-out-of-scope injection surface this phase's scope-membership gate does not close
**What goes wrong:** `ReconAgent.execute()` (and, by the same pattern, likely other sub-agents) builds shell commands via unescaped f-strings: `f"sublist3r -d {target} -o recon.txt"`. The code comment at `recon_agent.py:17-19` explicitly flags this as "a pre-existing command-injection-shaped pattern observed but explicitly out of scope for SEC-02 (workdir scoping only)." This phase's scope-membership validation gate (AI-SPEC.md Section 6, dimension 1) checks that `directive.target` is a *member of the approved scope list* — it does not (and per this pitfall, cannot) validate that the target string is free of shell metacharacters. A target that is legitimately in-scope (e.g. an operator-approved domain) but contains something like a backtick or `$()` in a crafted subdomain label would still pass the scope gate and still reach the vulnerable f-string.
**Why it happens:** the scope gate and the injection surface are orthogonal concerns — one validates *authorization*, the other validates *string safety* — and only the first is this phase's job per D-01/the Critical Failure Modes in AI-SPEC.md Section 1.
**How to avoid:** this phase does not need to fix the injection surface (it is explicitly out of scope, same as SEC-02's original carve-out) — but the planner should **not** claim the scope-membership gate makes directive dispatch "safe" in the security-domain sense; it only makes it *authorized*. Note this distinction in the phase's success-criteria language if the plan touches sub-agent code at all, so a future reader doesn't assume the gate is a full input-sanitization boundary.
**Warning signs:** none specific to this phase — flagging for awareness only, since OmX is a *new* source of `target` strings feeding this pre-existing sink.

## Code Examples

### OmO agent registry construction (referenced by Pattern 4)
```python
# backend/agent/orchestrator.py — Orchestrator.__init__
from backend.agent.sub_agents.cloud_agent import CloudAgent
from backend.agent.sub_agents.data_sec_agent import DataSecAgent
from backend.agent.sub_agents.endpoint_agent import EndpointAgent
from backend.agent.sub_agents.exploit_agent import ExploitAgent
from backend.agent.sub_agents.genai_agent import GenAIAgent
from backend.agent.sub_agents.iam_agent import IAMAgent
from backend.agent.sub_agents.ics_agent import ICSAgent
from backend.agent.sub_agents.intel_agent import IntelAgent
from backend.agent.sub_agents.model_sec_agent import ModelSecAgent
from backend.agent.sub_agents.recon_agent import ReconAgent
from backend.agent.sub_agents.scan_agent import ScanAgent

def _build_agent_registry() -> dict:
    # Verified: every BaseAgent subclass constructor takes zero arguments
    # (confirmed against ReconAgent.__init__ — name/engine/allowed_tools/priority
    # are all hardcoded in each subclass's own super().__init__() call).
    return {
        cls.__name__: cls()
        for cls in (CloudAgent, DataSecAgent, EndpointAgent, ExploitAgent, GenAIAgent,
                    IAMAgent, ICSAgent, IntelAgent, ModelSecAgent, ReconAgent, ScanAgent)
    }
```

### Pre-dispatch agent-registry validation (closes AI-SPEC.md Section 3 pitfall #3)
```python
# backend/agent/omo.py — called before OmO.dispatch() begins the loop
def validate_plan_against_registry(plan: "EngagementPlan", agents: dict) -> None:
    unknown = [d.agent for d in plan.directives if d.agent not in agents]
    if unknown:
        raise OmXPlanValidationError(
            f"Plan references unregistered agent(s): {unknown}. "
            f"Known agents: {sorted(agents.keys())}"
        )
```

### SessionStore cache-plus-persistence resolve() (resolves Pitfall 3)
```python
# backend/session/session_store.py
async def resolve(self, session_id: str) -> Optional[EngagementSession]:
    if session_id in self._sessions:          # hot path — same object identity preserved
        return self._sessions[session_id]
    row = await asyncio.to_thread(             # cold path — only hit after a restart
        lambda: self._conn.execute(
            "SELECT payload FROM sessions WHERE session_id = ?", (session_id,)
        ).fetchone()
    )
    if row is None:
        return None
    session = self._deserialize(row["payload"])  # from_row(), addresses Pitfall 4
    self._sessions[session_id] = session          # repopulate cache
    return session
```

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|---|---|---|---|
| `Orchestrator.process_stream()` streams the raw Claude completion word-by-word with no agent dispatch | 3-stage pipeline: OmX.plan() → OmO.dispatch() → ResponseComposer.compose(), still streamed word-by-word at the final stage | This phase (Phase 3) | The chat reply the operator sees stops being "whatever Claude free-associated" and starts being a report of what actually executed — this is the entire point of ORCH-01/ORCH-03 |
| `SessionStore` is a pure in-memory dict, lost on every restart | SQLite + WAL, cache-plus-persistence (Pitfall 3) | This phase (PERSIST-01) | Matches the precedent Phase 2 already set for `ClientProfileDB`/`ResearchKB` — this is the third SQLite-WAL-backed store in the codebase, not a new pattern |
| `LLMRouter.complete()` supports exactly two paths: Claude (orchestration) or Ollama (everything else, including the current unlabeled fallback) | Task-based multi-provider: Claude (orchestration), Ollama/Qwen (compaction, new), DeepSeek (optional, gated on API key presence) | This phase (ORCH-02/D-04) | The existing Ollama fallback-on-error behavior in `_claude_complete()` (line 53-55: `except Exception... falling back to Ollama`) is untouched by this — it's a distinct code path from the new `mode="compaction"` routing; don't conflate "fallback on Claude error" with "compaction routing," they solve different problems and both remain after this phase |

**Deprecated/outdated:** None — this phase adds capability, it does not deprecate any existing live path (the old `SessionState`/`ConversationManager` classes in `conversation.py` were already dead/orphaned before this phase per the confirmed-zero-callers grep, not deprecated by this phase's work).

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|----------------|
| A1 | `qwen_model` default value should be something like `"qwen2.5:7b"` | Pitfall 6 / Standard Stack | If the operator hasn't pulled a Qwen tag into their Ollama instance, `mode="compaction"` calls will fail at runtime with a 404-equivalent from Ollama's `/api/generate` — same failure shape as the Phase 1 `claude_model` bug (CLEAN-02) this project already fixed once. The planner should treat the exact Qwen model tag as an operator-confirmed value, not a hardcoded default, or add a startup/first-call health check mirroring what Phase 1 established for Claude. |
| A2 | DeepSeek's API is OpenAI-compatible (`https://api.deepseek.com`, chat-completions-shaped) and can be called via a lightweight `httpx`/`aiohttp` client without a new SDK dependency | Pitfall 6 / Standard Stack | If DeepSeek's actual API shape differs from this assumption (e.g. requires a dedicated SDK, different auth header, different endpoint path), the "wire DeepSeek as a configurable option" part of D-04 could need an additional dependency not currently accounted for. Since D-04 explicitly says DeepSeek is "not required to be exercised by default," this is a lower-risk assumption than A1 — worth a `checkpoint:human-verify` before the operator actually sets `deepseek_api_key`, not before the phase's core work lands. |
| A3 | `SmartMemory.get_best_tools()` should be stubbed to return `[]` rather than raising `NotImplementedError` (contrast with Phase 1's precedent of using `NotImplementedError` for `custom_tool_generator._register_tool()`) | Pitfall 2 | If `NotImplementedError` is preferred instead (matching the Phase 1 precedent for a different orphaned dependency), `StrategyEvolutionEngine.enrich_chain()` would need an explicit try/except around the tool-lookup branch instead of relying on `SmartMemory` to fail gracefully. Either approach satisfies D-10's "minimal stub" bar — this is a style choice the planner should make explicitly, not an accuracy risk. |

**If this table is empty:** N/A — see above; all three assumptions are implementation-default choices flagged for confirmation, not claims about what the codebase currently does (which were all verified via grep/direct read, not assumed).

## Open Questions (RESOLVED)

1. **Should `TaskRegistry` writes and `EngagementState.phase_status`/`SessionStore` writes share a single SQL transaction, or just a single connection?**
   - What we know: Pattern 2 recommends the same SQLite connection for both `SessionStore` and `TaskRegistry` for consistency reasons.
   - What's unclear: whether the planner should go further and wrap each directive's `TaskRegistry` status update + `phase_status` persistence in one `BEGIN...COMMIT` block (true atomicity) or treat "same connection, sequential writes" as sufficient given this is a single-operator, low-concurrency system where the crash window between two sequential `execute()`+`commit()` calls is narrow but not zero.
   - Recommendation: default to sequential same-connection writes (simpler, matches existing `ClientProfileDB` patterns which don't use explicit multi-statement transactions either) unless the plan-checker or eval-auditor flags PERSIST-01's "trustworthy resume" bar as requiring true transactional atomicity — this is a complexity/correctness tradeoff worth a `checkpoint:human-verify` if the planner is unsure, not a default to silently pick.
   - **RESOLVED:** `03-04-PLAN.md`'s threat model (T-03-05c) adopted the recommendation — same-connection sequential writes, no explicit multi-statement transaction wrapper.

2. **Does `ResponseComposer.compose()`'s existing signature (`decision: Dict`, `findings: List[Dict]`, `session_state: Dict`) need to change to accept the new `EngagementPlan`/directive-result shape, or can OmO's dispatch results be adapted to fit the existing dict shape?**
   - What we know: `ResponseComposer.compose()` already exists and is unused (constructed but never called, per CONTEXT.md's wiring-gap finding) — its current signature expects a single `decision` dict with `intent`/`engine`/`target`/`phase`/`tools` keys, which maps naturally to a *single* `InstructionParser.parse()` result, not a multi-directive `EngagementPlan`.
   - What's unclear: whether Pattern 4's wiring should call `compose()` once per completed directive (looping, concatenating output) or once at the end summarizing the whole plan — AI-SPEC.md's Core Pattern (Section 4) says "response composition... turns the completed/failed directive results into the operator-facing chat reply" (singular reply, implying once-at-the-end), but doesn't specify whether `ResponseComposer.compose()`'s signature itself needs a new multi-directive variant method or should be called in a loop.
   - Recommendation: this is a genuine implementation-shape decision the planner should resolve during task breakdown — likely add a new `compose_plan_summary(plan, session)` method to `ResponseComposer` rather than forcing `compose()`'s existing single-decision signature to awkwardly represent a multi-directive DAG result.
   - **RESOLVED:** `03-09-PLAN.md` Task 2 adopted the recommendation verbatim — added `compose_plan_summary(plan, session)` as a new method rather than forcing the existing single-decision `compose()` signature.

## Environment Availability

| Dependency | Required By | Available | Version | Fallback |
|------------|--------------|-----------|---------|----------|
| Ollama (local) | `mode="compaction"` (D-04), existing Ollama fallback path | Not probed — this is a runtime dependency the operator manages themselves per `CLAUDE.md`'s constraint ("operator manages their own Kali/Ollama instance"); no `ollama` binary or service assumed present in this research/planning environment | — | The existing `OllamaClient` already degrades gracefully on connection failure (`_ollama_complete` catches `Exception`, logs, returns `""`) — no new fallback needed, this behavior is inherited unchanged |
| DeepSeek API key | Optional DeepSeek provider route (D-04) | Not configured (`config.py` has no `deepseek_api_key` field yet — see Pitfall 6) | — | D-04 explicitly makes this optional: "gated by a `config.settings.deepseek_api_key` presence check so its absence never breaks orchestration or compaction" — already a documented no-op fallback in AI-SPEC.md |
| Anthropic API key | OmX plan generation (Claude, orchestration mode) | Present in `.env.example` template (`ANTHROPIC_API_KEY=sk-ant-`); actual operator key not verifiable from this research session | — | None — Claude is the load-bearing provider for OmX; if unavailable, `_claude_complete`'s existing fallback routes to Ollama, which would then need to handle forced-tool-use-shaped prompting it wasn't designed for (Ollama has no native tool-use API equivalent to Anthropic's `tool_choice`) — this is a real gap worth flagging to the planner: **OmX's Claude-error fallback path is undefined**, unlike the existing chat-completion fallback which works because free-text Ollama output is an acceptable substitute for free-text Claude output, but Ollama cannot produce the structured `tool_use` block OmX's `plan()` parses. |

**Missing dependencies with no fallback:**
- None outright blocking — but see the Anthropic API key row: OmX's structured-output dependency on Claude specifically (not "any LLM") is a design constraint the planner should surface explicitly, since it differs from every other LLM call in this codebase, which all tolerate an Ollama substitute.

**Missing dependencies with fallback:**
- Ollama (compaction path) — existing degrade-to-empty-string behavior, inherited unchanged
- DeepSeek — explicitly optional per D-04

## Validation Architecture

### Test Framework
| Property | Value |
|----------|-------|
| Framework | pytest 8.3.3 + pytest-asyncio 0.24.0 (`asyncio_mode="auto"`) |
| Config file | `pyproject.toml` (`testpaths = ["tests"]`, `python_files = ["test_*.py"]`) |
| Quick run command | `pytest tests/agent/ tests/session/ -x --tb=short` |
| Full suite command | `pytest tests/ --tb=short` |

### Phase Requirements → Test Map
| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|---------------------|---------------|
| ORCH-01 | `PHASE_FAILED` event reaches `ConnectionManager.send()` when a directive's `agent.execute()` raises | integration | `pytest tests/agent/test_omo.py::test_directive_failure_emits_phase_failed -x` | ❌ Wave 0 — `tests/agent/test_omo.py` does not exist |
| ORCH-01 | `session.state.phase_status[directive.id]` transitions to `"failed"` on exception | unit | `pytest tests/agent/test_omo.py::test_phase_status_set_to_failed_on_exception -x` | ❌ Wave 0 |
| ORCH-02 | `LLMRouter.complete(mode="compaction")` resolves to Ollama/Qwen, never Claude | unit | `pytest tests/agent/test_llm_router.py::test_compaction_mode_routes_to_ollama -x` | ❌ Wave 0 — extends existing `tests/agent/test_llm_router.py` (file exists, new test needed) |
| ORCH-02 | `LLMRouter.complete(mode="orchestration")` still resolves to Claude (regression guard) | unit | `pytest tests/agent/test_llm_router.py -x` | ✅ existing tests cover this today |
| ORCH-03 | `OmX.plan()` returns a valid `EngagementPlan` for a canonical `$pentest`-style directive | unit | `pytest tests/agent/test_omx.py::test_plan_generates_valid_dag -x` | ❌ Wave 0 — `tests/agent/test_omx.py` does not exist |
| ORCH-03 | A hallucinated agent name in a `Directive` fails `validate_plan_against_registry()` before any `agent.execute()` call | unit | `pytest tests/agent/test_omo.py::test_unregistered_agent_blocks_dispatch -x` | ❌ Wave 0 |
| PERSIST-01 | `SessionStore` reload after a simulated restart reconstructs `phase_status`/findings matching last commit | integration | `pytest tests/session/test_session_store.py::test_resolve_after_restart_reconstructs_state -x` | ❌ Wave 0 — extends existing file |
| PERSIST-01 | `TaskRegistry` rows with `status='running'` after restart are detected and surfaced (Pattern 2's crash-detection query) | integration | `pytest tests/agent/test_task_registry.py::test_running_row_detected_after_restart -x` | ❌ Wave 0 — `tests/agent/test_task_registry.py` does not exist |

### Sampling Rate
- **Per task commit:** `pytest tests/agent/ tests/session/ -x --tb=short`
- **Per wave merge:** `pytest tests/ --tb=short`
- **Phase gate:** Full suite green before `/gsd:verify-work`

### Wave 0 Gaps
- [ ] `tests/agent/test_omx.py` — covers ORCH-03 (plan generation, validation-retry, `OmXPlanValidationError` after 3 attempts)
- [ ] `tests/agent/test_omo.py` — covers ORCH-01, ORCH-03 (sequential dispatch, PHASE_FAILED emission, pre-dispatch registry/cycle validation)
- [ ] `tests/agent/test_task_registry.py` — covers PERSIST-01's crash-detection query (Pattern 2)
- [ ] `tests/agent/test_clawhip.py` — covers `Clawhip.emit()` → `ConnectionManager.send()` + conditional `ExplainableAI.log_decision()` calls
- [ ] `tests/agent/test_instruction_parser.py` — does not exist today (zero test coverage for `InstructionParser`/duplicate `EngineRouter` currently) — needed to cover Pattern 3's reconciliation (signature change to `EngagementSession`, `EngineRouter.dispatch()` merge)
- [ ] Extend `tests/session/test_session_store.py` — SQLite persistence + the cache-plus-persistence `resolve()` behavior (Pitfall 3); update `test_resolve_returns_same_object` per that pitfall's guidance
- [ ] Extend `tests/agent/test_llm_router.py` — `mode="compaction"` and optional DeepSeek routing (ORCH-02)
- [ ] Add `summariser_threshold` field + a minimal `tests/agent/test_conversation_summariser.py` smoke test (Pitfall 1) — currently zero coverage, currently broken
- [ ] Add `SmartMemory.get_best_tools()` stub + a `tests/memory/test_smart_memory.py` addition asserting it returns `[]` without raising (Pitfall 2)
- [ ] Framework install: none — pytest/pytest-asyncio already configured and passing (144 tests green per STATE.md's Phase 1 baseline)

## Security Domain

### Applicable ASVS Categories

| ASVS Category | Applies | Standard Control |
|---|---|---|
| V1 Architecture, Design and Threat Modeling | yes | The pre-dispatch validation gate (scope-membership + registry + cycle check, AI-SPEC.md Section 6) is itself the ASVS V1 control — "validate before execute" as an architectural invariant, not a per-endpoint check |
| V4 Access Control | partial | Single static bearer token (existing `backend/auth.py`, unchanged by this phase per `CLAUDE.md`'s "no auth hardening beyond static bearer token required for now") — this phase does not add or need finer-grained access control; the *scope* enforcement (which targets a directive may touch) is a business-logic control, not an ASVS V4 authentication/authorization control, and is already covered under V1 above |
| V5 Input Validation | yes | `Directive`/`EngagementPlan` Pydantic validation (already locked in AI-SPEC.md) is the input-validation boundary for OmX's own output; separately, Pitfall 7 documents that this validation does **not** extend to shell-metacharacter safety in `target` strings reaching sub-agent f-string-interpolated commands — that gap is pre-existing and explicitly out of this phase's scope (matches the SEC-02 carve-out), not a new regression this phase introduces |
| V9 Self-Protection / Logging | yes | `ExplainableAI.log_decision()` (Pitfall 5) becomes this phase's audit-logging control for `PHASE_FAILED`/`PLAN_REJECTED` events — currently a no-op (zero callers); wiring it is the concrete ASVS V9 logging deliverable for this phase, matching AI-SPEC.md Section 6's guardrail table ("Any scope-membership gate rejection → WARNING logged with full directive detail — never silently dropped") |
| V6 Cryptography | no | No new cryptographic material this phase — `CredentialVault` injection pattern (existing, unchanged) already handles credential secrecy; SQLite files are not encrypted at rest, consistent with the existing `ClientProfileDB`/`ResearchKB` precedent (no new regression) |

### Known Threat Patterns for this stack

| Pattern | STRIDE | Standard Mitigation |
|---|---|---|
| Scope creep via LLM-generated directive targets (Critical Failure Mode #1, AI-SPEC.md Section 1) | Elevation of Privilege / Tampering | Deterministic set-membership pre-dispatch gate (already locked, AI-SPEC.md Section 6) — code-based, not LLM-judged |
| Hallucinated agent name reaching `agents[directive.agent]` (`KeyError` treated as a crash instead of caught validation failure) | Tampering / Denial of Service | `validate_plan_against_registry()` (Code Examples above) run before directive 1 dispatches |
| Session-resume state mismatch after a crash (Critical Failure Mode #5) masking what actually executed against a live target | Repudiation | `TaskRegistry`'s `status='running'`-after-restart detection query (Pattern 2) — treated as P1/halt-dispatch per AI-SPEC.md Section 6's Guardrails table |
| Pre-existing shell command injection via `target` string in sub-agent f-strings (Pitfall 7) | Tampering | Out of scope for this phase (same carve-out as SEC-02) — noted for awareness, not remediated here |
| Silent failure swallowing the exact defect this phase exists to fix (ORCH-01) | Repudiation / Denial of Service | `Clawhip.emit(PHASE_FAILED, ...)` on every caught exception/timeout in `OmO.dispatch()`'s loop — no bare `except: pass` permitted in the dispatch loop |

## Sources

### Primary (HIGH confidence — direct file reads/greps in this repo)
- `backend/api/ws_handler.py` — `ConnectionManager`, `websocket_chat()` calling convention
- `backend/reporting/explainable_ai.py` — `ExplainableAI`/`ExploitChainer` (confirms "XAILogger" naming mismatch, zero callers)
- `backend/agent/instruction_parser.py`, `backend/agent/engine_router.py` — confirmed byte-identical duplicate `EngineRouter`, confirmed zero live callers of `InstructionParser.parse()`
- `backend/agent/conversation.py` — `SessionState` (old type `InstructionParser.parse()` currently expects)
- `backend/session/engagement_session.py` — `EngagementSession`/`ScopeConfig`/`EngagementState`/`ConversationHistory` (no serialization helpers, confirmed)
- `backend/agent/orchestrator.py` — confirmed `process()`/`process_stream()` never call `parser`, `engine_router`, `tool_selector`, or `composer`
- `backend/agent/llm_router.py`, `backend/inference/ollama_client.py` — current 2-provider dispatch, `_ollama_complete`'s existing graceful-degrade pattern
- `backend/agent/tool_selector.py`, `backend/agent/response_composer.py`, `backend/agent/sub_agents/base.py` — confirmed unused-but-constructed status, `ResponseComposer.compose()`'s existing single-decision signature
- `backend/agent/sub_agents/recon_agent.py` — confirmed zero-arg constructor pattern, confirmed pre-existing f-string shell injection surface (source comment)
- `backend/session/session_store.py` + `tests/session/test_session_store.py` — confirmed in-memory dict, confirmed `is`-identity test assertion
- `backend/memory/client_profile.py`, `backend/intelligence/research_kb.py` — the established SQLite WAL connect/pragma/row_factory pattern
- `backend/intelligence/strategy_evolution.py`, `backend/memory/smart_memory.py` — confirmed `get_best_tools()` missing from `SmartMemory`
- `backend/intelligence/research_daemon.py` — confirmed no live `EventBus`, `event_bus` param is optional/inert
- `backend/agent/conversation_summariser.py`, `backend/config.py` — confirmed `summariser_threshold` field missing
- `.env.example` — confirmed `SUMMARISER_THRESHOLD`, `MISTRAL_MODEL` documented but not all mirrored into `Settings`
- `pyproject.toml`, `tests/` directory listing, `tests/agent/test_orchestrator.py` — test framework/config, existing coverage baseline
- `.planning/config.json` — `nyquist_validation: true`, `commit_docs: true`, no `security_enforcement` key (treated as enabled per default)

### Secondary (MEDIUM confidence)
- None — this research required no external web lookups; the entire gap this document fills is internal-codebase archaeology, not framework/library research (already covered by 03-AI-SPEC.md)

### Tertiary (LOW confidence)
- A1/A2 in Assumptions Log — Qwen model tag naming convention and DeepSeek API shape are based on general training knowledge of these ecosystems, not verified against this operator's actual Ollama instance or DeepSeek's live API docs in this research session

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH — no new packages, all verified against `backend/requirements.txt`
- Architecture (clawhip/TaskRegistry/wiring patterns): HIGH — every design recommendation is grounded in a directly-read, directly-grepped source file, not inferred
- Pitfalls: HIGH — all 7 pitfalls are confirmed defects/gaps found via direct code inspection (grep + read), not speculative
- Assumptions (Qwen tag, DeepSeek API shape): LOW — flagged explicitly in Assumptions Log, needs operator confirmation before those specific config defaults are trusted

**Research date:** 2026-09-01
**Valid until:** 2026-09-15 (14 days — this research is tied to a specific, currently-uncommitted codebase state; any commit touching `backend/agent/`, `backend/session/`, `backend/config.py`, or `backend/intelligence/strategy_evolution.py`/`backend/memory/smart_memory.py` before planning begins should trigger a re-check of the pitfalls above)
