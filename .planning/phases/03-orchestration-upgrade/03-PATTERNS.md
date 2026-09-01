# Phase 3: Orchestration Upgrade - Pattern Map

**Mapped:** 2026-09-01
**Files analyzed:** 22 (9 new, 13 modified)
**Analogs found:** 20 / 22

## File Classification

| New/Modified File | Role | Data Flow | Closest Analog | Match Quality |
|---|---|---|---|---|
| `backend/agent/omx.py` (NEW) | service (planner) | request-response (forced tool-use LLM call) | `backend/agent/llm_router.py` (Claude call shape) + `backend/intelligence/custom_tool_generator.py` (retry-loop shape) | role-match (composite) |
| `backend/agent/omo.py` (NEW) | service (coordinator) | event-driven / batch (sequential dispatch loop) | `backend/intelligence/custom_tool_generator.py` (`promote()` gate pipeline with `asyncio.wait_for` + try/except per stage) | role-match |
| `backend/agent/task_registry.py` (NEW) | model/store | CRUD (SQLite) | `backend/memory/client_profile.py` (`ClientProfileDB`) | exact (SQLite+WAL CRUD store) |
| `backend/agent/clawhip.py` (NEW) | service (event router) | event-driven (fan-out to WS + audit log) | `backend/api/ws_handler.py`'s `ConnectionManager` (transport) + `backend/reporting/explainable_ai.py`'s `ExplainableAI.log_decision` (audit sink) | role-match (composite) |
| `tests/agent/test_omx.py` (NEW) | test | request-response | `tests/agent/test_llm_router.py` | exact (Claude mock pattern) |
| `tests/agent/test_omo.py` (NEW) | test | event-driven | `tests/agent/test_orchestrator.py` | role-match |
| `tests/agent/test_task_registry.py` (NEW) | test | CRUD | `tests/intelligence/test_research_kb_wal.py` | exact (SQLite WAL test pattern) |
| `tests/agent/test_clawhip.py` (NEW) | test | event-driven | `tests/agent/test_orchestrator.py` (mock-and-assert-call shape) | role-match |
| `tests/agent/test_instruction_parser.py` (NEW) | test | request-response | `tests/agent/test_llm_router.py` (plain pytest, no fixture) | role-match |
| `backend/agent/orchestrator.py` (MODIFIED) | service (facade/controller) | request-response + streaming | itself (existing `process`/`process_stream`) | exact — minimal-diff restructuring, not a rewrite |
| `backend/agent/instruction_parser.py` (MODIFIED) | service/utility | request-response | itself + `backend/agent/engine_router.py` (canonical dedupe target) | exact |
| `backend/agent/llm_router.py` (MODIFIED) | service | request-response | itself (existing `complete()`/`_claude_complete()`/`_ollama_complete()`) | exact |
| `backend/session/engagement_session.py` (MODIFIED) | model | CRUD (add serialization) | `backend/memory/client_profile.py`'s `ClientProfile`/`_row_to_profile()` (dataclass ↔ SQLite row round-trip) | role-match |
| `backend/session/session_store.py` (MODIFIED) | store/service | CRUD (SQLite, cache-plus-persistence) | `backend/memory/client_profile.py` (`ClientProfileDB`) | exact |
| `backend/config.py` (MODIFIED) | config | — | itself (existing `Settings` fields) | exact |
| `backend/reporting/explainable_ai.py` (MODIFIED — new caller only, likely no internal edit) | service (logger) | event-driven | itself (`log_decision` signature already fixed) | exact (no analog needed — first real caller is `clawhip.py`) |
| `backend/memory/smart_memory.py` (MODIFIED — add stub method) | store | CRUD | itself (existing `search()`'s "return what little I have" degrade pattern) | exact |
| `tests/session/test_session_store.py` (MODIFIED — extend) | test | CRUD | `tests/intelligence/test_research_kb_wal.py` (WAL assertion pattern) + itself (existing sync tests) | exact (composite) |
| `tests/agent/test_llm_router.py` (MODIFIED — extend) | test | request-response | itself | exact |
| `tests/memory/test_smart_memory.py` (MODIFIED — extend) | test | CRUD | itself (existing `TestSmartMemoryAdaptiveLearning` class, currently `xfail`ed) | exact |
| `tests/agent/test_conversation_summariser.py` (NEW) | test | request-response | `tests/agent/test_llm_router.py` (plain smoke-test shape) | role-match |
| `backend/intelligence/strategy_evolution.py` (touched only if D-10 Architect-role wiring needs it) | service | event-driven | no code change expected — `SmartMemory.get_best_tools()` stub (above) makes existing `_enrich_node()` call-safe without touching this file | n/a — see No Analog Found |

## Pattern Assignments

### `backend/agent/omx.py` (NEW — service, request-response)

**Analog 1 (Claude SDK call shape):** `backend/agent/llm_router.py`

**Imports pattern** (lines 1-8):
```python
import logging
from dataclasses import dataclass
from typing import Dict, List

from backend import config
from backend.inference.ollama_client import OllamaClient

logger = logging.getLogger(__name__)
```
Follow this: `from backend import config` (not `from backend.config import settings`), module-level `logger = logging.getLogger(__name__)`.

**Claude call shape** (lines 19-22, 35-52 — `LLMRouter.__init__`/`_claude_complete`):
```python
class LLMRouter:
    def __init__(self):
        import anthropic
        self.claude = anthropic.AsyncAnthropic(api_key=config.settings.anthropic_api_key)
        ...
    async def _claude_complete(self, messages, system):
        try:
            kwargs = dict(model=config.settings.claude_model, max_tokens=4096, messages=messages)
            if system:
                kwargs["system"] = system
            response = await self.claude.messages.create(**kwargs)
            return LLMResponse(content=response.content[0].text, ...)
        except Exception as e:
            logger.error(f"Claude error: {e}, falling back to Ollama")
            return await self._ollama_complete(messages)
```
`OmX.plan()` reuses `llm_router.claude` (the already-constructed `AsyncAnthropic` client) directly — do not re-instantiate a second Anthropic client. Do NOT copy the `except Exception: fall back to Ollama` behavior for the forced-tool-use call — per RESEARCH.md's Open Question/Environment Availability finding, Ollama cannot produce a `tool_use` block, so OmX's failure path must be its own retry-then-`OmXPlanValidationError` loop (AI-SPEC.md Section 3), not `LLMRouter`'s existing Claude→Ollama fallback.

**Analog 2 (retry-loop / gate shape):** `backend/intelligence/custom_tool_generator.py` lines 365-399 (`promote()`'s G2 sandbox gate)
```python
if executor:
    try:
        result = await asyncio.wait_for(executor(tool.code, tool.name), timeout=120)
        ...
    except asyncio.TimeoutError:
        sandbox_result = SandboxResult(passed=False, error="Sandbox execution timed out (120s)")
    except Exception as exc:
        sandbox_result = SandboxResult(passed=False, error=str(exc))
```
Mirror this try/except-per-attempt shape for `OmX.plan()`'s 3-attempt validation retry loop (already fully specified in AI-SPEC.md Section 3 — use that code verbatim as the primary source, this analog only confirms the codebase's established try/except-with-typed-error-result idiom).

**Error type pattern:** Follow `backend/agent/sub_agents/base.py`'s `ToolPermissionError(Exception): pass` — define `class OmXPlanValidationError(Exception): pass` the same minimal way (no custom `__init__`, no message-formatting override).

---

### `backend/agent/omo.py` (NEW — service, event-driven/batch dispatch)

**Analog:** `backend/intelligence/custom_tool_generator.py`'s gated pipeline (`promote()`) — sequential stage-by-stage execution where each stage transitions state and catches its own exception without aborting the outer object.

**Core dispatch loop pattern** (adapt from AI-SPEC.md Section 3's `OmO.dispatch()`, cross-checked against this codebase's existing timeout idiom):
```python
# backend/tools/backends/kali_ssh.py:190-194 — the project's asyncio.wait_for + asyncio.TimeoutError idiom
try:
    healthy = await asyncio.wait_for(<call>, timeout=<n>)
except asyncio.TimeoutError:
    <handle>
```
Apply this exact `asyncio.wait_for(agent.execute(...), timeout=...)` / `except asyncio.TimeoutError` shape per directive (AI-SPEC.md Section 3 pitfall #5) — the codebase already uses this idiom in `kali_ssh.py` and `custom_tool_generator.py`, so OmO's per-directive timeout is not introducing a new pattern.

**State transition pattern:** `backend/session/engagement_session.py` lines 30-40 (`EngagementState.set_phase_status`, `add_finding`) — call these exactly as declared, no wrapper:
```python
def add_finding(self, finding: Dict) -> None:
    self.findings.append(finding)

def set_phase_status(self, phase_id: str, status: str) -> None:
    self.phase_status[phase_id] = status
```

**Agent registry construction pattern (for `Orchestrator.__init__`, consumed by `omo.dispatch`)** — already fully specified in RESEARCH.md's "Code Examples" section; copy verbatim:
```python
def _build_agent_registry() -> dict:
    return {
        cls.__name__: cls()
        for cls in (CloudAgent, DataSecAgent, EndpointAgent, ExploitAgent, GenAIAgent,
                    IAMAgent, ICSAgent, IntelAgent, ModelSecAgent, ReconAgent, ScanAgent)
    }
```
Verified: every `BaseAgent` subclass constructor is zero-arg (`backend/agent/sub_agents/recon_agent.py` lines 4-11 — `super().__init__(name=..., engine=..., allowed_tools=[...], priority=1)` hardcoded, no params).

**No bare except/pass rule:** `backend/api/ws_handler.py` lines 85-90 shows the project's existing pattern for catching-and-reporting rather than swallowing:
```python
except WebSocketDisconnect:
    pass
except Exception as e:
    logger.error(f"WebSocket error: {e}")
    if session_id:
        await manager.send(session_id, {"type": "error", "message": str(e)})
```
`OmO.dispatch()`'s per-directive `except Exception as e:` must follow this shape — log + emit (`clawhip.emit(PHASE_FAILED, ...)`), never a bare `except: pass` (RESEARCH.md's Known Threat Patterns table explicitly forbids this for the dispatch loop).

---

### `backend/agent/task_registry.py` (NEW — model/store, CRUD)

**Analog:** `backend/memory/client_profile.py` (`ClientProfileDB`) — closest exact match: dataclass model + SQLite-WAL-backed store class with `initialize()`/`close()`/CRUD methods.

**Imports pattern** (lines 1-19):
```python
from __future__ import annotations

import asyncio
import json
import logging
import sqlite3
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)
```

**Connect → WAL pragma → row_factory pattern** (lines 45-61, identical in `backend/intelligence/research_kb.py` lines 47-62 — this is the established, verbatim-reused pattern across the codebase):
```python
def __init__(self, db_path: Path | None = None) -> None:
    self._db_path = db_path or Path("data/<store-name>/<store-name>.db")
    self._db_path.parent.mkdir(parents=True, exist_ok=True)
    self._conn: sqlite3.Connection | None = None
    self._lock = asyncio.Lock()

async def initialize(self) -> None:
    async with self._lock:
        self._conn = await asyncio.to_thread(
            sqlite3.connect, str(self._db_path), check_same_thread=False,
        )
        self._conn.row_factory = sqlite3.Row
        await asyncio.to_thread(self._conn.execute, "PRAGMA journal_mode=WAL")
        # NOTE: journal_mode persists in the DB file; synchronous does NOT —
        # must be reissued on every new connection.
        await asyncio.to_thread(self._conn.execute, "PRAGMA synchronous=NORMAL")
        await asyncio.to_thread(self._conn.executescript, """
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
        """)
        await asyncio.to_thread(self._conn.commit)
```
(Exact schema per RESEARCH.md Pattern 2 — same connection/db file as `SessionStore`, per RESEARCH.md's consistency argument; do not open a second `sqlite3.connect()`.)

**Blocking-call wrapper pattern** (lines 141-147, `get_profile`):
```python
row = await asyncio.to_thread(
    lambda: self._conn.execute(
        "SELECT * FROM client_profiles WHERE client_id = ?",
        (client_id,),
    ).fetchone()
)
```
Every `TaskRegistry` read/write must go through `asyncio.to_thread`, never call `self._conn.execute(...)` directly from `async def` (RESEARCH.md AI-SPEC pitfall #4).

**Crash-detection query** (RESEARCH.md Pattern 2, use verbatim):
```python
stale = conn.execute(
    "SELECT directive_id, agent_name FROM task_registry "
    "WHERE session_id = ? AND status = 'running'",
    (session_id,),
).fetchall()
```

**close() pattern** (lines 83-86):
```python
async def close(self) -> None:
    if self._conn:
        await asyncio.to_thread(self._conn.close)
        self._conn = None
```

---

### `backend/agent/clawhip.py` (NEW — service, event-driven)

**Analog 1 (transport):** `backend/api/ws_handler.py`'s `ConnectionManager` (lines 13-27):
```python
class ConnectionManager:
    def __init__(self) -> None:
        self.active: Dict[str, WebSocket] = {}
    async def send(self, session_id: str, payload: dict) -> None:
        ws = self.active.get(session_id)
        if ws:
            await ws.send_json(payload)
```
`Clawhip` holds a reference to this existing `manager` singleton (imported from `backend.api.ws_handler`) — do not build a new transport, call `manager.send(session_id, event.model_dump(mode="json"))`.

**Analog 2 (audit sink):** `backend/reporting/explainable_ai.py` lines 13-28 (`ExplainableAI.log_decision`):
```python
def log_decision(self, decision_type: str, reasoning: str, confidence: float, factors: List[str]):
    entry = {"timestamp": datetime.now().isoformat(), "decision_type": decision_type, ...}
    self.audit_log.append(entry)
    logger.info(f"XAI: {decision_type} - {reasoning}")
```
Call this exact signature — do NOT search for a class named `XAILogger` (it does not exist; RESEARCH.md Pitfall 5).

**Full recommended shape:** already fully specified in RESEARCH.md's Pattern 1 (Section "Architecture Patterns") — copy verbatim, including the `ClawhipEventType`/`ClawhipEvent` Pydantic models and the `emit()` method that only calls `xai.log_decision()` for `PHASE_FAILED`/`PLAN_REJECTED` events (not every lifecycle tick).

---

### `backend/session/task/session_store.py` reconciliation — `backend/session/session_store.py` (MODIFIED)

**Analog:** `backend/memory/client_profile.py` (`ClientProfileDB`) for the SQLite half; itself (existing dict-based methods) for the cache half.

**Cache-plus-persistence `resolve()` pattern** (RESEARCH.md "Code Examples" — Pitfall 3 fix, copy verbatim):
```python
async def resolve(self, session_id: str) -> Optional[EngagementSession]:
    if session_id in self._sessions:          # hot path — same object identity preserved
        return self._sessions[session_id]
    row = await asyncio.to_thread(
        lambda: self._conn.execute(
            "SELECT payload FROM sessions WHERE session_id = ?", (session_id,)
        ).fetchone()
    )
    if row is None:
        return None
    session = self._deserialize(row["payload"])  # from_row(), Pitfall 4
    self._sessions[session_id] = session
    return session
```

**Existing methods to preserve exactly** (`backend/session/session_store.py` lines 7-25) — `create()`, `touch()`, and the module-level singleton `session_store = SessionStore()` (line 25) must keep their current synchronous-friendly call signatures used by `backend/api/ws_handler.py` lines 50-66 (`session_store.resolve(raw_id)`, `session_store.create()`, `session_store.touch(session_id)` — all called without `await` today). **Flag for planner:** `ws_handler.py` calls these synchronously; if `resolve()`/`create()`/`touch()` become `async def` for SQLite I/O, every call site in `ws_handler.py` needs `await` added — `ws_handler.py` is on the "existing delivery primitive" touch list per CONTEXT.md, so this is an in-scope one-line-per-callsite change, not a new file.

**Test regression to update:** `tests/session/test_session_store.py` line 19-23 (`test_resolve_returns_same_object` — asserts `resolved is created`) — per RESEARCH.md Pitfall 3, keep this test passing (cache-plus-persistence preserves identity on the hot path); do not rewrite it to equality unless the pure-SQLite alternative is chosen instead.

---

### `backend/session/engagement_session.py` (MODIFIED — add serialization)

**Analog:** `backend/memory/client_profile.py`'s `ClientProfile` (dataclass) ↔ `_row_to_profile()` (lines 22-36, 88-100) round-trip pattern:
```python
@dataclass
class ClientProfile:
    client_id: str
    ...
    engagement_count: int = 0
    last_seen: str = ""

def _row_to_profile(self, row: sqlite3.Row) -> ClientProfile:
    return ClientProfile(
        client_id=row["client_id"],
        ...
        engagement_count=row["engagement_count"],
        last_seen=row["last_seen"],
    )
```
Add an equivalent `EngagementSession.to_row()`/`from_row()` pair (or `json.dumps(asdict(session), default=str)` for the `datetime` fields specifically per RESEARCH.md Pitfall 4 — `dataclasses.asdict()` recurses correctly into nested dataclasses `ScopeConfig`/`ConversationHistory`/`EngagementState` but leaves `datetime` un-serializable). This is new code with no exact prior analog in this file — `ClientProfile` is the best structural precedent (dataclass + explicit row-mapping method) even though it doesn't have nested dataclasses or datetime fields itself.

**Existing methods to preserve exactly** (lines 30-40):
```python
def add_finding(self, finding: Dict) -> None:
    self.findings.append(finding)
def set_phase_status(self, phase_id: str, status: str) -> None:
    self.phase_status[phase_id] = status
```

---

### `backend/agent/instruction_parser.py` (MODIFIED — dedupe + signature fix)

**Analog:** itself + `backend/agent/engine_router.py` (the canonical, byte-identical duplicate target).

**Exact diff** (RESEARCH.md Pattern 3, verified byte-identical duplicate — copy the before/after diff verbatim):
```python
# BEFORE (backend/agent/instruction_parser.py lines 1-6, 11-36)
from backend.agent.conversation import SessionState
class EngineRouter:              # DELETE — duplicate of engine_router.py
    def dispatch(self, intent, target=None): ...
    def _is_ml_target(self, target): ...
class InstructionParser:
    def parse(self, message: str, session: SessionState, mode=None) -> Dict[str, Any]:
        ...
        return {..., "mode": mode or session.mode}

# AFTER
from backend.session.engagement_session import EngagementSession
from backend.agent.engine_router import EngineRouter  # import canonical, don't redefine
class InstructionParser:
    def parse(self, message: str, session: EngagementSession, mode: Optional[str] = None) -> Dict[str, Any]:
        intent = self._detect_intent(message)
        target = self._extract_target(message)
        ...
        resolved_mode = mode or EngineRouter().dispatch(intent, target)  # merge point, see RESEARCH.md note
        return {..., "mode": resolved_mode}
```
`EngagementSession` has no `.mode` field — the `mode` key must be re-derived via `EngineRouter().dispatch(intent, target)` inline, not read from a session attribute (RESEARCH.md's flagged "genuine design decision" point). All other methods (`_detect_intent`, `_extract_target`, `_extract_constraints`, `_detect_phase`, `_calculate_confidence` — lines 61-146) are unchanged, keep byte-identical.

---

### `backend/agent/llm_router.py` (MODIFIED — extend for ORCH-02/D-04)

**Analog:** itself — extend the existing `complete()` dispatcher (lines 25-33) and `_ollama_complete()` (lines 57-68) shape:
```python
async def complete(self, messages, mode="orchestration", system="") -> LLMResponse:
    if mode == "orchestration":
        return await self._claude_complete(messages, system)
    return await self._ollama_complete(messages)   # extend: elif mode == "compaction": route to Qwen tag
                                                     #         elif mode == "deepseek": route to DeepSeek, gated on api key
```
Add `mode == "compaction"` branch calling `self.ollama.generate(model=config.settings.qwen_model, prompt=...)` (same call shape as `_ollama_complete` lines 57-68, just a different `model=` value) — do not add a new Ollama client, reuse `self.ollama` (already `OllamaClient(config.settings.ollama_host)`, line 23). Add a `deepseek_api_key` presence-gated branch per D-04, following the try/except-and-fallback shape at lines 53-55 for graceful degradation:
```python
except Exception as e:
    logger.error(f"Claude error: {e}, falling back to Ollama")
    return await self._ollama_complete(messages)
```

**Config fields needed first** (RESEARCH.md Pitfall 6) — see `backend/config.py` pattern assignment below; this file's new `mode` branches will `AttributeError` without those fields added first.

---

### `backend/config.py` (MODIFIED — add fields)

**Analog:** itself (existing `Settings` field list, lines 4-16):
```python
class Settings(BaseSettings):
    bearer_token: str = "dev-token"
    anthropic_api_key: str = ""
    ollama_host: str = "http://localhost:11434"
    claude_model: str = "claude-sonnet-4-6"
    mistral_model: str = "mistral:7b"
    embed_model: str = "nomic-embed-text"
    kali_host: str = "localhost"
    ...
    model_config = {"env_file": ".env", "env_file_encoding": "utf-8"}
```
Add, following the exact same `field_name: type = default` style (no `Field(...)` wrapper used anywhere in this class today — keep consistent):
```python
    summariser_threshold: int = 60000   # RESEARCH.md Pitfall 1 — currently missing, breaks ConversationSummariser
    qwen_model: str = "qwen2.5:7b"      # [ASSUMED — RESEARCH.md A1] confirm against operator's actual Ollama tag
    deepseek_api_key: str = ""
    deepseek_model: str = "deepseek-chat"
    deepseek_base_url: str = "https://api.deepseek.com"
```
Regression test precedent to mirror: `tests/agent/test_llm_router.py` lines 44-46 (`test_claude_model_is_sonnet_4_6`) — write an equivalent `assert config.settings.summariser_threshold == 60000`-style regression test for the new fields.

---

### `backend/memory/smart_memory.py` (MODIFIED — add minimal stub)

**Analog:** itself, existing `search()` method (lines 37-38) — the "return what little I have, never raise" idiom:
```python
async def search(self, query: str, top_k: int = 5) -> List[MemoryEntry]:
    return self.entries[-top_k:]
```
Add (RESEARCH.md Pitfall 2 / D-10, Assumption A3 — stub returns `[]`, not `NotImplementedError`, per the recommended lower-risk option):
```python
async def get_best_tools(self, target_type: str, top_k: int = 10) -> List[Dict[str, Any]]:
    return []
```
This makes `backend/intelligence/strategy_evolution.py`'s existing `_enrich_node()` call (line 118: `await self._memory.get_best_tools(target_type=..., top_k=10)`) safe to call without editing `strategy_evolution.py` itself.

---

## Shared Patterns

### SQLite WAL connect/pragma/row_factory
**Source:** `backend/memory/client_profile.py` lines 45-61 (also `backend/intelligence/research_kb.py` lines 47-62, byte-for-byte identical pattern)
**Apply to:** `task_registry.py`, `session_store.py`
```python
self._conn = await asyncio.to_thread(sqlite3.connect, str(self._db_path), check_same_thread=False)
self._conn.row_factory = sqlite3.Row
await asyncio.to_thread(self._conn.execute, "PRAGMA journal_mode=WAL")
await asyncio.to_thread(self._conn.execute, "PRAGMA synchronous=NORMAL")  # must reissue every connect
```

### asyncio.to_thread wrapper for every blocking sqlite3 call
**Source:** `backend/memory/client_profile.py` lines 141-147
**Apply to:** `task_registry.py`, `session_store.py` — never call `self._conn.execute(...)` directly from an `async def`.

### asyncio.wait_for + asyncio.TimeoutError per-call timeout
**Source:** `backend/tools/backends/kali_ssh.py` lines 190-194; `backend/intelligence/custom_tool_generator.py` lines 377-395
**Apply to:** `omo.py`'s per-directive `agent.execute()` dispatch call (AI-SPEC.md Section 3 pitfall #5).

### Logging: module-level logger, error-then-fallback on external-call failure
**Source:** `backend/agent/llm_router.py` line 8 (`logger = logging.getLogger(__name__)`), lines 53-55 (`logger.error(f"Claude error: {e}, falling back to Ollama")`)
**Apply to:** `omx.py`, `omo.py`, `clawhip.py`, `task_registry.py` — every new module.

### No bare except/pass in a dispatch/error-reporting path
**Source:** `backend/api/ws_handler.py` lines 85-90
**Apply to:** `omo.py`'s dispatch loop exception handling (RESEARCH.md's Known Threat Patterns table — "no bare `except: pass` permitted in the dispatch loop").

### Minimal-exception-class idiom
**Source:** `backend/agent/sub_agents/base.py` line 24-25 (`class ToolPermissionError(Exception): pass`); `backend/agent/response_composer.py` line 61-62 (same idiom, `ToolPermissionError` duplicated there too — pre-existing, not this phase's concern)
**Apply to:** `OmXPlanValidationError` in `omx.py`.

### Dataclass + zero-arg BaseAgent subclass constructor
**Source:** `backend/agent/sub_agents/recon_agent.py` lines 4-11
**Apply to:** `omo.py`'s / `orchestrator.py`'s agent-registry construction — confirms no factory/DI wiring is needed.

---

## No Analog Found

| File | Role | Data Flow | Reason |
|---|---|---|---|
| `backend/agent/omx.py`'s Pydantic `Directive`/`EngagementPlan` models | model (schema) | request-response | This codebase uses `@dataclass` everywhere for domain models (`EngagementSession`, `ClientProfile`, `ChainNode`) — `pydantic.BaseModel` is currently used only for `Settings` (`pydantic-settings`), not for a hand-defined domain schema. No existing analog for a hand-rolled Pydantic `BaseModel` DAG schema in this repo; AI-SPEC.md Section 3/4b is the sole source of truth here — use it verbatim rather than searching further. |
| `backend/agent/clawhip.py`'s `ClawhipEvent` typed model | model (schema) | event-driven | Same reason — no existing typed WS-event schema in this codebase (`ws_handler.py` sends ad-hoc `dict` payloads throughout, e.g. `{"chunk": chunk, "done": False}`). RESEARCH.md Pattern 1 is the sole source; explicitly note in the plan that this is the *first* typed WS payload in the codebase, an intentional new-but-narrow pattern (not a retrofit of the old ad-hoc dicts). |

## Metadata

**Analog search scope:** `backend/agent/`, `backend/session/`, `backend/memory/`, `backend/intelligence/`, `backend/reporting/`, `backend/api/`, `backend/tools/backends/`, `backend/config.py`, `tests/agent/`, `tests/session/`, `tests/memory/`, `tests/intelligence/`
**Files scanned:** 24 (read in full) — `client_profile.py`, `research_kb.py`, `llm_router.py`, `orchestrator.py`, `instruction_parser.py`, `engine_router.py`, `session_store.py`, `engagement_session.py`, `ws_handler.py`, `explainable_ai.py`, `sub_agents/base.py`, `sub_agents/recon_agent.py`, `config.py`, `tool_selector.py`, `response_composer.py`, `conversation_summariser.py`, `smart_memory.py`, `strategy_evolution.py`, `custom_tool_generator.py` (targeted), `kali_ssh.py` (targeted grep), `test_llm_router.py`, `test_session_store.py`, `test_research_kb_wal.py`, `test_orchestrator.py`, `test_smart_memory.py`
**Pattern extraction date:** 2026-09-01
