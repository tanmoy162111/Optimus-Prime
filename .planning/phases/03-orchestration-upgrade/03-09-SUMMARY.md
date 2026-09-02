---
phase: 03-orchestration-upgrade
plan: 09
subsystem: orchestrator-pipeline-wiring
tags: [orchestrator, omx, omo, clawhip, response-composer, orch-01, orch-03, d-02, d-02a]

# Dependency graph
requires:
  - "backend/agent/omx.py: OmX.plan()/EngagementPlan/OmXPlanValidationError (Plan 06)"
  - "backend/agent/omo.py: OmO.dispatch() sequential coordinator (Plan 08)"
  - "backend/agent/clawhip.py: Clawhip/ClawhipEvent/ClawhipEventType (Plan 05)"
  - "backend/agent/task_registry.py + session_store.task_registry (Plan 04)"
  - "backend/agent/llm_router.py: LLMRouter.complete(mode='compaction') (Plan 07)"
provides:
  - "backend/agent/orchestrator.py: Orchestrator wired end-to-end — the integration seam that turns Waves 1-3 into operator-visible chat behavior"
  - "backend/agent/response_composer.py: ResponseComposer.compose_plan_summary(plan, session) — first real caller of ResponseComposer"
affects: []

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "3-stage pipeline restructuring of an existing async-generator entry point while preserving its exact external contract (word-by-word str-yielding) — minimal-diff integration, not a rewrite"
    - "Mandatory, unconditional post-dispatch LLM compaction call (never behind a feature flag) as a structural guarantee that ROADMAP criterion 2 is demonstrably satisfied on every dispatch, not just when convenient"
    - "TDD RED/GREEN sequencing for a restructuring task achieved by temporarily reverting the target methods to their pre-change form, confirming the new tests fail for the right reason, then restoring the implementation — rather than writing tests and implementation as a single non-atomic commit"

key-files:
  created: []
  modified:
    - backend/agent/orchestrator.py
    - backend/agent/response_composer.py
    - backend/config.py
    - tests/agent/test_orchestrator.py

key-decisions:
  - "Compaction call is unconditional after every successful (non-rejected) dispatch, regardless of how many directives actually completed — matches the plan's literal 'MANDATORY, not optional... asserted unconditionally' acceptance criterion rather than gating it behind a completed-directive count"
  - "Both the compacted summary text AND the composed plan-summary reply are added to conv_history as separate assistant messages (compaction first, then the composed reply) — satisfies the plan's 'alongside the composed reply' wording literally while keeping the streamed chunks limited to the composed reply only, never the compaction summary"
  - "ResponseComposer.compose_plan_summary(plan, session) added as a new method (RESEARCH.md Open Question 2, resolved) rather than forcing the existing single-decision compose(decision, findings, session_state) signature to represent a multi-directive DAG result — reuses the existing _count_by_severity() helper"
  - "Orchestrator._get_manager() is a small static-method indirection around `from backend.api.ws_handler import manager` — kept the import module-level-equivalent (executed once, at class-definition-adjacent scope during __init__) rather than truly deferred, since ws_handler.py only imports Orchestrator lazily inside its own function body, so there is no circular-import hazard to work around"
  - "[Rule 3 - Blocking] Added missing models_input_path/ml_results_path fields to backend/config.py's Settings class — MLAIEngine.__init__ (constructed eagerly by GenAIAgent and ModelSecAgent, both now built by _build_agent_registry() in Orchestrator.__init__) read settings.models_input_path/ml_results_path, which did not exist on Settings, so simply constructing Orchestrator() raised AttributeError before any pipeline code could run. This is the same class of pre-existing config gap RESEARCH.md's Pitfall 6 already documented for qwen_model/deepseek_* (fixed by Plan 07) — models_input_path/ml_results_path was the one Settings field this plan's own construction work newly exercised and found missing."

requirements-completed: [ORCH-01, ORCH-03]

# Metrics
duration: ~55min
completed: 2026-09-02
---

# Phase 3 Plan 09: Orchestrator Pipeline Wiring Summary

**The integration seam: `Orchestrator.__init__` now constructs the 11-agent registry, OmX, OmO, and Clawhip once, and both `process()`/`process_stream()` run the OmX.plan() → OmO.dispatch() → ResponseComposer 3-stage pipeline instead of the old LLM-completion-only path — while preserving the exact `ws_handler.py` async-generator streaming contract byte-for-byte.**

## Performance

- **Duration:** ~55 min
- **Completed:** 2026-09-02
- **Tasks:** 2/2 completed
- **Files modified:** 4 (2 source files beyond the plan's declared `files_modified`, 1 test file, 1 config file)

## Accomplishments

- `backend/agent/orchestrator.py`:
  - `_build_agent_registry()` (module-level helper) constructs all 11 zero-arg `BaseAgent` subclasses (CloudAgent, DataSecAgent, EndpointAgent, ExploitAgent, GenAIAgent, IAMAgent, ICSAgent, IntelAgent, ModelSecAgent, ReconAgent, ScanAgent) into `self._agents`.
  - `Orchestrator.__init__` additionally constructs `self.clawhip = Clawhip(manager, ExplainableAI())` (the real `ws_handler.manager` singleton, verified identical object via `id()`), `self.omx = OmX(self.llm_router)`, and `self.omo = OmO(self._agents, self.clawhip, session_store.task_registry)` — reads the single shared `session_store.task_registry` instance (Plan 04), never constructs its own `TaskRegistry(...)` (grep-verified and test-verified). `parser`/`engine_router`/`tool_selector` remain instantiated but are never called anywhere in the new pipeline (D-02a).
  - `process_stream()` / `process()`: both now (1) add the user message to `conv_history`, (2) call `await self.omx.plan(message, session)` inside a `try` — on `OmXPlanValidationError`, emit `PLAN_REJECTED` via `clawhip.emit()`, add + surface an operator-facing rejection message, and return/yield WITHOUT calling `omo.dispatch()`; (3) `await self.omo.dispatch(plan, session, self._agents)`; (4) an unconditional `_compact_findings()` call — `LLMRouter.complete(mode="compaction")` on `session.state.findings`, logging the resolved provider (`"LLMRouter: compaction handled by {model_used}"`) and adding the compacted text (never raw finding dicts) to `conv_history`; (5) `self.composer.compose_plan_summary(plan, session)` builds the operator-facing reply; (6) `process_stream()` preserves the exact `for word in reply.split(): yield word + " "` contract, streaming the composed reply (not the compaction summary); `process()` returns an equivalent single dict. OmX plan generation and OmO dispatch start are logged as distinct lines (`"OmX generated N-directive plan"` / `"OmO dispatch starting..."`).
- `backend/agent/response_composer.py`: new `compose_plan_summary(plan, session)` method — summarizes an `EngagementPlan`'s directives by `phase_status` (completed/failed/gate_pending/pending) plus `session.state.findings` severity counts, reusing the existing `_count_by_severity()` helper. Resolves RESEARCH.md Open Question 2 exactly as the research recommended (a new method rather than forcing `compose()`'s single-decision signature).
- `backend/config.py`: added `models_input_path`/`ml_results_path` Settings fields (Rule 3 blocking fix — see Deviations).
- `tests/agent/test_orchestrator.py`: 15 tests — 5 construction tests (Task 1: all collaborators present, 11-agent registry membership, `omo.task_registry is session_store.task_registry` identity, no `TaskRegistry(...)` construction via source scan, `clawhip._manager is` the real `ws_handler.manager` singleton + a real `ExplainableAI` instance) and 10 pipeline-behavior tests (Task 2: OmX→OmO→compose sequencing, `PLAN_REJECTED` rejection path skips dispatch, word-by-word streaming contract preserved, D-02a no-call-sites for parser/engine_router/tool_selector, distinct OmX/OmO log lines, unconditional compaction call ordering, compacted-summary-not-raw-findings in conv_history, compaction provider logging, `process()`'s dict-return equivalent for both the success and rejection paths). The original 3 pre-existing tests (which asserted the old LLM-completion-only behavior) were superseded by the new pipeline-behavior tests, since that behavior no longer exists.

## Task-by-Task

1. **Task 1 — Construct agent registry + OmX + OmO + Clawhip in `__init__`**: committed as `9c3fea9`. Discovered and fixed a Rule 3 blocking issue (missing `models_input_path`/`ml_results_path` Settings fields) during first construction attempt — see Deviations. 5 construction tests green.
2. **Task 2 — Restructure `process()`/`process_stream()` into the pipeline (TDD)**: RED committed as `47c55d0` (9 new pipeline-behavior tests confirmed failing against the still-old LLM-completion-only implementation — `process()`/`process_stream()` temporarily reverted to their pre-Task-2 form to produce a genuine failure, since `__init__`'s Task 1 changes had already landed); GREEN committed as `6a92514` (implementation restored, all 15 tests passing, plus a same-commit test fix for a log-message-formatting bug found during the GREEN run — see Deviations).

## Verification

- `pytest tests/agent/test_orchestrator.py -k "init or registry or collaborators or task_registry" -x --tb=short` (Task 1's exact verify command) → 4 passed (the 5th construction test, `test_clawhip_constructed_with_manager_and_explainable_ai`, doesn't match this `-k` filter but passes when run directly / as part of the full file)
- `pytest tests/agent/test_orchestrator.py -x --tb=short` (Task 2's exact verify command) → 15 passed
- `python -c "import backend.agent.orchestrator, backend.api.ws_handler"` → imports clean
- `python -c "import backend.app"` → full FastAPI app imports clean (both `/api/chat` and `/ws/chat` entry points reachable)
- `grep -n "self.parser.parse(\|self.engine_router.dispatch(\|self.tool_selector\." backend/agent/orchestrator.py` → no matches (D-02a verified)
- `grep -n "TaskRegistry(" backend/agent/orchestrator.py` → no matches (no self-constructed TaskRegistry)
- Identity check: `Orchestrator().clawhip._manager is backend.api.ws_handler.manager` → `True` (real singleton, not a mock/stand-in)
- Full regression suite (`pytest tests/ --ignore=tests/tools/test_sandbox_docker.py`, excluding the pre-existing unrelated `docker`-import collection error documented in Plan 05's summary): **239 passed, 2 skipped, 15 xfailed, no regressions**. The pre-existing `test_chat_without_token_returns_401` failure logged in `deferred-items.md` by earlier plans did NOT reproduce in this run — `tests/api/test_auth.py` was fully green (7/7); left as-is/unverified-fixed since chasing it is out of this plan's scope.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 3 - Blocking] `backend/config.py` missing `models_input_path`/`ml_results_path` Settings fields**
- **Found during:** Task 1, first `Orchestrator()` construction attempt (both in a scratch import check and the first test run)
- **Issue:** `_build_agent_registry()` eagerly constructs `GenAIAgent` and `ModelSecAgent`, both of which construct `MLAIEngine()` in their own `__init__`. `MLAIEngine.__init__` reads `settings.models_input_path` and `settings.ml_results_path` — neither field existed on `backend/config.py`'s `Settings` class (only documented in `.env.example` as `MODELS_INPUT_PATH`/`ML_RESULTS_PATH`, never declared on the pydantic-settings model). Constructing `Orchestrator()` raised `AttributeError: 'Settings' object has no attribute 'models_input_path'` before any pipeline code could run — this blocked Task 1 outright, matching the same defect class RESEARCH.md's Pitfall 6 already documented (and Plan 07 already fixed) for `qwen_model`/`deepseek_*`.
- **Fix:** Added `models_input_path: str = "/models"` and `ml_results_path: str = "/results"` to `Settings`, matching the `.env.example` defaults and the existing field-declaration style (`field_name: type = default`, no `Field(...)` wrapper).
- **Files modified:** `backend/config.py`
- **Commit:** `9c3fea9`

**2. [Rule 1 - Bug] Test helper used incorrect log-record formatting (`r.message % r.args`)**
- **Found during:** Task 2, GREEN test run
- **Issue:** Two new tests (`test_process_stream_logs_omx_plan_and_omo_dispatch_as_distinct_lines`, `test_compaction_resolved_provider_is_logged`) built `messages = [r.message % r.args if r.args else r.message for r in caplog.records]` to read formatted log text. `LogRecord.message` is only populated by a prior call to `record.getMessage()`/formatter — reading it directly returns the unformatted (or empty) string, and manually re-applying `%`-formatting against `r.args` raised `TypeError: not all arguments converted during string formatting` for records with plain-string messages and no args.
- **Fix:** Replaced both occurrences with `r.getMessage()`, the correct stdlib API for reading a fully-formatted log record message regardless of whether it used `%s`-style args.
- **Files modified:** `tests/agent/test_orchestrator.py`
- **Commit:** `6a92514` (folded into the GREEN commit — this was a same-session test-authoring bug caught before the RED commit landed, not a post-GREEN regression)

No other deviations — the plan's own action text already fully specified the `ResponseComposer.compose_plan_summary()` addition (not declared in the plan's `files_modified` frontmatter, which listed only `backend/agent/orchestrator.py`/`tests/agent/test_orchestrator.py`, but explicitly required by Task 2's action paragraph — treated as in-scope per the action text, not a deviation).

## Known Stubs

None — both entry points fully run the 3-stage pipeline; no stub/placeholder data paths were introduced.

## Threat Flags

None — this plan's surface (wiring existing, already-threat-modeled components — OmX/OmO/Clawhip/ResponseComposer — into the two existing Orchestrator entry points) introduces no new network endpoint, auth path, file access pattern, or schema change at a trust boundary beyond what Plans 04/05/06/08's own threat models already cover. This plan's own `<threat_model>` (T-03-03 malformed-plan dispatch, T-03-02 silent-failure-swallowing) is satisfied by the `OmXPlanValidationError` → `PLAN_REJECTED` handler and by `OmO.dispatch()`'s existing `PHASE_FAILED` emission (Plan 08), both exercised unchanged through the new wiring.

## Self-Check: PASSED

- FOUND: `backend/agent/orchestrator.py` (pipeline wiring present — `self.omx`, `self.omo`, `self.clawhip`, `self._agents`, `_compact_findings`, `_reject_plan`) — verified via `[ -f ... ]`
- FOUND: `backend/agent/response_composer.py` (`compose_plan_summary` method present) — verified via `[ -f ... ]`
- FOUND: `backend/config.py` (`models_input_path`/`ml_results_path` fields present) — verified via `[ -f ... ]`
- FOUND: `tests/agent/test_orchestrator.py` (15 tests present) — verified via `[ -f ... ]`
- FOUND: `.planning/phases/03-orchestration-upgrade/03-09-SUMMARY.md` — verified via `[ -f ... ]`
- FOUND commit `9c3fea9` (feat — Task 1, construction) — verified via `git log --oneline --all | grep`
- FOUND commit `47c55d0` (test RED — Task 2) — verified via `git log --oneline --all | grep`
- FOUND commit `6a92514` (feat GREEN — Task 2) — verified via `git log --oneline --all | grep`

## TDD Gate Compliance

Task 2 carries `tdd="true"`. Gate sequence verified in git log:

1. RED gate: `47c55d0 test(03-09): add failing tests for OmX->OmO->ResponseComposer pipeline` — confirmed 9 of 9 new pipeline-behavior tests failing (mock-not-awaited assertions, wrong LLM mode, wrong streamed content, empty rejection message) against the still-old LLM-completion-only `process()`/`process_stream()`, while the 6 pre-existing/Task-1 tests in the same file continued passing (isolating the failure to exactly the new behavior under test).
2. GREEN gate: `6a92514 feat(03-09): implement OmX->OmO->ResponseComposer pipeline in process()/process_stream()` — implementation restored, all 15 tests (5 construction + 10 pipeline-behavior, including one test-only formatting fix) passing after.
3. No REFACTOR commit needed (the one inline fix during GREEN — see Deviations #2 — was a test-authoring bug caught and corrected within the same GREEN commit, not a post-GREEN cleanup pass).

Task 1 (`9c3fea9`) is a plain `type="auto"` task (no `tdd="true"`), so RED/GREEN gating does not apply to it — verified inline via the same test file's construction-test subset.
