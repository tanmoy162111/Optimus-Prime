---
phase: 03-orchestration-upgrade
plan: 08
subsystem: omo-dispatch-coordinator
tags: [omo, dispatch, sequential, orch-01, orch-03, d-02, d-07, d-08, scope-gate]

# Dependency graph
requires:
  - "backend/agent/omx.py: Directive/EngagementPlan/OmXPlanValidationError (Plan 06)"
  - "backend/agent/clawhip.py: Clawhip/ClawhipEvent/ClawhipEventType (Plan 05)"
  - "backend/agent/task_registry.py + backend/session/session_store.py: TaskRegistry handoff store (Plans 03/04)"
provides:
  - "backend/agent/omo.py: validate_plan_against_registry/acyclic/scope/stealth + validate_plan() pre-dispatch gate"
  - "backend/agent/omo.py: OmO.dispatch(plan, session, agents=None) — sequential dispatch loop, per-directive timeout, PHASE_FAILED/GATE_PENDING emission"
  - "backend/intelligence/strategy_evolution.py: StrategyEvolutionEngine.enrich_directive(directive) — OmO's defensive Architect-role integration point"
affects: [03-09]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Pre-dispatch validation gate (registry + acyclic + scope-membership + stealth-tier) runs to completion before directive 1 ever calls agent.execute() — 'validate before execute'"
    - "asyncio.wait_for + asyncio.TimeoutError per-directive timeout idiom (matches kali_ssh.py/custom_tool_generator.py precedent)"
    - "Whole-directive failure unit (D-07): any exception or timeout inside agent.execute() maps to exactly one phase_status=failed + TaskRegistry.mark(failed) + PHASE_FAILED clawhip emission, never a bare except/pass"
    - "Terminal GATE_PENDING boundary: gate_required=True directives fail closed (never dispatched, never hang/loop) since mid-dispatch operator approval is out of scope for phase 3"
    - "Architect role (StrategyEvolutionEngine) wired via a new enrich_directive() convenience method that wraps a single Directive in a one-node AttackChain and swallows all exceptions — call-safe regardless of ResearchKB/SmartMemory initialization state"

key-files:
  created:
    - backend/agent/omo.py
    - tests/agent/test_omo.py
  modified:
    - backend/intelligence/strategy_evolution.py

key-decisions:
  - "Per-directive timeout is a constructor parameter (OmO.__init__(..., directive_timeout=300)), not a new backend/config.py Settings field — files_modified for this plan does not list config.py, and a module-level default constant keeps the change scoped to omo.py per the plan's own file boundary"
  - "Stealth-tier check (validate_plan_stealth) is deliberately minimal: Directive.tools is a plain tool-name list with no per-flag detail (OmX doesn't emit flags separately), so the hook only rejects a tool *name* embedding a known aggressive-timing token (-t4/-t5/--max-rate/--min-rate) when scope.stealth_level is stealth-constrained ('stealth'/'low') — full flag-level enforcement is a future-phase concern once Directive carries a dedicated flags field, not scope creep for this plan"
  - "StrategyEvolutionEngine.enrich_directive() constructs its ChainNode with cve_id=None and reuses directive.phase as the technique — this can still reach ResearchKB.query() if the KB is uninitialized (unlike a cve_id=None/technique='' node that would skip it entirely), so the method wraps the whole enrich_chain() call in try/except to stay call-safe per D-10's 'invoke it but wrap defensively' instruction, rather than relying solely on avoiding the KB call path"
  - "Unmet-dependency directives are skipped (logged at WARNING, no clawhip emission) rather than treated as a failure — matches AI-SPEC.md's guardrail table ('Block — dispatch pauses; agent.execute() is not called') and lets independent, non-dependent directives in the same plan continue dispatching (D-08 sequential walk, not abort-on-first-gate)"

requirements-completed: [ORCH-01, ORCH-03]

# Metrics
duration: ~40min
completed: 2026-09-01
---

# Phase 3 Plan 08: OmO Multi-Agent Coordinator Summary

**Sequential dispatch coordinator that walks OmX's validated EngagementPlan DAG one directive at a time, enforcing scope/registry/cycle/stealth validation before any execution and guaranteeing a PHASE_FAILED (or terminal GATE_PENDING) event for every directive outcome — closing four of the five Critical Failure Modes from 03-AI-SPEC.md.**

## Performance

- **Duration:** ~40 min
- **Completed:** 2026-09-01
- **Tasks:** 2/2 completed
- **Files modified:** 3 (1 new source, 1 new test, 1 modified source)

## Accomplishments

- `backend/agent/omo.py`:
  - `validate_plan_against_registry(plan, agents)` — raises `OmXPlanValidationError` listing any `directive.agent` not in the live agent registry (RESEARCH.md Code Examples, verbatim shape). Closes Critical Failure Mode #3 (hallucinated agent name).
  - `validate_plan_acyclic(plan)` — white/gray/black DFS cycle detection over the `depends_on` graph; raises `OmXPlanValidationError` with the cycle path on detection.
  - `validate_plan_scope(plan, scope)` — deterministic set-membership scope-authorization gate (T-03-01): every `directive.target` must be in `scope.targets` and not in `scope.exclusions`, unless `gate_required=True` (ambiguous/discovered assets escalate via the gate rather than being silently included/excluded). Documents in-code (RESEARCH.md Pitfall 7) that this proves authorization, not shell-metacharacter safety.
  - `validate_plan_stealth(plan, stealth_level)` — minimal stealth-tier hook: rejects tool names embedding known aggressive-timing tokens when `stealth_level` is stealth-constrained.
  - `validate_plan(plan, agents, scope)` — runs all four gates in order; called as the first line of `OmO.dispatch()`, before the sequential loop, so no directive ever reaches `agent.execute()` on a validation failure.
  - `OmO.__init__(agents, clawhip, task_registry, architect=None, directive_timeout=300)` and `async def dispatch(plan, session, agents=None)` — D-08 strictly sequential (`for directive in plan.directives: await ...`, no `asyncio.gather`/`asyncio.create_task`). Per directive: skips if any `depends_on` prerequisite's `phase_status != "completed"`; if `gate_required=True`, sets `phase_status="gate_pending"`, marks `TaskRegistry` `"failed"` with a re-issue-needed error detail, and emits `GATE_PENDING` via clawhip — never calling `agent.execute()` for that directive (terminal, fails closed, phase-3 gate boundary); otherwise marks `TaskRegistry`/`phase_status` `"running"`, emits `PHASE_STARTED`, and calls `asyncio.wait_for(agent.execute(directive.target, tools=directive.tools), timeout=directive_timeout)` — `directive.tools` passed straight through, no `ToolSelector`/`InstructionParser`/`EngineRouter.dispatch()` call site anywhere (D-02a). On `asyncio.TimeoutError` or any `Exception`, both funnel through a single `_fail_directive()` helper: `phase_status="failed"`, `TaskRegistry.mark(..., "failed", error_detail=...)`, `logger.error(...)`, and exactly one `PHASE_FAILED` clawhip emission (whole-directive failure unit, D-07 — never a bare `except: pass`). On success: `phase_status="completed"`, `session.state.add_finding(result)`, `TaskRegistry.mark(..., "completed")`, `PHASE_COMPLETED` emitted, then a defensive optional call to `self.architect.enrich_directive(directive)` (never allowed to break the directive's own success path).
- `backend/intelligence/strategy_evolution.py`: added `StrategyEvolutionEngine.enrich_directive(directive)` — OmO's Architect-role (D-10) integration point. Wraps a single `Directive` into a one-node `AttackChain`/`ChainNode` (using `directive.phase` as the technique and the first `directive.tools` entry, if any) and routes it through the existing `enrich_chain()` pipeline, catching and logging (at `WARNING`) any exception rather than propagating — call-safe regardless of whether the injected `ResearchKB`/`SmartMemory` are initialized.
- `tests/agent/test_omo.py`: 23 tests across two TDD cycles — Task 1 (11 tests: registry/cycle/scope validator unit tests plus dispatch-level tests asserting each validation failure blocks all `agent.execute()` calls) and Task 2 (12 tests: success path with tools-passthrough, failure/timeout path emitting exactly one `PHASE_FAILED`, terminal `GATE_PENDING` boundary never calling `execute()`, strict DAG-order dispatch with a `asyncio.gather`/`asyncio.create_task` source-scan assertion, unmet-dependency skip, no-bare-except source-scan assertion, and Architect integration both with a raising mock and with `architect=None`).

## Task-by-Task

1. **Task 1 — Pre-dispatch validation gate (TDD)**: RED test committed first (`e47e913`) confirming `backend.agent.omo` did not yet exist; GREEN implementation committed (`2fc1db2`) with all 11 validation-gate tests passing, `dispatch()` calling `validate_plan()` before an (at this point) empty loop body.
2. **Task 2 — Sequential dispatch loop with timeout/phase_status/PHASE_FAILED/GATE_PENDING (TDD)**: RED tests appended (`9600dda`) confirming all 10 new dispatch-behavior tests failed against the Task 1 stub (missing `phase_status` keys, zero clawhip emissions, zero `execute()` calls); GREEN implementation committed (`5b29099`) implementing the full loop plus the `StrategyEvolutionEngine.enrich_directive()` Architect integration point, with all 23 tests passing.

## Verification

- `pytest tests/agent/test_omo.py -k "validate or registry or scope or cycle or gate" -x --tb=short` (Task 1 subset) → 10 passed
- `pytest tests/agent/test_omo.py -x --tb=short` → 23 passed
- `python -c "from backend.agent.omo import OmO"` → imports clean
- `grep -n "asyncio.gather\|asyncio.create_task" backend/agent/omo.py` / `grep -n "except:" backend/agent/omo.py` → no real usage (only docstring mentions of what is deliberately absent)
- Full regression suite (`pytest tests/ --ignore=tests/tools/test_sandbox_docker.py`) → 227 passed, 2 skipped, 15 xfailed, no regressions (the ignored module has a pre-existing, unrelated `ModuleNotFoundError: No module named 'docker'` collection error in this sandbox, documented in Plan 05's summary)

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Docstring text triggered the plan's own "no gather/create_task" grep-style test assertion**
- **Found during:** Task 2, first GREEN test run
- **Issue:** `OmO.dispatch()`'s docstring/comment explaining D-08 originally used the literal strings `asyncio.gather`/`asyncio.create_task` to describe what is *not* used — `test_no_gather_or_create_task_in_dispatch_source` (which does `inspect.getsource(OmO.dispatch)` and asserts those substrings are absent) failed on the comment text itself, not real usage.
- **Fix:** Reworded the in-method comment to "no concurrent/batched dispatch primitives" (module-level docstring, outside `dispatch()`'s own source, still names the exact APIs for a human reader).
- **Files modified:** `backend/agent/omo.py`
- **Commit:** `5b29099`

No other deviations — plan executed as written, including the `strategy_evolution.py` touch declared in `files_modified` (03-PATTERNS.md had flagged "no code change expected" as a possibility, but the plan's own action text required a real, defensively-wrapped Architect-role call site, which `enrich_directive()` provides).

## Known Stubs

- `StrategyEvolutionEngine.enrich_directive()` is a minimal D-10 integration point, not full enrichment: it always constructs a `ChainNode` with `cve_id=None`, so `enrich_chain()`'s CVE-based PoC lookup branch is never exercised from OmO's call site. This is intentional per the plan ("invoke it but wrap defensively... don't require real enrichment") — full Architect-role wiring (CVE-aware chain construction from directive findings) is out of this phase's scope (v1.1 Phase 9, per 03-CONTEXT.md D-10).
- `OmO`'s `directive_timeout` has no dedicated `backend/config.py` field — it is a per-instance constructor default (300s) only. If a future plan wires `Orchestrator.__init__` to construct `OmO` for real (Plan 09's scope), that wiring should decide whether to surface this as an operator-configurable setting; not done here since `config.py` was outside this plan's `files_modified`.

## Threat Flags

None — this plan's surface (a pre-dispatch validation gate plus a sequential in-process dispatch loop) is fully covered by the plan's own `<threat_model>` (T-03-01 scope-membership gate, T-03-02 silent-failure mitigation, T-03-03 hallucinated-DAG gate, T-03-04 out-of-order/ungated dispatch, T-03-07-inj accepted injection-surface carve-out). No new network endpoint, auth path, file access pattern, or schema change at a trust boundary was introduced.

## Self-Check: PASSED

- FOUND: `backend/agent/omo.py`
- FOUND: `tests/agent/test_omo.py`
- FOUND: `backend/intelligence/strategy_evolution.py` (`enrich_directive` method present)
- FOUND commit `e47e913` (test RED — Task 1)
- FOUND commit `2fc1db2` (feat GREEN — Task 1)
- FOUND commit `9600dda` (test RED — Task 2)
- FOUND commit `5b29099` (feat GREEN — Task 2)

## TDD Gate Compliance

Both tasks carry `tdd="true"`. Gate sequence verified in git log:

**Task 1:**
1. RED gate: `e47e913 test(03-08): add failing test for OmO pre-dispatch validation gate` — confirmed failing (`ModuleNotFoundError: No module named 'backend.agent.omo'`) before implementation.
2. GREEN gate: `2fc1db2 feat(03-08): implement OmO pre-dispatch validation gate` — all 11 Task 1 tests passing after.
3. No REFACTOR commit needed.

**Task 2:**
1. RED gate: `9600dda test(03-08): add failing test for OmO sequential dispatch loop` — confirmed all 10 new tests failing (KeyError on unset `phase_status`, zero clawhip emissions, zero `execute()` awaits) against the Task 1 stub before implementation.
2. GREEN gate: `5b29099 feat(03-08): implement OmO sequential dispatch loop with PHASE_FAILED + GATE_PENDING` — all 23 tests passing after.
3. No REFACTOR commit needed (one inline fix during GREEN — see Deviations — was folded into the GREEN commit, not a separate refactor pass).
