---
phase: 03-orchestration-upgrade
plan: 06
subsystem: agent-orchestration
tags: [omx, planner, forced-tool-use, anthropic-sdk, pydantic, orch-03, d-01, d-06]

# Dependency graph
requires: []
provides:
  - "Directive/EngagementPlan Pydantic models — the DAG schema OmO (a later plan) dispatches against"
  - "OmX.plan(directive_text, session) -> EngagementPlan via Claude forced tool use, with a 3-attempt validation-retry loop and OmXPlanValidationError hard-failure"
  - "_OMX_PLANNING_SYSTEM_PROMPT — dedicated planning-only system prompt, distinct from orchestrator._SYSTEM_PROMPT, with scope/stealth constraints and the $pentest few-shot"
affects: [03-07, 03-08, 03-09]

# Tech tracking
tech-stack:
  added: []
  patterns:
    - "Anthropic forced tool use (tool_choice={type:tool, name:..., disable_parallel_tool_use:True}) for structured-output DAG generation, tool_use block selected by .type never by content[0] position"
    - "Pydantic model_json_schema() derives the tool's input_schema directly from the validator model so schema and validation can never drift apart"
    - "Validation-retry loop: on ValidationError or stop_reason=='max_tokens', append the model's own malformed output plus a corrective user turn and retry, up to 3 total attempts, then raise a domain-specific exception rather than dispatch a partial/default result"

key-files:
  created:
    - backend/agent/omx.py
    - tests/agent/test_omx.py
  modified: []

key-decisions:
  - "Worktree HEAD was on a stale pre-Phase-3 base (7f9efad, ~5 commits behind main, no phase-03 planning docs present) — corrected via the mandated worktree_branch_check git reset --hard to d04606b (the phase-03 finalize-plan commit) before any file was read. No commits were lost; the target commit already existed in the object store."
  - "Split the single-pass implementation into two commits matching the plan's Task 1 / Task 2 boundaries (schema+prompt, then plan() method) rather than one combined commit, to keep per-task atomicity even though both were authored together"
  - "$pentest few-shot in _OMX_PLANNING_SYSTEM_PROMPT maps architecture doc phases 6-8 (verify/attribution/report, originally VerificationLoop/ThreatAttributionEngine/IntelligentReporter in OPTIMUS_PRIME_ARCHITECTURE.md 3.1) onto IntelAgent, since those are not registered BaseAgent subclasses today — kept the illustrative example inside the closed agent vocabulary the prompt itself declares, rather than contradicting it"
  - "Local test execution required a scratch venv (python3.14 is the only interpreter available in this environment vs. the project's pinned 3.12) with unpinned-latest pydantic/anthropic/fastapi/aiohttp — backend/requirements.txt itself was NOT modified; this was dev-environment-only tooling to run pytest against already-pinned, already-vetted project dependencies"

patterns-established:
  - "AI-SPEC Section 3 plan() shape implemented verbatim: 3-attempt loop, next(b for b in response.content if b.type=='tool_use'), EngagementPlan.model_validate(tool_use.input), corrective retry turn on ValidationError"

requirements-completed: [ORCH-03]

# Metrics
duration: ~35min (including worktree base correction)
completed: 2026-09-01
---

# Phase 3 Plan 06: OmX Workflow Planner Summary

**LLM-driven engagement planner: Claude forced tool use decomposes an operator directive into a Pydantic-validated `EngagementPlan` DAG, with a 3-attempt validation-retry loop and a hard `OmXPlanValidationError` failure — never a partial/hallucinated plan reaching dispatch.**

## Performance

- **Duration:** ~35 min (including worktree base correction — see Deviations)
- **Completed:** 2026-09-01
- **Tasks:** 2/2 completed
- **Files modified:** 2 (1 new source, 1 new test)

## Accomplishments

- `backend/agent/omx.py`: `Directive`/`EngagementPlan` Pydantic models exactly per AI-SPEC Section 3 (`engine: Literal["InfrastructureEngine","MLAIEngine","ICSEngine"]`, `tools`/`depends_on` default to `[]`, `gate_required` defaults `False`); `OmXPlanValidationError(Exception): pass` minimal idiom matching `ToolPermissionError`; a dedicated `_OMX_PLANNING_SYSTEM_PROMPT` (distinct string from `orchestrator._SYSTEM_PROMPT`) stating the closed engine/agent vocabulary, scope.targets/exclusions/stealth_level hard constraints with `gate_required` guidance for ambiguous assets, a stealth-conformance-on-every-retry instruction, and the canonical `$pentest` 8-phase decomposition as a static inline few-shot (including a full example `emit_engagement_plan` JSON payload).
- `OmX.__init__(llm_router)` builds `self._plan_tool` with `input_schema=EngagementPlan.model_json_schema()` so the tool schema can never drift from the Pydantic validator.
- `OmX.plan(directive_text, session) -> EngagementPlan`: injects `session.scope` (targets/exclusions/stealth_level/ports/protocols) into the user turn, calls `self.llm_router.claude.messages.create(...)` directly with forced tool use (`tool_choice={"type":"tool","name":"emit_engagement_plan","disable_parallel_tool_use":True}`), selects the `tool_use` block by `.type` (never `content[0]`), treats `stop_reason=="max_tokens"` as a truncated-JSON validation failure, and on `ValidationError` appends the model's own content plus a corrective user turn and retries — 3 total attempts before raising `OmXPlanValidationError`. Never calls `LLMRouter.complete()` or references Ollama (`grep -n "_ollama\|mode=\"orchestration\"\|\.complete(" backend/agent/omx.py` returns nothing).
- `tests/agent/test_omx.py`: 12 tests covering schema validation (8-directive DAG, bogus-engine rejection, field defaults), the minimal-exception idiom, prompt-content assertions (distinct from orchestrator prompt, closed engine vocabulary, `$pentest` few-shot, scope/stealth/gate_required language), forced-tool-use call shape, tool_use-block-by-type selection with a leading text block, the 3-attempt retry-then-succeed path, the 3-attempt exhaustion-then-raise path, `max_tokens`-triggers-retry, and the no-Ollama/no-`.complete()`-fallback source-scan assertion.

## Verification

- `pytest tests/agent/test_omx.py -k "model or schema or prompt" -x --tb=short` — 3 passed (Task 1 subset)
- `pytest tests/agent/test_omx.py -x --tb=short` — 12 passed (both tasks)
- `python -c "from backend.agent.omx import OmX, EngagementPlan, Directive, OmXPlanValidationError"` — imports clean
- Full regression suite (`pytest tests/`) — 171 passed, 2 skipped, 15 xfailed (pre-existing), no regressions introduced
- `grep -n "_ollama\|mode=\"orchestration\"\|\.complete(" backend/agent/omx.py` — no matches (acceptance criterion: OmX never falls back to Ollama/LLMRouter.complete())

## Deviations

### Auto-fixed Issues

**1. [Rule 3 - Blocking] Worktree HEAD was on a stale pre-Phase-3 base**
- **Found during:** `worktree_branch_check` (mandatory first step)
- **Issue:** `git merge-base HEAD d04606b...` did not equal `d04606b...` — the worktree's branch (`worktree-agent-a02734552f92c221c`) had been forked from `7f9efad` (a commit predating all of Phase 3's planning docs — `.planning/phases/03-orchestration-upgrade/` did not exist at that base), not from the phase-03 finalize-plan commit the orchestrator expected.
- **Fix:** Confirmed no uncommitted tracked changes existed (only an untracked, pre-existing `.planning/HANDOFF.json`), confirmed the expected commit `d04606b` existed in the repository's object store (reachable from `main`), then ran the prompt-mandated `git reset --hard d04606b50ae1703ab6bffefc31ca4ca392614305` and verified `HEAD` matched.
- **Files modified:** None (git ref only)
- **Commit:** N/A (pre-work correction, not a task deliverable)

**2. [Rule 3 - Blocking] No Python dependencies installed anywhere on the host; only Python 3.14 available (project targets 3.12)**
- **Found during:** First `pytest` invocation for Task 1 verification
- **Issue:** `ModuleNotFoundError: No module named 'fastapi'` (then `pydantic`, `anthropic`, `aiohttp`) — the sandboxed environment has no project virtualenv, and `pip install` at the pinned versions (`pydantic==2.9.2` etc.) fails to build `pydantic-core` from source because the pinned `pydantic-core`'s Rust/PyO3 toolchain does not support Python 3.14 (only up to 3.13).
- **Fix:** Created a throwaway venv under the session scratchpad directory and installed unpinned-latest `pydantic`/`anthropic`/`fastapi`/`pytest`/`pytest-asyncio`/`pydantic-settings`/`httpx`/`aiohttp` (all API-compatible major versions) purely to execute the test suite locally. `backend/requirements.txt` was NOT modified — this is dev-tooling-only, not a project dependency change, and no new/unvetted package names were introduced (all are already-pinned project dependencies; only their exact patch versions differ to get a Python-3.14-compatible wheel).
- **Files modified:** None (scratch venv outside the repo)
- **Commit:** N/A

## Known Stubs

None — OmX is fully implemented per the plan; it has no wiring to OmO/dispatch (that is explicitly a later plan's scope, and OmX's own independence from OmO is a stated success criterion).

## Threat Flags

None — this plan's surface (an LLM planning call + Pydantic validation) is fully covered by the plan's own `<threat_model>` (T-03-03, T-03-01, T-03-06, T-03-SC); no new network endpoint, auth path, file access pattern, or schema change at a trust boundary was introduced beyond what the threat model already anticipates.

## Self-Check: PASSED

- `backend/agent/omx.py` — FOUND
- `tests/agent/test_omx.py` — FOUND
- Commit `c551192` (Task 1: schema/prompt) — FOUND in `git log --oneline --all`
- Commit `59c8d39` (Task 2: plan() method) — FOUND in `git log --oneline --all`
