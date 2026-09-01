---
phase: 03-orchestration-upgrade
plan: 05
subsystem: clawhip-event-router
tags: [websocket, xai-audit, event-router, orchestration]
dependency-graph:
  requires: []
  provides:
    - "backend/agent/clawhip.py: ClawhipEventType, ClawhipEvent, Clawhip.emit()"
    - "backend/intelligence/research_daemon.py: ResearchDaemon.deliver_to_clawhip() stub"
  affects:
    - "Plan 08 (OmO): emits GATE_PENDING via Clawhip when a gated directive cannot resolve mid-dispatch"
tech-stack:
  added: []
  patterns:
    - "Thin two-call event router (no pub/sub abstraction) wrapping existing ConnectionManager + ExplainableAI"
key-files:
  created:
    - backend/agent/clawhip.py
    - tests/agent/test_clawhip.py
  modified:
    - backend/intelligence/research_daemon.py
decisions:
  - "Clawhip.emit() audits PHASE_FAILED/PLAN_REJECTED/GATE_PENDING only — routine PHASE_STARTED/PHASE_COMPLETED lifecycle events are not audit-logged (matches AI-SPEC Section 6 guardrail: audit gate/failure events, not high-frequency noise)"
  - "research_daemon stub kept deliberately inert (debug log only, no queue/thread) per D-10 — real wiring deferred to v1.1 Phase 9"
metrics:
  duration: 12min
  completed: 2026-09-01
---

# Phase 03 Plan 05: Clawhip Event Router Summary

Built the single typed-event router (clawhip) that formats and pushes lifecycle/phase events to the frontend WebSocket via the existing `ConnectionManager`, and conditionally to the `ExplainableAI` audit trail — giving `ExplainableAI.log_decision()` its first real caller and the terminal `GATE_PENDING` event Plan 08's OmO coordinator will emit.

## What Was Built

- `backend/agent/clawhip.py`: `ClawhipEventType` enum (`PHASE_STARTED`, `PHASE_COMPLETED`, `PHASE_FAILED`, `PLAN_REJECTED`, `GATE_PENDING`), `ClawhipEvent` Pydantic model, and `Clawhip` class with `async emit(session_id, event)`. `emit()` always calls `connection_manager.send(session_id, event.model_dump(mode="json"))`, and additionally calls `xai_logger.log_decision(...)` only for `PHASE_FAILED`/`PLAN_REJECTED`/`GATE_PENDING` (auditable decision/failure/gate-boundary events, not routine lifecycle noise).
- `backend/intelligence/research_daemon.py`: added `ResearchDaemon.deliver_to_clawhip(payload)` — a minimal, genuinely inert stub delivery-channel method (debug log only, no queue/thread/task) that clawhip (or future OmO Architect-role wiring) can target as a monitoring sink per D-10.
- `tests/agent/test_clawhip.py`: 10 tests covering emit-and-send-always, conditional XAI logging per event type, plain-dict payload shape, `GATE_PENDING` enum membership, absence of any "Collab" reference in the module (D-09 boundary), and the research-daemon stub's callability/inertness.

## Task-by-Task

1. **Task 1 — Implement Clawhip event router (TDD)**: RED test committed first (`dd5e173`) confirming `backend.agent.clawhip` did not yet exist; GREEN implementation committed (`9d85f25`) with all emit-behavior tests passing.
2. **Task 2 — Minimal research-daemon delivery stub (D-10)**: `deliver_to_clawhip()` added (`781aa87`), asserted callable-and-inert with no thread/task creation.

## Verification

- `pytest tests/agent/test_clawhip.py -x --tb=short` → 10 passed
- `python -c "from backend.agent.clawhip import Clawhip, ClawhipEvent, ClawhipEventType; assert ClawhipEventType.GATE_PENDING"` → imports clean
- Full repo test suite (excluding pre-existing `tests/tools/test_sandbox_docker.py` collection error caused by a missing `docker` package in this sandbox, unrelated to this plan): 163 passed, 2 skipped, 15 xfailed — no regressions.

## Deviations from Plan

### Auto-fixed Issues

**1. [Rule 1 - Bug] Removed literal "CollabWebSocket" wording from clawhip.py's own docstring**
- **Found during:** Task 1, first test run (GREEN phase)
- **Issue:** The plan's acceptance criteria requires `grep -c "Collab" backend/agent/clawhip.py` to return zero hits ("No CollabWebSocket / subscriber-list code exists"). My first draft's module/class docstrings explained the D-09 exclusion using the literal word "CollabWebSocket," which technically violated that grep-based acceptance check even though no CollabWebSocket *code* was ever present.
- **Fix:** Reworded both docstrings to describe the exclusion without using the string "Collab" (e.g., "does not deliver to any multi-user, real-time-collaboration transport").
- **Files modified:** `backend/agent/clawhip.py`
- **Commit:** `9d85f25`

No other deviations — plan executed as written.

## Known Stubs

- `ResearchDaemon.deliver_to_clawhip()` is an intentional stub per D-10 (debug log only). No listener, queue, or real delivery exists. Full wiring is v1.1 Phase 9 scope (Auto Research & Strategy Evolution) — not a gap introduced by this plan.
- `Clawhip` is constructed with injected `connection_manager`/`xai_logger` but has no live call site yet in this plan — Plan 08 (OmO) is the consumer that instantiates and calls `Clawhip.emit()` for real, including the `GATE_PENDING` terminal event. This is expected: Plan 05's scope is the router itself, not its wiring into OmO's dispatch loop.

## Self-Check: PASSED

- FOUND: backend/agent/clawhip.py
- FOUND: backend/intelligence/research_daemon.py (deliver_to_clawhip method present)
- FOUND: tests/agent/test_clawhip.py
- FOUND commit dd5e173 (test RED)
- FOUND commit 9d85f25 (feat GREEN — Clawhip)
- FOUND commit 781aa87 (feat — research_daemon stub)

## TDD Gate Compliance

Task 1 carries `tdd="true"`. Gate sequence verified in git log:
1. RED gate: `dd5e173 test(03-05): add failing test for Clawhip event router` — confirmed failing (ModuleNotFoundError) before implementation.
2. GREEN gate: `9d85f25 feat(03-05): implement Clawhip event router` — all clawhip-related tests passing after.
3. No REFACTOR commit was needed (no post-GREEN cleanup required).

Task 2 (`781aa87`) is a plain `type="auto"` task (no `tdd="true"`), so RED/GREEN gating does not apply to it — verified inline via the same test file.
