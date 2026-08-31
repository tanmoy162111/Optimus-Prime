---
phase: 3
slug: orchestration-upgrade
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-09-01
---

# Phase 3 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | pytest 8.3.3 + pytest-asyncio 0.24.0 (`asyncio_mode="auto"`) |
| **Config file** | `pyproject.toml` (`testpaths = ["tests"]`, `python_files = ["test_*.py"]`) |
| **Quick run command** | `pytest tests/agent/ tests/session/ -x --tb=short` |
| **Full suite command** | `pytest tests/ --tb=short` |
| **Estimated runtime** | ~30 seconds (quick), ~2-3 minutes (full suite, growing from Phase 2's 158-test baseline) |

---

## Sampling Rate

- **After every task commit:** Run the targeted test file for the requirement just implemented (see Per-Task Verification Map)
- **After every plan wave:** Run `pytest tests/ --tb=short` (full suite, repo root)
- **Before `/gsd:verify-work`:** Full suite must be green
- **Max feedback latency:** 30 seconds

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Secure Behavior | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|-----------------|-----------|-------------------|-------------|--------|
| TBD | TBD | TBD | ORCH-01 | `PHASE_FAILED` event reaches `ConnectionManager.send()` when a directive's `agent.execute()` raises | integration | `pytest tests/agent/test_omo.py::test_directive_failure_emits_phase_failed -x` | ❌ Wave 0 | ⬜ pending |
| TBD | TBD | TBD | ORCH-01 | `session.state.phase_status[directive.id]` transitions to `"failed"` on exception | unit | `pytest tests/agent/test_omo.py::test_phase_status_set_to_failed_on_exception -x` | ❌ Wave 0 | ⬜ pending |
| TBD | TBD | TBD | ORCH-02 | `LLMRouter.complete(mode="compaction")` resolves to Ollama/Qwen, never Claude | unit | `pytest tests/agent/test_llm_router.py::test_compaction_mode_routes_to_ollama -x` | ❌ Wave 0 (extends existing file) | ⬜ pending |
| TBD | TBD | TBD | ORCH-02 | `LLMRouter.complete(mode="orchestration")` still resolves to Claude (regression guard) | unit | `pytest tests/agent/test_llm_router.py -x` | ✅ existing | ⬜ pending |
| TBD | TBD | TBD | ORCH-03 | `OmX.plan()` returns a valid `EngagementPlan` for a canonical `$pentest`-style directive | unit | `pytest tests/agent/test_omx.py::test_plan_generates_valid_dag -x` | ❌ Wave 0 | ⬜ pending |
| TBD | TBD | TBD | ORCH-03 | A hallucinated agent name in a `Directive` fails registry validation before any `agent.execute()` call | unit | `pytest tests/agent/test_omo.py::test_unregistered_agent_blocks_dispatch -x` | ❌ Wave 0 | ⬜ pending |
| TBD | TBD | TBD | PERSIST-01 | `SessionStore` reload after a simulated restart reconstructs `phase_status`/findings matching last commit | integration | `pytest tests/session/test_session_store.py::test_resolve_after_restart_reconstructs_state -x` | ❌ Wave 0 (extends existing file) | ⬜ pending |
| TBD | TBD | TBD | PERSIST-01 | `TaskRegistry` rows with `status='running'` after restart are detected and surfaced | integration | `pytest tests/agent/test_task_registry.py::test_running_row_detected_after_restart -x` | ❌ Wave 0 | ⬜ pending |

*Task ID / Plan / Wave columns populated by the planner as plans are created.*

---

## Wave 0 Requirements

- [ ] `tests/agent/test_omx.py` — covers ORCH-03 (plan generation, validation-retry, `OmXPlanValidationError` after 3 attempts) — new file
- [ ] `tests/agent/test_omo.py` — covers ORCH-01, ORCH-03 (sequential dispatch, PHASE_FAILED emission, pre-dispatch registry/cycle validation) — new file
- [ ] `tests/agent/test_task_registry.py` — covers PERSIST-01's crash-detection query — new file
- [ ] `tests/agent/test_clawhip.py` — covers `Clawhip.emit()` → `ConnectionManager.send()` + conditional `ExplainableAI.log_decision()` calls — new file
- [ ] `tests/agent/test_instruction_parser.py` — zero existing coverage for `InstructionParser`/duplicate `EngineRouter` — needed to cover the D-02 reconciliation (signature change to `EngagementSession`, `EngineRouter.dispatch()` merge) — new file
- [ ] Extend `tests/session/test_session_store.py` — SQLite persistence + cache-plus-persistence `resolve()` behavior; update `test_resolve_returns_same_object` per RESEARCH.md's identity-semantics pitfall
- [ ] Extend `tests/agent/test_llm_router.py` — `mode="compaction"` and optional DeepSeek routing (ORCH-02)
- [ ] Add `summariser_threshold` field to `config.py` + a minimal `tests/agent/test_conversation_summariser.py` smoke test — `ConversationSummariser()` currently raises `AttributeError` (RESEARCH.md Pitfall — confirmed pre-existing defect this phase's own code depends on)
- [ ] Add `SmartMemory.get_best_tools()` stub + a `tests/memory/test_smart_memory.py` addition asserting it returns `[]` without raising — `StrategyEvolutionEngine.enrich_chain()` currently raises `AttributeError` (confirmed pre-existing defect)
- [ ] Framework install: none — pytest/pytest-asyncio already configured and passing (158 tests green per Phase 2's baseline)

---

## Manual-Only Verifications

*None — all four phase requirements have automated verification per the map above.*

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 30s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
