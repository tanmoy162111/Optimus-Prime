---
phase: 1
slug: cleanup-configuration
status: draft
nyquist_compliant: false
wave_0_complete: false
created: 2026-05-12
---

# Phase 1 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | pytest 8.3.3 + pytest-asyncio 0.24.0 |
| **Config file** | `pyproject.toml` |
| **Quick run command** | `pytest tests/ -v --tb=short` |
| **Full suite command** | `pytest tests/ -v --tb=short` (after CLEAN-01 deletes backend/tests/) |
| **Estimated runtime** | ~10 seconds |

---

## Sampling Rate

- **After every task commit:** Run `pytest tests/ -v --tb=short`
- **After every plan wave:** Run `pytest tests/ -v --tb=short`
- **Before `/gsd:verify-work`:** Full suite must be green
- **Max feedback latency:** ~10 seconds

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|-----------|-------------------|-------------|--------|
| model-fix | 01 | 1 | CLEAN-02 | unit | `pytest tests/agent/test_llm_router.py -v` | ✅ | ⬜ pending |
| dead-tests-delete | 02 | 1 | CLEAN-01 | structural | `python -c "import os; assert not os.path.exists('backend/tests/test_base_agent_resilience.py')"` | N/A | ⬜ pending |
| preserved-tests-check | 02 | 1 | CLEAN-01 | import | `python -c "import backend.agent; import backend.session"` | ✅ | ⬜ pending |
| delete-dead-dirs | 02 | 2 | CLEAN-01 | structural | `python -c "import os; [assert not os.path.exists(p) for p in ['backend/core','backend/agents','backend/main.py']]"` | N/A | ⬜ pending |
| pytest-testpaths | 02 | 2 | CLEAN-01 | config | `grep 'testpaths' pyproject.toml` → must show `["tests"]` only | ✅ | ⬜ pending |
| full-suite-green | 02 | 2 | CLEAN-01 | suite | `pytest tests/ -v` → exit 0 | ✅ | ⬜ pending |

*Status: ⬜ pending · ✅ green · ❌ red · ⚠️ flaky*

---

## Wave 0 Requirements

Existing infrastructure covers all phase requirements. No new test files need to be created.

- `tests/agent/test_llm_router.py` — already exercises LLMRouter with config.settings.claude_model
- CLEAN-01 verification is structural (directory absence + import success) — no new test code needed

---

## Manual-Only Verifications

| Behavior | Requirement | Why Manual | Test Instructions |
|----------|-------------|------------|-------------------|
| No "Claude error / falling back to Ollama" in logs during normal operation | CLEAN-02 | Requires running the full backend and sending a message; can't be automated without live Anthropic API key | Start backend, send one chat message, grep logs for `"Claude error"` — must be absent |

---

## Validation Sign-Off

- [ ] All tasks have `<automated>` verify or Wave 0 dependencies
- [ ] Sampling continuity: no 3 consecutive tasks without automated verify
- [ ] Wave 0 covers all MISSING references
- [ ] No watch-mode flags
- [ ] Feedback latency < 10s
- [ ] `nyquist_compliant: true` set in frontmatter

**Approval:** pending
