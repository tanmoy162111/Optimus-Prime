# Phase 1: Cleanup & Configuration — Research

**Researched:** 2026-05-12
**Domain:** Python module cleanup, pytest test migration, Anthropic Claude API model identifiers
**Confidence:** HIGH

---

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| CLEAN-01 | Delete `backend/main.py`, `backend/core/`, `backend/agents/`; migrate all `backend/tests/` imports to `backend/agent/` paths | Confirmed: 18 test files with 70 import occurrences of `backend.core.*` and `backend.agents.*` to migrate; exact module mappings documented below |
| CLEAN-02 | Correct `claude_model` in `backend/config.py` from `"claude-opus-4-7"` to `"claude-sonnet-4-6"` | Confirmed: single line change in `backend/config.py:8`; `llm_router.py` reads `config.settings.claude_model` at call time so no other change required |
</phase_requirements>

---

## Summary

Phase 1 is a pure cleanup phase with zero new features. There are two independent work streams:

**Work stream A (CLEAN-01):** The project has two parallel backend architectures. The old system lives in `backend/core/` (6-layer monolith, ~20 files), `backend/agents/` (legacy agents, ~9 files), and `backend/main.py` (846-line entry point). The new canonical system lives in `backend/agent/` (orchestration), `backend/api/` (endpoints), `backend/session/` (state), with `backend/app.py` as entry point. The Dockerfile already serves `backend.app:app` — so the old system is dead code. However, `pyproject.toml` points pytest at `backend/tests/`, which imports from the old system paths. Those 18 test files (70 import lines) must have their imports updated to equivalent new-system modules before the old directories can be deleted.

**Work stream B (CLEAN-02):** `backend/config.py` declares `claude_model: str = "claude-opus-4-7"`. The model ID `"claude-opus-4-7"` does not exist in the Anthropic API, causing every Claude call to 404 and fall back to Ollama silently. The correct current model is `"claude-sonnet-4-6"`. This is a one-line fix. The new system's `backend/agent/llm_router.py` reads `config.settings.claude_model` at request time (not at import time), so fixing `config.py` alone corrects the behavior without touching `llm_router.py`.

**Primary recommendation:** Fix CLEAN-02 first (one line, immediate unblocking). Then tackle CLEAN-01 test-by-test, verify each file passes, then delete the dead directories last.

---

## Standard Stack

No new libraries are needed. This phase uses the project's existing tooling.

### Core (already installed)
| Tool | Version | Purpose | Notes |
|------|---------|---------|-------|
| pytest | 8.3.3 | Run migrated test suite | Config in `pyproject.toml` |
| pytest-asyncio | 0.24.0 | Async test support | `asyncio_mode = "auto"` already set |
| anthropic | 0.38.0 | Claude API client | Already in `backend/requirements.txt` |
| pydantic-settings | 2.6.1 | Settings class that reads `claude_model` | Already in use |

### No new installations required

The cleanup work is entirely within the existing codebase — no `pip install` steps needed.

---

## Architecture Patterns

### Current State (before Phase 1)

```
backend/
├── app.py                  # NEW entry point (active, served by Docker)
├── main.py                 # OLD entry point (dead code — DELETE)
├── config.py               # Has wrong claude_model value — FIX
│
├── agent/                  # NEW canonical orchestration (KEEP)
│   ├── llm_router.py       # reads config.settings.claude_model
│   ├── orchestrator.py
│   └── sub_agents/
│       └── base.py         # Lightweight BaseAgent + ToolPermissionError
│
├── agents/                 # OLD legacy agents (DEAD CODE — DELETE)
├── core/                   # OLD 6-layer monolith (DEAD CODE — DELETE)
│   ├── base_agent.py       # Full BaseAgent with run_loop, ToolResult, AgentAction
│   ├── models.py           # AgentTask, ScopeConfig, FindingClassification, etc.
│   ├── event_bus.py        # DurableEventLog, EventBus
│   ├── omx.py              # OmX planner
│   ├── omo.py              # OmO coordinator
│   └── ...
│
└── tests/                  # OLD test suite — imports from core/agents (MIGRATE)
    └── test_*.py           # 18 files importing from backend.core.* and backend.agents.*
```

### Target State (after Phase 1)

```
backend/
├── app.py                  # Entry point (unchanged)
├── config.py               # claude_model = "claude-sonnet-4-6" (FIXED)
│
├── agent/                  # Canonical system (unchanged)
├── api/                    # Unchanged
├── session/                # Unchanged
│
└── tests/                  # All imports migrated to backend.agent.* paths
    └── test_*.py
```

### Pattern: One-Line Config Fix

```python
# backend/config.py — line 8 before:
claude_model: str = "claude-opus-4-7"

# backend/config.py — line 8 after:
claude_model: str = "claude-sonnet-4-6"
```

No other files need touching for CLEAN-02. The `llm_router.py` call site already reads `config.settings.claude_model` dynamically.

---

## CLEAN-01: Test Migration Map

This is the complete picture of what must change. The mapping is derived from examining each test file's imports against available modules in the new system.

### 18 Files with Old Imports — Decision per File

The key architectural fact: `backend/core/` contains production-grade implementations that the new `backend/agent/` system did NOT fully replicate. Specifically:

- `backend/core/models.py` — contains `AgentTask`, `ScopeConfig`, `FindingClassification`, `AgentType`, `EngineType`, `StealthLevel`, etc. These are NOT in `backend/agent/`.
- `backend/core/event_bus.py` — `DurableEventLog`, `EventBus`. NOT replicated in new system.
- `backend/core/omx.py`, `backend/core/omo.py` — OmX/OmO. NOT in new system.
- `backend/core/permission.py`, `backend/core/scope_enforcer.py`, etc. — NOT in new system.
- `backend/agents/recon_agent.py`, `backend/agents/exploit_agent.py`, etc. — NOT in new system (new equivalents exist in `backend/agent/sub_agents/` but may not have identical APIs).
- `backend/core/session.py` — old Session model. New session is in `backend/session/engagement_session.py`.
- `backend/core/terminal_broadcaster.py` — exists ONLY in `backend/core/`. Not replicated.

**Critical finding:** The `backend/tests/` suite tests the OLD system's production logic (OmX, OmO, full permission pipeline, BaseAgent with run_loop, EventBus, VerificationLoop). These modules are in `backend/core/` and cannot be "remapped" to `backend/agent/` because `backend/agent/` does not contain equivalent implementations.

### Two Strategies Available

| Strategy | Description | Risk |
|----------|-------------|------|
| **A — Delete tests that test dead code** | Tests for OmX, OmO, permission pipeline, event bus, scope enforcer, and agents all test the OLD system. Since the OLD system is dead code being deleted, tests for it are equally dead. Delete them along with the code they test. | Some tests may be testing modules that are still used (event_bus, verification_loop, memory, intelligence) via the old system paths. Those must be preserved or truly deleted. |
| **B — Move core/ and agents/ to a legacy path, keep tests** | Rename directories (e.g., `backend/_legacy/`) rather than deleting. Tests continue to work. Deferred proper cleanup. | Doesn't satisfy CLEAN-01 success criteria. |

**Recommended strategy: Strategy A with surgical preservation**

The following modules tested in `backend/tests/` are part of subsystems that still exist (not inside `core/` or `agents/`), and their tests can be preserved by updating imports:

| Test File | Old Import | Equivalent New Path | Action |
|-----------|-----------|---------------------|--------|
| `test_event_bus.py` | `backend.core.event_bus` | No equivalent in new system | The `event_bus` is used by `backend/main.py` (old), NOT by `backend/app.py` (new). Tests test dead code. **Delete or skip.** |
| `test_verification_loop_classify.py` | `backend.core.models.FindingClassification` | No `models.py` in new system | `FindingClassification` does not exist in new system. **Delete or skip.** |
| `test_session_merge.py` | `backend.core.session.Session` | `backend.session.engagement_session` | Different class name/API — evaluate if merge semantics are preserved |
| `test_terminal_broadcaster.py` | `backend.core.terminal_broadcaster`, `backend.main` | No equivalent in new system | Terminal broadcaster is old-system only. **Delete or skip.** |
| `test_report_formats.py` | `backend.main._resolve_findings` | No equivalent in new system | Tests `backend.main` internals. **Delete or skip.** |

**Tests that test subsystems still in `backend/` (outside `core/` and `agents/`):**

| Test File | Status | Notes |
|-----------|--------|-------|
| `test_client_profile.py` | Likely preserved — `backend/memory/client_profile.py` still exists | Check imports — if using `backend.core.*` only for models, may need small edits |
| `test_smart_memory.py` | Likely preserved — `backend/memory/smart_memory.py` still exists | Check imports |
| `test_source_adapters.py` | Likely preserved — `backend/intelligence/source_adapters.py` still exists | Check imports |
| `test_custom_tool_generator.py` | Likely preserved — `backend/intelligence/custom_tool_generator.py` still exists | May import `backend.core.event_bus` — needs verification |
| `test_research_daemon.py` | Likely preserved — `backend/intelligence/research_daemon.py` still exists | May import `backend.core.event_bus` — needs verification |
| `test_kali_connection_mgr.py` | Partially preserved — `backend/tools/backends/kali_ssh.py` still exists | Imports `backend.core.terminal_broadcaster` — problematic |
| `test_kali_ssh_timeouts.py` | Check — kali_ssh backend still exists | May or may not import core/ |
| `test_tor_socks5.py` | Check — tor_socks5 backend still exists | Likely clean |

**Tests that clearly test dead code (delete with the dead directories):**

| Test File | Reason |
|-----------|--------|
| `test_base_agent_resilience.py` | Tests `backend.core.base_agent.BaseAgent` (old, full implementation) |
| `test_exploit_agent_fallback.py` | Tests `backend.agents.exploit_agent.ExploitAgent` (old) |
| `test_recon_agent_loop.py` | Tests `backend.agents.recon_agent.ReconAgent` (old) and `backend.core.omx.OmX` |
| `test_scope_discovery_target_type.py` | Tests `backend.agents.scope_discovery_agent.ScopeDiscoveryAgent` (old) |
| `test_intel_agent_enrich.py` | Tests `backend.agents.intel_agent.IntelAgent` (old) |
| `test_llm_json_hardening.py` | Tests `backend.agents.scan_agent._extract_json_from_llm_response` (old) |
| `test_pentest_e2e.py` | Tests OmX + OmO + old agents full E2E flow |
| `test_omx_enrichment.py` | Tests `backend.core.omx.OmX` (old) |
| `test_omx_two_phase_exploit.py` | Tests `backend.core.omx.OmX` (old) |
| `test_permission_pipeline.py` | Tests `backend.core.permission.PermissionPipeline` (old) |
| `test_safety_regression.py` | Tests `backend.core.scope_enforcer.ScopeEnforcer` (old) |
| `test_verification_policy.py` | Tests `backend.core.credential_vault.CredentialVault` (old) and `backend.core.models` |
| `test_tool_fallback_resolver.py` | Tests `backend.core.tool_fallback.ToolFallbackResolver` (old) |
| `test_event_bus.py` | Tests `backend.core.event_bus` (old) |
| `test_terminal_broadcaster.py` | Tests `backend.core.terminal_broadcaster` and `backend.main` (old) |
| `test_report_formats.py` | Tests `backend.main._resolve_findings` (old) |
| `test_verification_loop_classify.py` | Tests `backend.core.models.FindingClassification` (old) |
| `test_session_merge.py` | Tests `backend.core.session.Session` (old) |

---

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Model ID validation | Custom version checker | Anthropic docs / known working ID | No Anthropic SDK method to enumerate valid model IDs at runtime — just use the correct string |
| Test migration tooling | Import rewrite script | Direct manual edits per file | Only 70 import lines across 18 files — automation overhead exceeds manual effort |
| Compatibility shim for old test paths | `sys.modules` aliasing | Delete tests that test dead code | Shims hide the problem; the tests are not worth preserving |

---

## Common Pitfalls

### Pitfall 1: Deleting directories before verifying pytest passes

**What goes wrong:** Deleting `backend/core/` and `backend/agents/` before all relevant tests are either migrated or deleted will cause a cascade of ImportError failures that obscure whether the remaining tests are actually correct.

**Why it happens:** `pyproject.toml` runs `backend/tests/` by default. If any file there still imports from deleted paths, pytest collection itself fails.

**How to avoid:** Complete all test file decisions (migrate or delete), run pytest and verify zero collection errors, THEN delete the directories.

**Warning signs:** `ModuleNotFoundError: No module named 'backend.core'` in pytest output means deletion happened prematurely.

### Pitfall 2: Treating all `backend/tests/` tests as migrateable

**What goes wrong:** Attempting to rewrite imports like `from backend.core.models import AgentTask` to something in `backend/agent/` when no equivalent exists, creating broken stubs.

**Why it happens:** The new `backend/agent/` system is a simpler orchestration layer, not a full reimplementation of the 6-layer architecture. Many types in `backend/core/models.py` do not exist anywhere in the new system.

**How to avoid:** For each test file, verify the imported symbol actually exists in the target module before attempting migration. If it doesn't exist, the test tests dead code and should be deleted.

**Warning signs:** Import succeeds but test fails with `AttributeError` — indicates symbol was found in wrong module.

### Pitfall 3: Assuming `backend/app.py` and `backend/main.py` are independent

**What goes wrong:** Leaving `backend/main.py` in place while deleting `backend/core/` will cause import errors if anything still references `backend/main.py`.

**Why it happens:** `backend/main.py` imports from `backend.core.*` at module level. If `backend/core/` is deleted first, `backend/main.py` immediately becomes broken even if nothing calls it.

**How to avoid:** Delete `backend/main.py` in the same step as (or before) deleting `backend/core/`. They are one atomic removal.

**Warning signs:** `ImportError` from `backend.main` during pytest collection even after updating test imports.

### Pitfall 4: Wrong model ID format

**What goes wrong:** Using a plausible-looking but incorrect model ID, causing silent Ollama fallback.

**Why it happens:** The `_claude_complete` method catches ALL exceptions and falls back to Ollama with only a `logger.error` — no exception is raised to the caller. A 404/invalid-model error is silently swallowed.

**How to avoid:** After setting `claude_model = "claude-sonnet-4-6"`, make a direct API call and check logs for absence of `"Claude error"` fallback messages.

**Warning signs:** Log line `Claude error: ..., falling back to Ollama` during normal operation means the model ID is still wrong.

### Pitfall 5: pytest testpaths mismatch

**What goes wrong:** New tests under `tests/` (the correct new-system test suite) are not run by pytest because `pyproject.toml` specifies `testpaths = ["backend/tests"]`.

**Why it happens:** The `pyproject.toml` config was set when `backend/tests/` was the only suite. The newer `tests/` directory was added later.

**How to avoid:** After completing CLEAN-01, update `pyproject.toml` `testpaths` to include both suites, or decide which is canonical.

**Current state:** `pyproject.toml` line 8: `testpaths = ["backend/tests"]` — the `tests/` directory (33 new tests) is NOT in the default run.

---

## Code Examples

### CLEAN-02: The exact fix

```python
# File: backend/config.py — change line 8

# BEFORE (wrong — model does not exist in Anthropic API):
claude_model: str = "claude-opus-4-7"

# AFTER (correct — this is the current working model):
claude_model: str = "claude-sonnet-4-6"
```

### Verifying Claude is being used (not Ollama fallback)

After the fix, the LLM router should log NO fallback events. The fallback only fires on this code path:

```python
# backend/agent/llm_router.py lines 53-55
except Exception as e:
    logger.error(f"Claude error: {e}, falling back to Ollama")
    return await self._ollama_complete(messages)
```

Verification: search logs for `"Claude error"` — if absent during normal operation, Claude is being used correctly.

### How the model ID flows through the system

```python
# backend/config.py
class Settings(BaseSettings):
    claude_model: str = "claude-sonnet-4-6"   # after fix

# backend/agent/llm_router.py
class LLMRouter:
    async def _claude_complete(self, messages, system):
        kwargs = dict(
            model=config.settings.claude_model,   # reads at call time
            ...
        )
        response = await self.claude.messages.create(**kwargs)
```

The value is read from `config.settings` at call time (not cached at init), so changing `config.py` takes effect immediately without restart in development.

### pyproject.toml testpaths decision

```toml
# Current (only runs backend/tests/ — old suite):
testpaths = ["backend/tests"]

# After Phase 1 (both suites):
testpaths = ["backend/tests", "tests"]
# OR, if all backend/tests are deleted:
testpaths = ["tests"]
```

---

## Environment Availability

Step 2.6: SKIPPED — Phase 1 is purely Python file edits and deletions. No external services, CLIs, databases, or runtimes beyond the Python interpreter and pytest are required.

---

## Validation Architecture

### Test Framework

| Property | Value |
|----------|-------|
| Framework | pytest 8.3.3 + pytest-asyncio 0.24.0 |
| Config file | `pyproject.toml` (exists) |
| Quick run command | `pytest tests/ -v --tb=short` |
| Full suite command | `pytest backend/tests/ tests/ -v --tb=short` |

### Phase Requirements → Test Map

| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| CLEAN-01 | No imports from `backend.core` or `backend.agents` anywhere in `backend/tests/` | lint/import check | `python -c "import backend.agent; import backend.session"` then `pytest tests/ -v` | ✅ `tests/` suite exists |
| CLEAN-01 | `backend/main.py`, `backend/core/`, `backend/agents/` are absent | filesystem check | `python -c "import os; assert not os.path.exists('backend/core')"` | N/A |
| CLEAN-02 | `config.settings.claude_model == "claude-sonnet-4-6"` | unit | `pytest tests/agent/test_llm_router.py -v` | ✅ exists |
| CLEAN-02 | No "Claude error / falling back" in logs during normal operation | integration (manual log check) | Run backend, send one message, grep logs | manual-only |

### Sampling Rate

- Per task commit: `pytest tests/ -v --tb=short`
- Per wave merge: `pytest backend/tests/ tests/ -v --tb=short` (after migration)
- Phase gate: Full suite green before `/gsd:verify-work`

### Wave 0 Gaps

None — existing test infrastructure covers all phase requirements. No new test files need to be created. The `tests/agent/test_llm_router.py` already exercises the LLMRouter. The CLEAN-01 verification is structural (directory absence + import success) rather than requiring new test code.

---

## Open Questions

1. **Preserve or delete `test_kali_connection_mgr.py` and `test_kali_ssh_timeouts.py`?**
   - What we know: `backend/tools/backends/kali_ssh.py` still exists in the new system. These tests are for that module.
   - What's unclear: These tests import `backend.core.terminal_broadcaster` (2 import lines). `TerminalBroadcaster` does not exist in the new system.
   - Recommendation: Read the files during plan execution. If `TerminalBroadcaster` usage can be mocked out or removed from the test without losing test value, migrate. Otherwise delete.

2. **Should `pyproject.toml` testpaths include `tests/` after cleanup?**
   - What we know: `tests/` (33 tests for new system) is not run by default. `backend/tests/` (old suite) is run by default.
   - What's unclear: The intended final state — should both suites run, or only the new one?
   - Recommendation: After CLEAN-01, set `testpaths = ["tests"]` and discard `backend/tests/` entirely (the old tests test dead code). This satisfies success criterion #2 cleanly.

3. **Do any production modules (not in `core/` or `agents/`) import from `backend.core.*`?**
   - What we know: `backend/app.py` imports from `backend.core.*` extensively (it IS the old entry point). `backend/agent/llm_router.py` imports from `backend` (i.e., `config.py`). `backend/agent/` modules do not import from `backend.core.*`.
   - What's unclear: Do `backend/intelligence/`, `backend/memory/`, `backend/tools/`, `backend/verification/` modules import from `backend.core.*`?
   - Recommendation: Run a grep for `from backend.core` across all non-test Python files before deleting to catch any hidden dependencies.

---

## Sources

### Primary (HIGH confidence)
- Direct file inspection of `backend/config.py` — confirmed wrong model value on line 8
- Direct file inspection of `backend/agent/llm_router.py` — confirmed reads `config.settings.claude_model` at call time
- Direct file inspection of `backend/app.py` and `backend/main.py` — confirmed two separate entry points
- Direct grep of `backend/tests/` — 70 occurrences across 18 files importing from `backend.core.*` / `backend.agents.*`
- `backend/Dockerfile` — confirmed `CMD ["uvicorn", "backend.app:app", ...]` (new system is canonical)
- `pyproject.toml` — confirmed `testpaths = ["backend/tests"]` only

### Secondary (MEDIUM confidence)
- `.planning/codebase/STRUCTURE.md` — corroborates old/new system split analysis
- `.planning/codebase/TESTING.md` — corroborates test import split and test counts

### Tertiary (LOW confidence)
- Anthropic model ID `"claude-sonnet-4-6"` is consistent with known model naming conventions and the `additional_context` provided. Verified against project's own hardcoded reference in `backend/main.py` line 229: `model=os.environ.get("CLAUDE_MODEL", "claude-sonnet-4-6")`.

---

## Project Constraints (from CLAUDE.md)

| Directive | Impact on Phase 1 |
|-----------|-------------------|
| No breaking changes to BaseAgent loop | `backend/agent/sub_agents/base.py` (new BaseAgent) must not be modified. CLEAN-01 deletes `backend/core/base_agent.py` (old), not the new one. |
| Python/FastAPI backend — no stack changes | No new frameworks or libraries. Cleanup only. |
| No stack changes (React frontend) | Phase 1 has no frontend work. |
| Use GSD workflow for file changes | All edits must go through `/gsd:execute-phase` tasks, not ad-hoc edits. |

---

## Metadata

**Confidence breakdown:**
- CLEAN-02 (model ID fix): HIGH — single line, confirmed by direct file inspection, corroborated by `backend/main.py` default value
- CLEAN-01 (test migration): HIGH for scope identification — 18 files, 70 import lines documented. MEDIUM for per-file migration decisions — 3 files (`test_kali_*.py`, `test_client_profile.py`, `test_smart_memory.py`, `test_source_adapters.py`) need targeted inspection during execution
- Architecture understanding: HIGH — confirmed by `.planning/codebase/STRUCTURE.md`, Dockerfile, and `pyproject.toml`

**Research date:** 2026-05-12
**Valid until:** 2026-06-12 (stable codebase, no moving parts)
