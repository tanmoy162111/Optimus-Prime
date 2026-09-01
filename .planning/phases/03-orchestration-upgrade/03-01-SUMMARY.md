---
phase: 03-orchestration-upgrade
plan: 01
subsystem: config + memory
tags: [config, settings, smart-memory, multi-provider, prerequisite-fix]
requires: []
provides:
  - "config.settings.summariser_threshold"
  - "config.settings.qwen_model"
  - "config.settings.deepseek_api_key"
  - "config.settings.deepseek_model"
  - "config.settings.deepseek_base_url"
  - "SmartMemory.get_best_tools()"
affects:
  - "backend/agent/conversation_summariser.py (unblocked — no longer raises AttributeError)"
  - "backend/intelligence/strategy_evolution.py (StrategyEvolutionEngine._enrich_node() call now safe)"
tech-stack:
  added: []
  patterns:
    - "Settings fields use plain `name: type = default` style, no Field() wrapper (matches existing config.py convention)"
    - "SmartMemory degrade idiom: return empty/partial result, never raise (matches existing search())"
key-files:
  created:
    - tests/agent/test_conversation_summariser.py
  modified:
    - backend/config.py
    - backend/memory/smart_memory.py
    - tests/memory/test_smart_memory.py
decisions:
  - "get_best_tools() returns [] (not NotImplementedError) per RESEARCH.md Assumption A3 and D-10 minimal-stub bar"
  - "qwen_model default 'qwen2.5:7b' is [ASSUMED] per RESEARCH.md Assumption A1 — operator must confirm real Ollama tag via .env"
metrics:
  duration: 25min
  completed: 2026-09-01
---

# Phase 3 Plan 1: Prerequisite Config & Memory Fixes Summary

Added five multi-provider/summariser Settings fields to config.py and a `get_best_tools()` no-op stub to SmartMemory, clearing the two pre-existing AttributeError defects (RESEARCH.md Pitfalls 1 and 2) that this phase's downstream LLMRouter/OmX/compaction work depends on.

## What Was Built

- `backend/config.py`: added `summariser_threshold: int = 60000`, `qwen_model: str = "qwen2.5:7b"`, `deepseek_api_key: str = ""`, `deepseek_model: str = "deepseek-chat"`, `deepseek_base_url: str = "https://api.deepseek.com"` — no existing fields touched.
- `backend/memory/smart_memory.py`: added `async def get_best_tools(self, target_type: str, top_k: int = 10) -> List[Dict[str, Any]]` returning `[]`, matching the existing `search()` "return what little I have, never raise" idiom.
- `tests/agent/test_conversation_summariser.py` (new): smoke test instantiating `ConversationSummariser()` and asserting `threshold == 60000`.
- `tests/memory/test_smart_memory.py`: added `TestSmartMemoryGetBestToolsStub` asserting `get_best_tools("web", top_k=10) == []` without raising.

## Tasks Completed

| Task | Name | Commit | Files |
|------|------|--------|-------|
| 1 | Add multi-provider + summariser Settings fields to config.py | 2075411 | backend/config.py |
| 2 | Add SmartMemory.get_best_tools() no-op stub | 5cbb4bf | backend/memory/smart_memory.py, tests/memory/test_smart_memory.py |
| 3 | ConversationSummariser instantiation smoke test | f45f184 | tests/agent/test_conversation_summariser.py |

## Verification

Ran inside a `python:3.12-slim` container (matching project's pinned `backend/requirements.txt`) since no local venv/interpreter matching the pinned dependency set was available in the executor environment:

- `python -c "from backend import config; ..."` — all five new fields confirmed present with correct defaults; `claude_model`/`mistral_model` unmodified.
- `pytest tests/agent/test_conversation_summariser.py tests/memory/test_smart_memory.py -x --tb=short` — 2 passed, 9 xfailed (pre-existing xfails unrelated to this plan, unchanged).
- Full suite `pytest tests/ -q` — 156 passed, 6 skipped, 15 xfailed, 1 failed (pre-existing, out of scope — see Deferred Issues below).

## Deviations from Plan

None — plan executed exactly as written. All three tasks matched their `<action>` blocks; no Rule 1-4 fixes were needed in the touched files.

## Deferred Issues

Full-suite verification (broader than this plan's own `<verification>` block) surfaced one pre-existing, out-of-scope failure, logged to `.planning/phases/03-orchestration-upgrade/deferred-items.md` per scope-boundary rules (not fixed — unrelated to `backend/config.py` / `backend/memory/smart_memory.py`):

- `tests/api/test_auth.py::test_chat_without_token_returns_401` — expects `401` when no `Authorization` header is sent, but FastAPI's `HTTPBearer` returns `403` for a missing header (401 only fires on an invalid/wrong token). Predates this plan; `backend/auth.py` and `backend/api/chat_routes.py` were not touched by any task here.

## Known Stubs

- `SmartMemory.get_best_tools()` is an intentional no-op stub (returns `[]`) — this is the plan's explicit deliverable (RESEARCH.md Assumption A3, D-10 minimal-stub bar), not a gap. Full implementation (tool-effectiveness tracking, `store_tool_effectiveness`) remains tracked under the pre-existing SmartMemory xfail backlog (see STATE.md Open TODOs, unchanged by this plan).

## Self-Check: PASSED

- FOUND: backend/config.py (summariser_threshold, qwen_model, deepseek_api_key, deepseek_model, deepseek_base_url all present)
- FOUND: backend/memory/smart_memory.py (get_best_tools present)
- FOUND: tests/agent/test_conversation_summariser.py
- FOUND: tests/memory/test_smart_memory.py (TestSmartMemoryGetBestToolsStub present)
- FOUND commit 2075411 (git log --oneline --all)
- FOUND commit 5cbb4bf (git log --oneline --all)
- FOUND commit f45f184 (git log --oneline --all)
