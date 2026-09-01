---
phase: 03-orchestration-upgrade
plan: 02
subsystem: agent (LLM routing)
tags: [llm-router, multi-provider, deepseek, ollama, qwen, tdd]
requires:
  - "config.settings.qwen_model (03-01)"
  - "config.settings.deepseek_api_key / deepseek_model / deepseek_base_url (03-01)"
provides:
  - "LLMRouter.complete(mode='compaction') -> Ollama/Qwen routing"
  - "LLMRouter.complete(mode='deepseek') -> optional key-gated DeepSeek provider"
affects:
  - "backend/agent/orchestrator.py (future plans may pass mode='compaction'/'deepseek' through LLMRouter)"
  - "backend/agent/conversation_summariser.py (future consumer of mode='compaction')"
tech-stack:
  added: []
  patterns:
    - "Task-based mode dispatch in LLMRouter.complete() via explicit elif branches per mode, falling through to the existing unconditional Ollama/mistral path for anything unrecognized (unchanged default)"
    - "Optional-provider degrade idiom: check the gating config field first, log a WARNING, and route to the existing _ollama_complete() rather than raising or half-failing (mirrors _claude_complete()'s except-fallback shape)"
    - "httpx.AsyncClient context-managed POST for OpenAI-compatible chat-completions call, no new SDK dependency (httpx already pinned)"
key-files:
  created: []
  modified:
    - backend/agent/llm_router.py
    - tests/agent/test_llm_router.py
decisions:
  - "DeepSeek call shape assumed OpenAI-compatible chat-completions POST to {deepseek_base_url}/chat/completions per RESEARCH.md Assumption A2 — not independently verified against DeepSeek's live API in this plan (A2 flagged as lower-risk since D-04 makes DeepSeek optional, not required to be exercised by default)"
  - "_compaction_complete() and _deepseek_complete() both reuse self.ollama for their fallback path — no second OllamaClient constructed, verified via a source-grep regression test"
metrics:
  duration: 45min
  completed: 2026-09-01
---

# Phase 3 Plan 2: LLMRouter Multi-Provider Task-Based Routing Summary

Extended `LLMRouter.complete()` with two new task-routed modes — `compaction` (always Ollama/Qwen) and `deepseek` (optional, key-gated) — while leaving the existing `orchestration` (Claude) branch and the unconditional Ollama-fallback path byte-identical, per ORCH-02/D-04 (multi-provider by addition, not a Claude replacement).

## What Was Built

- `backend/agent/llm_router.py`:
  - `complete()` gained two new `elif` branches: `mode == "compaction"` → `_compaction_complete()`, `mode == "deepseek"` → `_deepseek_complete()`. The `mode == "orchestration"` Claude branch and the final unconditional `_ollama_complete()` fallback (for any other/unknown mode) are unchanged.
  - `_compaction_complete()`: reuses `self.ollama` (no second `OllamaClient` instantiated), calls `self.ollama.generate(model=config.settings.qwen_model, prompt=...)` using the same prompt-join shape as the existing `_ollama_complete()`.
  - `_deepseek_complete()`: checks `config.settings.deepseek_api_key` first — empty key logs a `WARNING` and degrades to `_ollama_complete()` (absence never breaks orchestration/compaction, D-04). A present key issues an OpenAI-compatible chat-completions `POST` via `httpx.AsyncClient` to `{config.settings.deepseek_base_url}/chat/completions` with `config.settings.deepseek_model`, wrapped in a `try/except` that degrades to `_ollama_complete()` on any HTTP/parsing error (mirrors `_claude_complete()`'s except-fallback shape).
  - Added top-level `import httpx` (already pinned in `backend/requirements.txt` — no new dependency).
- `tests/agent/test_llm_router.py`: extended from 4 to 11 tests covering compaction routing, orchestration regression, unknown-mode unchanged-behavior, single-OllamaClient-construction regression, DeepSeek key-absent degrade, DeepSeek key-present HTTP call, and DeepSeek-branch-doesn't-affect-orchestration/compaction.

## Tasks Completed

TDD RED/GREEN cycle followed for both tasks (plan frontmatter `tdd="true"` on both):

| Task | Name | RED Commit | GREEN Commit | Files |
|------|------|------------|---------------|-------|
| 1 | Add mode='compaction' → Ollama/Qwen routing | 13db809 | 4692fb3 | backend/agent/llm_router.py, tests/agent/test_llm_router.py |
| 2 | Optional DeepSeek provider route, gated on API-key presence | 8b300a2 | 15c4b6e | backend/agent/llm_router.py, tests/agent/test_llm_router.py |

RED-phase verification for Task 1 confirmed `test_compaction_mode_routes_to_ollama` failed against `qwen_model` (asserted `qwen2.5:7b`, got `mistral:7b` — mode fell through to the existing unconditional Ollama path) while the other 3 new guard tests already passed against pre-existing behavior (expected — see Deviations). RED-phase verification for Task 2 confirmed `test_deepseek_mode_with_api_key_calls_configured_endpoint` failed (`post` never called — no `deepseek` branch existed yet) while the key-absent-degrade test already passed trivially against the pre-existing fallthrough (expected).

## Verification

Ran inside a `python:3.12-slim`-based container (host Python is 3.14; pinned `backend/requirements.txt` deps do not build there). Built a one-off reusable image (`optimus-py312-deps`, tagged locally, removed at end of this plan's execution) after two prior transient `--rm` container test runs produced empty/truncated output under a 300s background-command watchdog — a fresh dependency-install-then-commit image avoided repeating the ~2-3 minute `pip install -r backend/requirements.txt` on every subsequent test invocation:

- `pytest tests/agent/test_llm_router.py -x --tb=short` — 11 passed (final state, after both GREEN commits).
- `python -c "from backend.agent.llm_router import LLMRouter"` — imports clean.
- Full suite `pytest tests/ -q` — 195 passed, 6 skipped, 15 xfailed, 1 failed (pre-existing, out of scope — see Deferred Issues below; unchanged by this plan's 2-file diff).
- `grep -c "OllamaClient(" backend/agent/llm_router.py` equivalent (source-based regression test `test_only_one_ollama_client_constructed`) confirms exactly one construction site.
- Confirmed no new package in `backend/requirements.txt`: `httpx==0.27.2` was already pinned (used previously in `backend/intelligence/source_adapters.py`).

## Deviations from Plan

None — plan executed exactly as written. Both tasks' `<action>` blocks were implemented verbatim; no Rule 1-4 fixes were needed in `backend/agent/llm_router.py` or its test file.

## Deferred Issues

Full-suite verification (broader than this plan's own `<verification>` block) surfaced one pre-existing, out-of-scope failure, already logged to `.planning/phases/03-orchestration-upgrade/deferred-items.md` by Plans 03-01 and 03-07 (not re-fixed here — unrelated to `backend/agent/llm_router.py`):

- `tests/api/test_auth.py::test_chat_without_token_returns_401` — expects `401` when no `Authorization` header is sent, but FastAPI's `HTTPBearer` returns `403` for a missing header. Predates this plan; `backend/auth.py` was not touched by either task here.

## Known Stubs

None. Both new provider routes (`compaction`, `deepseek`) are fully wired against their real dependencies (`self.ollama.generate()`, `httpx.AsyncClient` POST) — no hardcoded/placeholder return values. The DeepSeek key-absent path is an intentional, spec-required degrade (not a stub): D-04 explicitly requires DeepSeek's absence to never break orchestration/compaction, and the degrade routes through the same real `_ollama_complete()` path every other fallback in this module already uses.

## Threat Flags

| Flag | File | Description |
|------|------|--------------|
| threat_flag: outbound-egress | backend/agent/llm_router.py (`_deepseek_complete`) | New outbound HTTPS call to `config.settings.deepseek_base_url` when `deepseek_api_key` is configured — already covered by the plan's own threat model (T-03-08b, disposition `accept`: opt-in, no egress when key is empty). No new undocumented surface; flagged here only for verifier cross-reference since this is the first plan in the phase to actually implement the call site RESEARCH.md's Assumption A2 anticipated.

## Self-Check: PASSED

- FOUND: backend/agent/llm_router.py (elif mode == "compaction" / elif mode == "deepseek" branches, _compaction_complete, _deepseek_complete, import httpx all present)
- FOUND: tests/agent/test_llm_router.py (11 test functions, including test_compaction_mode_routes_to_ollama, test_deepseek_mode_with_api_key_calls_configured_endpoint)
- FOUND commit 13db809 (git log --oneline --all)
- FOUND commit 4692fb3 (git log --oneline --all)
- FOUND commit 8b300a2 (git log --oneline --all)
- FOUND commit 15c4b6e (git log --oneline --all)

All items verified directly against the worktree filesystem and `git log --oneline --all` — no missing items.
