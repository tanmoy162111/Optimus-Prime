---
phase: 02-security-hardening
plan: 02
subsystem: execution (SSH/Kali command scoping)
tags: [security, ssh, paramiko, workdir-isolation, sub-agents]
dependency-graph:
  requires: []
  provides:
    - "ShellManager.execute() workdir-scoped command prefixing (SEC-02)"
    - "SSHClient/ShellManager engagement_id threading"
  affects:
    - "backend/agent/sub_agents/*.py (7 sub-agents)"
tech-stack:
  added: []
  patterns:
    - "kwargs.get('engagement_id', 'default') at sub-agent execute() construction sites"
    - "mkdir -p '{workdir}' && cd '{workdir}' && {command} prefix applied on every ShellManager.execute() call"
key-files:
  created:
    - tests/execution/__init__.py
    - tests/execution/test_shell_manager_scoping.py
  modified:
    - backend/execution/ssh_client.py
    - backend/execution/shell_manager.py
    - backend/agent/sub_agents/recon_agent.py
    - backend/agent/sub_agents/scan_agent.py
    - backend/agent/sub_agents/cloud_agent.py
    - backend/agent/sub_agents/data_sec_agent.py
    - backend/agent/sub_agents/exploit_agent.py
    - backend/agent/sub_agents/iam_agent.py
    - backend/agent/sub_agents/endpoint_agent.py
decisions:
  - "SSHClient stores engagement_id but does not apply scoping itself — the cd/mkdir prefix lives one layer up in ShellManager.execute(), per D-03, avoiding duplicated scoping logic"
  - "create_session()/send_to_session() left unchanged (still call self.ssh.execute directly, bypassing the scoped execute()) but documented with a comment as intentionally unscoped dead-code (T-02-07) since they have zero live callers today"
  - "engagement_id threaded into sub-agents via the existing kwargs.get(...) idiom on execute(), not via constructor injection, since no live orchestrator wiring calls sub_agent.execute() yet (RESEARCH.md's 'important caveat')"
metrics:
  duration: ~25min
  completed: 2026-08-29
---

# Phase 2 Plan 2: Per-Engagement Kali Workdir Scoping (SEC-02) Summary

Centralized `/engagements/{engagement_id}/` command scoping in `ShellManager.execute()` via a `mkdir -p && cd &&` prefix, threaded `engagement_id` from each of the 7 sub-agents' `execute(**kwargs)` into `SSHClient`/`ShellManager` construction, and rewrote the 4 sub-agent commands that wrote to absolute `/tmp/...` paths (which the `cd` prefix cannot scope) to use relative filenames.

## What Was Built

1. **`tests/execution/test_shell_manager_scoping.py`** (new) — mocks `SSHClient.execute` and asserts the exact scoped command string `mkdir -p "/engagements/{id}" && cd "/engagements/{id}" && {command}` for two distinct `engagement_id`s, proving per-engagement isolation of the prefix.

2. **`backend/execution/ssh_client.py`** — `SSHClient.__init__` now accepts an optional `engagement_id: str | None = None`, stored as `self.engagement_id`. `connect()`/`execute()` bodies are unchanged; `SSHClient` remains a dumb command-runner.

3. **`backend/execution/shell_manager.py`** — `ShellManager.__init__` now requires `engagement_id: str` and computes `self._workdir = f"/engagements/{engagement_id}"`. `execute()` prefixes every command with `mkdir -p "{workdir}" && cd "{workdir}" && {command}` before forwarding to `self.ssh.execute()`. `create_session()`/`send_to_session()` are left unchanged (they still call `self.ssh.execute()` directly, bypassing scoping) and now carry a code comment documenting them as intentionally unscoped dead-code — no live callers today, but a future caller must not assume isolation holds for these two methods.

4. **7 sub-agents** (`recon_agent.py`, `scan_agent.py`, `cloud_agent.py`, `data_sec_agent.py`, `exploit_agent.py`, `iam_agent.py`, `endpoint_agent.py`) — each now reads `engagement_id = kwargs.get("engagement_id", "default")` at the inline `SSHClient()`/`ShellManager(ssh)` construction site inside `execute()`, and constructs `SSHClient(engagement_id=engagement_id)` / `ShellManager(ssh, engagement_id=engagement_id)`.

5. **4 absolute-path fixes** (RESEARCH.md Pitfall 1 — a correction to CONTEXT.md's D-04, which assumed `/tmp/` paths were already scoping-safe):
   - `recon_agent.py`: `sublist3r -d {target} -o /tmp/recon.txt` → `-o recon.txt`
   - `scan_agent.py`: `nmap -sV -sC -oA /tmp/scan {target}` → `-oA scan`
   - `cloud_agent.py`: `scoutsuite --provider {provider} --report-dir /tmp/cloud` → `--report-dir cloud`
   - `data_sec_agent.py`: `testssl.sh --jsonfile /tmp/tls.json {host}` → `--jsonfile tls.json`

   These relative filenames now resolve inside `/engagements/{engagement_id}/` once the centralized `cd` prefix lands the shell there.

## Deviations from Plan

None — plan executed exactly as written. All threat-model mitigations (T-02-04, T-02-05, T-02-06, T-02-07) applied as specified: code comments added at each sub-agent construction site flagging the pre-existing unescaped f-string command interpolation (T-02-06, out of scope for this phase), and a comment above `create_session()` documenting the unscoped-dead-code status (T-02-07).

## Environment / Infrastructure Notes (not plan deviations, flagged for orchestrator)

1. **Stale worktree base.** This worktree's branch (`worktree-agent-ad122638c3701e585`) was created from a commit (`7f9efad`) that predates several `main` commits, including the Phase 1 test-directory migration (`bd8ef4c`, which moved `pyproject.toml`'s `testpaths` from `backend/tests` to `tests`) and the deletion of the old `backend/tests/` dead-code suite. As a result, this worktree's `pyproject.toml` still points `testpaths` at `backend/tests`, and running bare `pytest` collects the stale `backend/tests/` directory (which errors on import in `test_smart_memory.py`, an unrelated pre-existing issue). Verified via `git diff --stat 7f9efad 73c9ecf -- backend/execution/ backend/agent/sub_agents/` that **none of this plan's target files differ** between the stale base and `main`'s current tip — so this plan's edits are unaffected and safe to merge. Test verification for this plan was performed by explicitly targeting `pytest tests/` (the canonical new-style suite), which collected 35 tests, all passing, including both new SEC-02 scoping tests. Did not modify `pyproject.toml` (out of this plan's file scope, and a shared file that could conflict with the other 3 parallel worktree agents in this wave). The orchestrator should verify all 4 wave-1 worktree branches share this same stale-base condition and confirm the eventual merge to `main` resolves cleanly (expected, since `main` already has the correct `pyproject.toml`/`backend/tests` state and none of this plan's branches touch those paths).
2. **No local Python 3.12 environment.** System Python is 3.14; the pinned `backend/requirements.txt` (`pydantic-core` via `pyo3`) fails to build from source under 3.14. Verification was performed using an ephemeral scratchpad venv with unpinned `fastapi`/`pydantic`/`pytest`/`pytest-asyncio`/`paramiko` (matching RESEARCH.md's noted fallback: run tests in a project-managed venv since this host has no pre-existing one). This venv was created outside the repo/worktree and is not part of any commit.

## Verification

- `pytest tests/execution/test_shell_manager_scoping.py -x --tb=short` — 2 passed (RED confirmed before Task 2, GREEN confirmed after)
- `pytest tests/` (canonical suite, explicit path) — 35 passed, 0 failed, no regressions
- `grep -rc "/tmp/" backend/agent/sub_agents/*.py` — every file at 0
- `grep -rl "engagement_id=engagement_id" backend/agent/sub_agents/` — all 7 files match

## Self-Check

- FOUND: tests/execution/__init__.py
- FOUND: tests/execution/test_shell_manager_scoping.py
- FOUND: backend/execution/ssh_client.py (engagement_id param present)
- FOUND: backend/execution/shell_manager.py (workdir scoping present)
- FOUND: backend/agent/sub_agents/recon_agent.py (recon.txt, engagement_id threading)
- FOUND: backend/agent/sub_agents/scan_agent.py (oA scan, engagement_id threading)
- FOUND: backend/agent/sub_agents/cloud_agent.py (report-dir cloud, engagement_id threading)
- FOUND: backend/agent/sub_agents/data_sec_agent.py (jsonfile tls.json, engagement_id threading)
- FOUND: backend/agent/sub_agents/exploit_agent.py (engagement_id threading)
- FOUND: backend/agent/sub_agents/iam_agent.py (engagement_id threading)
- FOUND: backend/agent/sub_agents/endpoint_agent.py (engagement_id threading)
- Commit ec0dc52: FOUND in git log
- Commit 31e1314: FOUND in git log
- Commit 92a8483: FOUND in git log

## Self-Check: PASSED
