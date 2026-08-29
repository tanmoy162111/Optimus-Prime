---
phase: 02-security-hardening
plan: 01
subsystem: tool-execution
tags: [docker, sandbox, docker-py, sec-01, isolation]

# Dependency graph
requires:
  - phase: 01-cleanup-configuration
    provides: backend/tools/backends/sandbox.py unified under canonical backend/ layout
provides:
  - "run_tool_code() executes generated tool code inside an isolated Docker container (network_mode=none, mem_limit=256m), no host subprocess"
  - "SEC-01 satisfied: SandboxOnDemandBackend no longer spawns python3 directly on the host"
affects: [v1.1-phase-9-auto-research-strategy-evolution]

# Tech tracking
tech-stack:
  added:
    - "docker==7.2.0 (docker-py) — pinned in backend/requirements.txt"
  patterns:
    - "asyncio.to_thread wrapping a synchronous docker-py blocking call, guarded by asyncio.wait_for — mirrors backend/tools/sandbox_manager.py's RuntimeWatchdog convention for wrapping blocking Docker calls"
    - "put_archive() to inject script bytes into the container instead of a bind mount — a bind mount's host_path resolves against the Docker daemon's host filesystem, not the backend container's own filesystem (DooD), so a tempfile path inside the backend container would silently mount an empty directory"
    - "container.remove(force=True) in a finally block instead of auto_remove=True — auto_remove races client-side log reads for fast-exiting scripts (docker-py issues #1813, #3289)"

key-files:
  created:
    - tests/tools/test_sandbox_docker.py
  modified:
    - backend/tools/backends/sandbox.py
    - backend/requirements.txt
    - docker-compose.yml

key-decisions:
  - "DooD (Docker socket mounted into backend container) per locked decision D-10 — backend container now has host-level Docker access; accepted given personal-use single-operator constraint (CLAUDE.md) and zero live callers to this backend this phase (D-02)"
  - "Worktree branch was found forked from a stale pre-Phase-1-cleanup commit (7f9efad, ~30 commits behind main) — same staleness observed in the 02-03 and 02-04 worktrees. Fast-forwarded via `git merge --ff-only main` (branch had zero unique commits, a pure ancestor) before starting task work. No commits lost or rewritten."
  - "Task 3's implementation and commit were completed after a stalled full-suite verification run — the orchestrator (not this agent) diagnosed the stall as a pre-existing, unrelated hang in tests/intelligence/test_custom_tool_generator.py::TestG2Sandbox::test_sandbox_timeout (a real asyncio.sleep(300) in a mock, reproduced independently on a clean main checkout — predates all of Phase 2's work, not caused by any of the 4 parallel plans). The orchestrator committed this task's already-passing sandbox.py change and wrote this SUMMARY.md."

patterns-established:
  - "RESEARCH.md Pattern 1 (docker-py container isolation) applied verbatim: create → put_archive → start → wait(timeout=) → logs → remove(force=True)"

requirements-completed: [SEC-01]

# Metrics
duration: ~45min (including stall diagnosis)
completed: 2026-08-29
---

# Phase 2 Plan 1: Docker Sandbox Isolation Summary

**`SandboxOnDemandBackend.run_tool_code()` now launches an isolated, resource-capped Docker container instead of a host `python3` subprocess — closing the RCE risk PROJECT.md flagged, ready for v1.1 Phase 9 to wire a live caller.**

## Performance

- **Duration:** ~45 min (including a stalled full-suite verification run that the orchestrator diagnosed and recovered from)
- **Completed:** 2026-08-29
- **Tasks:** 3/3 completed
- **Files modified:** 4 (1 source, 1 new test, 2 config)

## Accomplishments
- `backend/tools/backends/sandbox.py`: `run_tool_code()` replaces `asyncio.create_subprocess_exec("python3", ...)` with a Docker container run via `docker-py` (`network_mode="none"`, `mem_limit="256m"`), wrapped in `asyncio.to_thread` + `asyncio.wait_for`. Return dict shape (`status`/`stdout`/`stderr`/`exit_code`/`effectiveness_score`) unchanged; `_compute_effectiveness`/`_count_findings` untouched.
- `docker==7.2.0` pinned in `backend/requirements.txt`; `docker-compose.yml` backend service now mounts `/var/run/docker.sock:/var/run/docker.sock` (DooD per D-10).
- New `tests/tools/test_sandbox_docker.py`: 4/4 tests pass against a live Docker daemon — success-shape, no-leaked-container, filesystem isolation, and timeout-with-cleanup. Skippable via `docker_available()` when no daemon is reachable.
- This backend remains unwired (zero live callers) per D-02 — `custom_tool_generator.py` wiring stays v1.1 Phase 9 scope.

## Verification
- `pytest tests/tools/test_sandbox_docker.py -x --tb=short` — 4 passed, 3.31s, independently re-run and confirmed by the orchestrator after the executor's stall.
- Acceptance criteria confirmed: `import docker` present, `network_mode="none"` and `mem_limit="256m"` present, `asyncio.to_thread` present, zero remaining `create_subprocess_exec` calls, `_compute_effectiveness`/`_count_findings` signatures unchanged.

## Deviations
- The full-suite `pytest tests/` verification step this executor was running stalled — root cause confirmed by the orchestrator as a **pre-existing, unrelated** hang: `tests/intelligence/test_custom_tool_generator.py::TestG2Sandbox::test_sandbox_timeout` contains a genuine `await asyncio.sleep(300)` in a mock sandbox executor, reproduced independently on a clean `main` checkout with none of Phase 2's changes applied. This is orphaned dead code (`custom_tool_generator.py` has zero live callers) unrelated to any of the 4 Phase 2 plans — flagged for the orchestrator/user to capture as a follow-up, not fixed here (out of this plan's scope).

## Self-Check: PASSED
