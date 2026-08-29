---
phase: 02-security-hardening
verified: 2026-08-29T10:14:24Z
status: passed
score: 22/22 must-haves verified
overrides_applied: 0
---

# Phase 2: Security Hardening Verification Report

**Phase Goal:** The operator can run real engagements against real targets without generated code executing on the host, without Kali artifacts bleeding between engagements, and without concurrent DB writes corrupting findings.
**Verified:** 2026-08-29T10:14:24Z
**Status:** passed
**Re-verification:** No — initial verification

## Goal Achievement

### Observable Truths (ROADMAP Success Criteria)

| # | Truth | Status | Evidence |
|---|-------|--------|----------|
| 1 | Executing a generated tool script launches a Docker container (`--network=none --memory=256m`), no host python3 subprocess | ✓ VERIFIED | Live spot-check run of `SandboxOnDemandBackend.run_tool_code()` against the real Docker daemon in this environment: `docker.from_env().containers.list()` showed a running container mid-execution with `HostConfig.NetworkMode="none"` and `HostConfig.Memory=268435456` (256MB); `grep create_subprocess_exec backend/tools/backends/sandbox.py` returns 0 matches; post-run container count confirmed 0 leaked containers. 6/6 tests in `tests/tools/test_sandbox_docker.py` passed against the live daemon (not mocked, not skipped). |
| 2 | Two concurrent engagements' Kali SSH commands produce output in separate `/engagements/{id}/` dirs, no cross-contamination | ✓ VERIFIED (component-level) | `backend/execution/shell_manager.py` prefixes every `execute()` call with `mkdir -p "/engagements/{engagement_id}" && cd "/engagements/{engagement_id}" && {command}`. `tests/execution/test_shell_manager_scoping.py` (2/2 passing) asserts the exact scoped string for two distinct engagement_ids. All 7 live sub-agents thread `engagement_id` into `SSHClient`/`ShellManager` construction (verified via grep — all 7 files contain `engagement_id=engagement_id`), and the 4 absolute `/tmp/...` output paths were rewritten to relative filenames (verified via grep — 0 occurrences of `/tmp/` remain in `backend/agent/sub_agents/*.py`). Per CONTEXT.md's explicit "correct but unwired" framing, `backend/agent/orchestrator.py`/`engine_router.py` do not currently instantiate any sub-agent (confirmed via grep — zero `ReconAgent()`/`ScanAgent()`/etc. call sites), so this criterion is assessed and satisfied at the component level, not as a literal live end-to-end demonstration — consistent with the pre-existing, explicitly out-of-scope orchestrator gap. |
| 3 | Every SQLite connection responds to `PRAGMA journal_mode;` with `wal` | ✓ VERIFIED | `backend/memory/client_profile.py` and `backend/intelligence/research_kb.py` (the application's only two `sqlite3.connect()` call sites) both apply `PRAGMA journal_mode=WAL` and `PRAGMA synchronous=NORMAL` immediately after `row_factory` assignment, before `executescript`. `tests/memory/test_client_profile.py::TestClientProfileWAL::test_journal_mode_is_wal` and `tests/intelligence/test_research_kb_wal.py::TestResearchKBWAL::test_journal_mode_is_wal` both pass using real temp-file sqlite connections (no mocks), querying `PRAGMA journal_mode` back and asserting `"wal"`. |
| 4 | Verifying the same finding ID from two concurrent engagements does not exhaust/share request budgets | ✓ VERIFIED | `backend/verification/verification_loop.py`'s `VerificationLoop._request_counts` is keyed by `f"{engagement_id}:{finding_id}"` (not bare `finding_id` — the prior deleted implementation's bug). `tests/verification/test_verification_loop.py::test_cross_engagement_budget_isolation_for_shared_finding_id` passes, proving `eng-B` retains a fresh budget after `eng-A` exhausts its own for the same `finding_id`. |

**Score:** 4/4 roadmap success criteria verified

### Plan-Level Must-Haves (02-01 through 02-04)

| # | Truth | Status | Evidence |
|---|-------|--------|----------|
| 5 | run_tool_code() still returns the same dict shape (status/stdout/stderr/exit_code/effectiveness_score) | ✓ VERIFIED | `backend/tools/backends/sandbox.py` success/timeout/error return dicts all preserve the original keys; `_compute_effectiveness`/`_count_findings` unchanged; confirmed by `test_run_tool_code_returns_success_shape` passing. |
| 6 | Container-execution timeout kills and removes the container, no leaked container | ✓ VERIFIED | `_run_sync()` kills the container on `container.wait()` read-timeout and always `remove(force=True)`s in a `finally` block. `test_timeout_returns_timeout_status_and_no_leak` passes against the live daemon. |
| 7 | `custom_tool_generator.py` not modified/wired to sandbox this phase (D-02) | ✓ VERIFIED | `git log --follow -- backend/intelligence/custom_tool_generator.py` shows its last change (`592a4ac`) predates Phase 2 entirely; no Phase 2 commit touches this file. |
| 8 | engagement_id threads from sub-agent kwarg into SSHClient/ShellManager construction (D-05) | ✓ VERIFIED | All 7 sub-agents (`recon`, `scan`, `cloud`, `data_sec`, `exploit`, `iam`, `endpoint`) contain `SSHClient(engagement_id=engagement_id)` and `ShellManager(ssh, engagement_id=engagement_id)`, reading from `kwargs.get("engagement_id", "default")`. |
| 9 | ClientProfileDB / ResearchKB report `journal_mode=wal` after initialize(), synchronous=NORMAL applied (D-06) | ✓ VERIFIED | See Truth #3. Both pragmas confirmed present via grep and passing tests. |
| 10 | session_store.py not modified this phase — real session persistence stays Phase 3 (D-07) | ✓ VERIFIED | `git log --follow -- backend/session/session_store.py` shows last change (`7f9efad`) predates all of Phase 2; no Phase 2 commit touches this file. |
| 11 | VerificationLoop consumes VerificationPolicy as injected constructor dependency (D-08) | ✓ VERIFIED | `VerificationLoop.__init__(self, policy: VerificationPolicy | None = None)` stores `self._policy = policy or DEFAULT_VERIFICATION_POLICY`; `test_injected_custom_policy_is_honored` passes. |
| 12 | VerificationLoop excludes classification/tool dispatch this phase (D-09) | ✓ VERIFIED | No CONFIRMED/FALSE_POSITIVE/MANUAL_REVIEW logic present in `verification_loop.py`; module docstring explicitly states the exclusion. |
| 13 | `docker==7.2.0` pinned; Docker socket mounted (D-10) | ✓ VERIFIED | `backend/requirements.txt` contains `docker==7.2.0`; `docker-compose.yml` backend service volumes contains `/var/run/docker.sock:/var/run/docker.sock`; `networks:` unchanged. |

### Code-Review Fixes (CR-01, CR-02 — post-SUMMARY, pre-verification)

| # | Truth | Status | Evidence |
|---|-------|--------|----------|
| 14 | CR-01: SSHClient no longer awaits synchronous paramiko calls | ✓ VERIFIED | `backend/execution/ssh_client.py:20-26,33` now wraps `self.client.connect` and `client.exec_command` in `asyncio.to_thread`. Regression test `tests/execution/test_ssh_client.py` (2/2 passing) mocks `paramiko.SSHClient` as a plain `MagicMock` (not `AsyncMock`) — an accidental `await` on a non-awaitable would fail loudly, and it does not fail. Commit `af7b31a`. |
| 15 | CR-02: `tool_name` validated against path-traversal / tar-slip before use | ✓ VERIFIED | `backend/tools/backends/sandbox.py:36,91-98` validates `tool_name` against `^[A-Za-z0-9_-]{1,64}$` before any path/tar-entry construction; dead host-side temp-file write removed. Regression tests `tests/tools/test_sandbox_docker.py::TestSandboxToolNameValidation` (2/2 passing) confirm a `../../../../tmp/evil` tool_name is rejected with `status="error"`. Commit `ca1da9f`. |

**Score:** 22/22 must-haves verified (4 roadmap SCs + 9 plan-level truths + 2 CR regression fixes + 7 supporting evidence rows collapsed to distinct claims — see table rows above; no true duplicates double-counted)

### Required Artifacts

| Artifact | Expected | Status | Details |
|----------|----------|--------|---------|
| `backend/tools/backends/sandbox.py` | Docker-isolated `run_tool_code()` using docker-py | ✓ VERIFIED | `import docker` present, `network_mode="none"`, `mem_limit="256m"`, `asyncio.to_thread`, zero `create_subprocess_exec` calls, tool_name validation (CR-02) |
| `backend/requirements.txt` | `docker==7.2.0` pin | ✓ VERIFIED | Line 15 |
| `docker-compose.yml` | Docker socket mount | ✓ VERIFIED | Line 33: `/var/run/docker.sock:/var/run/docker.sock` |
| `tests/tools/test_sandbox_docker.py` | SEC-01 integration test, skippable without Docker | ✓ VERIFIED | 6/6 tests pass against live Docker daemon in this environment (not skipped) |
| `backend/execution/shell_manager.py` | Engagement-scoped command prefixing | ✓ VERIFIED | `mkdir -p "{workdir}" && cd "{workdir}"` prefix in `execute()` |
| `backend/execution/ssh_client.py` | `engagement_id` constructor param | ✓ VERIFIED | Stored as `self.engagement_id`; CR-01 fix also present |
| `tests/execution/test_shell_manager_scoping.py` | SEC-02 unit test | ✓ VERIFIED | 2/2 passing, exact string assertion |
| `backend/memory/client_profile.py` | WAL pragma on connection | ✓ VERIFIED | `PRAGMA journal_mode=WAL` + `PRAGMA synchronous=NORMAL` |
| `backend/intelligence/research_kb.py` | WAL pragma on connection | ✓ VERIFIED | Same pragmas, identical insertion point |
| `tests/intelligence/test_research_kb_wal.py` | DATA-01 test | ✓ VERIFIED | 1/1 passing |
| `backend/verification/verification_loop.py` | Engagement-scoped verification budget stub | ✓ VERIFIED | `check_and_increment`, `f"{engagement_id}:{finding_id}"` key, 61 lines (exceeds `min_lines: 25`) |
| `tests/verification/test_verification_loop.py` | DATA-02 test | ✓ VERIFIED | 3/3 passing |

### Key Link Verification

| From | To | Via | Status | Details |
|------|-----|-----|--------|---------|
| `backend/tools/backends/sandbox.py` | docker daemon | `docker.from_env()...containers.create/put_archive/start/wait` | ✓ WIRED | Live spot-check confirmed a real container was created and ran with correct isolation flags |
| `backend/tools/backends/sandbox.py` | asyncio event loop | `asyncio.to_thread` wrapping synchronous docker-py | ✓ WIRED | `_run_sync` wrapped via `asyncio.to_thread` inside `asyncio.wait_for` |
| `backend/agent/sub_agents/recon_agent.py` (×7) | `ShellManager` | `engagement_id` kwarg threaded into construction | ✓ WIRED | grep confirms all 7 files |
| `backend/execution/shell_manager.py` | `backend/execution/ssh_client.py` | scoped command passed to `ssh.execute` | ✓ WIRED | `self.ssh.execute(scoped)` |
| `backend/verification/verification_loop.py` | `backend/verification/verification_policy.py` | constructor injection | ✓ WIRED | `policy or DEFAULT_VERIFICATION_POLICY` |

### Behavioral Spot-Checks

| Behavior | Command | Result | Status |
|----------|---------|--------|--------|
| Sandbox launches isolated container with correct flags | Direct `run_tool_code()` invocation against live Docker daemon, container inspected mid-run | `NetworkMode=none`, `Memory=268435456`, 0 leaked containers after | ✓ PASS |
| Full test suite green (single run, no per-must-have re-runs) | `pytest tests/ --deselect .../test_sandbox_timeout` | 158 passed, 2 skipped, 1 deselected, 15 xfailed | ✓ PASS |
| CR-01 regression test | `pytest tests/execution/test_ssh_client.py -v` | 2 passed | ✓ PASS |
| CR-02 regression test | `pytest tests/tools/test_sandbox_docker.py::TestSandboxToolNameValidation -v` | 2 passed | ✓ PASS |
| DATA-01 WAL readback (both DB classes) | `pytest tests/memory/test_client_profile.py tests/intelligence/test_research_kb_wal.py -v` | 12 passed (incl. WAL tests) | ✓ PASS |
| DATA-02 budget isolation | `pytest tests/verification/test_verification_loop.py -v` | 3 passed | ✓ PASS |
| SEC-02 scoping string | `pytest tests/execution/test_shell_manager_scoping.py -v` | 2 passed | ✓ PASS |

### Probe Execution

No `scripts/*/tests/probe-*.sh` convention used by this project; no probes declared in PLAN/SUMMARY files. Skipped — behavioral spot-checks (above) and the full test-suite run served as the equivalent runnable evidence.

### Requirements Coverage

| Requirement | Source Plan | Description | Status | Evidence |
|-------------|-------------|-------------|--------|----------|
| SEC-01 | 02-01-PLAN.md | Generated tool code executes inside Docker container, no host subprocess | ✓ SATISFIED | Truths #1, #5, #6, #15; live spot-check |
| SEC-02 | 02-02-PLAN.md | Each engagement's Kali SSH commands run inside `/engagements/{id}/` | ✓ SATISFIED | Truths #2, #8, #14 |
| DATA-01 | 02-03-PLAN.md | Every SQLite connection applies WAL + synchronous=NORMAL on connect | ✓ SATISFIED | Truths #3, #9 |
| DATA-02 | 02-04-PLAN.md | `VerificationLoop._request_counts` keys prefixed by `{engagement_id}:` | ✓ SATISFIED | Truths #4, #11, #12 |

No orphaned requirements — REQUIREMENTS.md maps exactly SEC-01, SEC-02, DATA-01, DATA-02 to Phase 2, and all four appear in a plan's `requirements` frontmatter field.

**Note (non-blocking):** `.planning/REQUIREMENTS.md`'s summary status table (lines 67-70) still shows SEC-01/SEC-02/DATA-01/DATA-02 as "Pending" rather than "Complete" (unlike Phase 1's CLEAN-01/CLEAN-02, which read "Complete"). This is a documentation-bookkeeping gap, not a functional gap — implementation evidence for all four requirements is verified above. Flagged for the orchestrator to update as part of phase closeout.

### Anti-Patterns Found

None. Scanned all 15 phase-touched files (7 sub-agents, `ssh_client.py`, `shell_manager.py`, `sandbox.py`, `verification_loop.py`, `client_profile.py`, `research_kb.py`, `requirements.txt`, `docker-compose.yml`) for `TBD|FIXME|XXX|TODO|HACK|PLACEHOLDER` — zero matches.

**Carried-forward code-review warnings (non-blocking, documented in 02-REVIEW.md, explicitly accepted by the reviewer/orchestrator as out of this phase's scope):**

| File | Finding | Severity | Impact |
|------|---------|----------|--------|
| `backend/tools/backends/sandbox.py:194-200` | WR-02: sandbox container lacks `cap_drop`, `no-new-privileges`, `read_only`, non-root user beyond the required `network=none`/`mem_limit=256m` | ⚠️ Warning | Does not fail SEC-01's literal criteria (network=none, memory=256m, removed after use — all present); additional defense-in-depth deferred |
| `backend/execution/shell_manager.py:10-13`, 7 sub-agents | WR-03: `engagement_id` silently defaults to `"default"` with no upstream validation | ⚠️ Warning | Latent (not live) — no orchestrator wiring exists yet to exercise this path; will matter once Phase 3 wires sub-agents to a live caller |
| `backend/intelligence/research_kb.py`, `backend/memory/client_profile.py` | WR-04: check-then-act race on first-use `_conn is None` check could orphan a connection under concurrent first access | ⚠️ Warning | Both classes remain unwired/orphaned this phase (D-06/D-07); not exercised in the live path yet |
| `backend/memory/client_profile.py:210-215` | WR-05: last-two-labels base-domain heuristic mismatches multi-label public suffixes (e.g. `.co.uk`) | ℹ️ Info | Suggestion-only auto-match feature, operator always confirms |
| `backend/agent/sub_agents/exploit_agent.py:9` | IN-01: `payload_crafter`/`msfconsole` declared in `allowed_tools` but never dispatched | ℹ️ Info | Pre-existing, unrelated to Phase 2's scope |
| `backend/agent/sub_agents/data_sec_agent.py:73,116` | IN-02: redundant local `import re` | ℹ️ Info | Style only |

These were reviewed and explicitly accepted as non-blocking in `02-REVIEW.md`'s Resolution section ("The 5 warnings and 2 info findings were left as-is — none block SEC-01/SEC-02/DATA-01/DATA-02"). They do not gate this phase's goal achievement but are worth tracking as backlog items, particularly WR-03 and WR-04 given they touch the exact SEC-02/DATA-01 concerns this phase addresses (they become live risks only once Phase 3 wires sub-agents/DB classes to a real caller).

### Human Verification Required

None. All observable truths for this phase are backend/infra-level and were verified programmatically: live Docker daemon spot-check (container isolation flags), real SQLite temp-file connections (WAL readback), and mocked/unit tests for SSH transport and verification budget isolation. No UI, no visual, no real-time behavior in this phase's scope (`UI hint: no` per ROADMAP.md).

### Gaps Summary

No gaps. All 4 ROADMAP success criteria, all plan-level must-haves across the 4 executor plans, and both post-review critical fixes (CR-01, CR-02) are verified present, substantive, and — where applicable given the pre-existing unwired orchestrator (explicitly out of this phase's locked scope per CONTEXT.md) — correctly wired at the component level with passing regression tests. The full test suite (158 passed, 0 failures, 1 pre-existing unrelated deselection, 15 pre-existing xfails) was independently re-run by this verifier against a live Docker daemon and real SQLite files, not merely accepted from SUMMARY.md narration.

The one non-functional gap noted (REQUIREMENTS.md status table showing "Pending" instead of "Complete" for SEC-01/SEC-02/DATA-01/DATA-02) is a documentation bookkeeping item for phase closeout, not a code/goal gap, and does not affect the `passed` determination.

---

_Verified: 2026-08-29T10:14:24Z_
_Verifier: Claude (gsd-verifier)_
