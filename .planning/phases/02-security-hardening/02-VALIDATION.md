---
phase: 2
slug: security-hardening
status: planned
nyquist_compliant: true
wave_0_complete: false
created: 2026-08-29
---

# Phase 2 — Validation Strategy

> Per-phase validation contract for feedback sampling during execution.

---

## Test Infrastructure

| Property | Value |
|----------|-------|
| **Framework** | pytest 8.3.3 + pytest-asyncio 0.24.0 (`asyncio_mode = "auto"`) |
| **Config file** | `pyproject.toml` (`testpaths = ["tests"]`) |
| **Quick run command** | `pytest tests/execution/ tests/tools/test_sandbox_docker.py tests/verification/ -x --tb=short` |
| **Full suite command** | `pytest` (repo root, per `pyproject.toml` `addopts = "-v --tb=short"`) |
| **Estimated runtime** | ~30 seconds (quick), ~90 seconds (full suite, per existing 144-test baseline) |

---

## Sampling Rate

- **After every task commit:** Run the targeted test file for the requirement just implemented (see Per-Task Verification Map)
- **After every plan wave:** Run `pytest` (full suite, repo root)
- **Before `/gsd:verify-work`:** Full suite must be green
- **Max feedback latency:** 30 seconds

---

## Per-Task Verification Map

| Task ID | Plan | Wave | Requirement | Threat Ref | Secure Behavior | Test Type | Automated Command | File Exists | Status |
|---------|------|------|-------------|------------|-----------------|-----------|-------------------|-------------|--------|
| 02-01-T3 | 02-01 | 1 | SEC-01 | T-02-01, T-02-02, T-02-03, T-02-SC | `run_tool_code()` launches an isolated container (`--network=none --memory=256m --rm`), captures stdout/stderr/exit_code, cleans up after itself and after timeout | integration (requires live Docker daemon) | `pytest tests/tools/test_sandbox_docker.py -x` | ✅ created in 02-01-T1 | ⬜ pending |
| 02-02-T2 | 02-02 | 1 | SEC-02 | T-02-04, T-02-05, T-02-06 | `ShellManager.execute()` prefixes every command with `mkdir -p "{workdir}" && cd "{workdir}" &&`; the 4 absolute-`/tmp` commands are rewritten to relative paths (02-02-T3) | unit (mock `SSHClient`, assert exact string sent to `exec_command`) | `pytest tests/execution/test_shell_manager_scoping.py -x` | ✅ created in 02-02-T1 | ⬜ pending |
| 02-03-T2 | 02-03 | 1 | DATA-01 | T-02-07, T-02-08 | Both `ClientProfileDB` and `ResearchKB` report `journal_mode=wal` via `PRAGMA journal_mode;` after `initialize()` | unit (real temp-file sqlite connection, query pragma back) | `pytest tests/memory/test_client_profile.py tests/intelligence/test_research_kb_wal.py -x` | ✅ extended + created in 02-03-T1 | ⬜ pending |
| 02-04-T2 | 02-04 | 1 | DATA-02 | T-02-09, T-02-10 | `VerificationLoop.check_and_increment(engagement_id, finding_id)` tracks independent counters per `f"{engagement_id}:{finding_id}"` key; two engagements verifying the same finding_id don't share/exhaust each other's budget | unit | `pytest tests/verification/test_verification_loop.py -x` | ✅ created in 02-04-T1 | ⬜ pending |

*Task ID / Plan / Wave / Threat Ref columns populated by the planner. Wave-0 test scaffolds are the first task of each plan (RED before GREEN).*

---

## Wave 0 Requirements

- [ ] `tests/tools/test_sandbox_docker.py` — covers SEC-01; mark skippable when Docker daemon unavailable (`@pytest.mark.skipif(not docker_available(), reason="Docker daemon required")`) — created in 02-01 Task 1
- [ ] `tests/execution/__init__.py` + `tests/execution/test_shell_manager_scoping.py` — covers SEC-02; new directory — created in 02-02 Task 1
- [ ] `tests/verification/__init__.py` + `tests/verification/test_verification_loop.py` — covers DATA-02; new directory — created in 02-04 Task 1
- [ ] `tests/intelligence/test_research_kb_wal.py` — covers DATA-01 for `ResearchKB` (mirrors the extended `tests/memory/test_client_profile.py` pattern for the `ClientProfileDB` half) — created in 02-03 Task 1

---

## Manual-Only Verifications

*None — all four phase requirements have automated verification per the map above.*

---

## Validation Sign-Off

- [x] All tasks have `<automated>` verify or Wave 0 dependencies
- [x] Sampling continuity: no 3 consecutive tasks without automated verify
- [x] Wave 0 covers all MISSING references (each plan's Task 1 is the test scaffold)
- [x] No watch-mode flags
- [x] Feedback latency < 30s
- [x] `nyquist_compliant: true` set in frontmatter

**Approval:** planner-approved 2026-08-29
