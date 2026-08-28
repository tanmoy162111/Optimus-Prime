# Phase 2: Security Hardening - Context

**Gathered:** 2026-08-29
**Status:** Ready for planning

<domain>
## Phase Boundary

The operator can run real engagements against real targets without generated code executing on the host, without Kali artifacts bleeding between engagements, and without concurrent DB writes corrupting findings. Scope is SEC-01, SEC-02, DATA-01, DATA-02 as defined in ROADMAP.md Phase 2 — no new capabilities beyond hardening what Phase 1 left in place.

</domain>

<decisions>
## Implementation Decisions

### Docker sandbox (SEC-01)
- **D-01:** Fix `backend/tools/backends/sandbox.py` (`SandboxOnDemandBackend.run_tool_code()`) in place — replace the host `asyncio.create_subprocess_exec("python3", ...)` call with real Docker container isolation (`--network=none --memory=256m --rm`).
- **D-02:** Do NOT wire `custom_tool_generator.py` (or any other caller) to this backend in this phase. It has zero live callers today and stays that way — wiring it up is v1.1 Phase 9 (Auto Research & Strategy Evolution) scope. This phase only makes the backend itself correct and ready to be called later.

### Per-engagement Kali workdirs (SEC-02)
- **D-03:** Scope `/engagements/{engagement_id}/` centrally at `SSHClient`/`ShellManager`, not per sub-agent. Both classes take `engagement_id` at construction; every command executed through `ShellManager.execute()` gets `cd /engagements/{engagement_id}/ && ...` prefixed (or equivalent) before being sent to `SSHClient.execute()`.
- **D-04:** The 7 live sub-agents (`recon_agent.py`, `scan_agent.py`, `exploit_agent.py`, `cloud_agent.py`, `iam_agent.py`, `endpoint_agent.py`, `data_sec_agent.py`) do NOT need their own command strings changed — they keep building relative paths (e.g. `/tmp/recon.txt` → becomes relative or engagement-scoped automatically via the centralized `cd`). Verify each agent's hardcoded `/tmp/...` paths still resolve correctly once workdir scoping is centralized — if any agent assumes an absolute non-`/tmp` path, that agent needs a follow-up fix.
- **D-05:** `engagement_id` must be threaded from `EngagementSession` down to wherever `SSHClient`/`ShellManager` gets constructed for that engagement's tool calls.

### WAL mode (DATA-01)
- **D-06:** Scope narrowly: apply `PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;` immediately after connection at the two existing `sqlite3.connect()` call sites — `backend/memory/client_profile.py` and `backend/intelligence/research_kb.py`. Both are currently orphaned (no live caller), but the requirement is about the connection code being correct, not about wiring them into the live path.
- **D-07:** Do NOT stand up real SQLite-backed session persistence in this phase. `session_store.py` stays pure in-memory — that's Phase 3's PERSIST-01 (Orchestration Upgrade), explicitly out of scope here to avoid pulling Phase 3 work forward.

### VerificationLoop existence (DATA-02)
- **D-08:** Build a minimal `VerificationLoop` class in this phase — just enough to hold `_request_counts: Dict[str, int]` keyed by `f"{engagement_id}:{finding_id}"`, plus a method to check/increment against `VerificationPolicy.max_requests_per_finding` (the existing frozen policy dataclass at `backend/verification/verification_policy.py`, currently unused). This satisfies DATA-02's literal requirement: finding counts don't bleed across concurrent engagements.
- **D-09:** Do NOT implement the full verification loop (CONFIRMED / FALSE_POSITIVE / MANUAL_REVIEW classification, OmO Reviewer role, actual tool dispatch via `curl`/`nmap_verify`/`testssl_readonly`/`httpx_probe`) in this phase. That's the full F3 feature — v1.1 Phase 5 (Autonomous Verification Loop). This phase's `VerificationLoop` is intentionally a scoping-only stub; v1.1 Phase 5 will extend it, not replace it.

### Claude's Discretion
- Exact mechanism for prefixing `cd /engagements/{id}/` (wrapper method on `ShellManager` vs. `SSHClient` constructor option vs. a decorator) — pick whichever fits existing code style with least churn.
- Whether `VerificationLoop`'s stub lives in `backend/verification/` (alongside `verification_policy.py`) or a new location — planner's call, but `backend/verification/` is the natural home given `VerificationPolicy` is already there.
- Exact Docker image/base used for the SEC-01 sandbox container.

</decisions>

<specifics>
## Specific Ideas

No specific product references from this discussion — this phase is infrastructure hardening, not user-facing behavior. The two constraints that matter: (1) nothing currently live should regress, and (2) the two stubs built here (Docker sandbox, VerificationLoop) must be genuinely reusable by the v1.1 phases that wire them up, not throwaway scaffolding that gets rewritten.

</specifics>

<canonical_refs>
## Canonical References

**Downstream agents MUST read these before planning or implementing.**

### Project state and prior findings
- `.planning/PROJECT.md` — Constraints, Context section (documents the exact host-subprocess RCE risk and WAL/workdir/VerificationLoop gaps this phase closes)
- `.planning/ROADMAP.md` §"Phase 2: Security Hardening" — Goal, success criteria, requirement IDs (SEC-01, SEC-02, DATA-01, DATA-02)
- `.planning/REQUIREMENTS.md` — Full requirement text for SEC-01, SEC-02, DATA-01, DATA-02

### Architecture provenance (cited in existing code docstrings)
- `OPTIMUS_PRIME_ARCHITECTURE.md` §6.4 (N4) — referenced by `backend/tools/sandbox_manager.py` docstring (note: this is the RuntimeWatchdog for ml-runtime/ics-runtime containers, a DIFFERENT component from the SEC-01 sandbox target — do not conflate them)
- `OPTIMUS_PRIME_ARCHITECTURE.md` §7.4 (N9) — referenced by `backend/verification/verification_policy.py` docstring, governs what `VerificationLoop` is allowed to do (tool allowlist, max requests per finding, no-auth-injection default)

### Live code this phase touches
- `backend/tools/backends/sandbox.py` — `SandboxOnDemandBackend.run_tool_code()`, the SEC-01 target
- `backend/execution/ssh_client.py`, `backend/execution/shell_manager.py` — SEC-02 target, currently zero workdir scoping
- `backend/agent/sub_agents/recon_agent.py` (and the other 6 live sub-agents) — callers of `ShellManager`, currently hardcode `/tmp/` paths
- `backend/memory/client_profile.py`, `backend/intelligence/research_kb.py` — DATA-01's two `sqlite3.connect()` sites
- `backend/verification/verification_policy.py` — existing `VerificationPolicy` frozen dataclass the new `VerificationLoop` stub must consume
- `backend/session/engagement_session.py` — source of `engagement_id` for SEC-02/DATA-02 threading

</canonical_refs>

<code_context>
## Existing Code Insights

### Reusable Assets
- `VerificationPolicy` (`backend/verification/verification_policy.py`) — frozen dataclass already defines `max_requests_per_finding: int = 3` and the tool allowlist. The new `VerificationLoop` stub should take this as a constructor dependency, not reimplement limits.
- `EngagementSession` (`backend/session/engagement_session.py`) — already carries `session_id`/engagement identity; SEC-02 and DATA-02 threading should read `engagement_id` from here rather than inventing a new identifier.

### Established Patterns
- Sub-agents (`ReconAgent`, `ScanAgent`, etc.) all follow the same shape: construct `SSHClient()` + `ShellManager(ssh)` inline inside `execute()`, build raw f-string commands, call `shell.execute(cmd)`. Any workdir-scoping change to `SSHClient`/`ShellManager` constructors will need `engagement_id` passed through this same construction point in all 7 agents.
- `backend/tools/`, `backend/verification/`, `backend/memory/`, `backend/intelligence/` are ALL currently orphaned directories — nothing in `backend/agent/`, `backend/api/`, or `backend/app.py` imports from them. This phase's changes (sandbox.py, VerificationLoop stub, WAL pragma) stay in that same "correct but unwired" state; wiring happens in later phases (v1.1 Phase 5 for VerificationLoop, v1.1 Phase 9 for the sandbox).

### Integration Points
- `SSHClient`/`ShellManager` construction sites inside each of the 7 sub-agents' `execute()` methods — this is where `engagement_id` needs to flow in for SEC-02.
- Wherever `EngagementSession` is available to a sub-agent at dispatch time (likely via `EngineRouter`/`Orchestrator`) — need to confirm the call chain actually has `engagement_id` in scope when sub-agents are invoked.

</code_context>

<deferred>
## Deferred Ideas

- Wiring `custom_tool_generator.py` to the fixed Docker sandbox — v1.1 Phase 9 (Auto Research & Strategy Evolution)
- Full `VerificationLoop` (CONFIRMED/FALSE_POSITIVE/MANUAL_REVIEW, OmO Reviewer role, verification tool dispatch) — v1.1 Phase 5 (Autonomous Verification Loop)
- Real SQLite-backed session persistence for `session_store.py` — Phase 3 (Orchestration Upgrade), PERSIST-01

</deferred>

---

*Phase: 02-security-hardening*
*Context gathered: 2026-08-29*
