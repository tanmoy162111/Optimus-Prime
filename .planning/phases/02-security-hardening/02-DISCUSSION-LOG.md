# Phase 2: Security Hardening - Discussion Log

> **Audit trail only.** Do not use as input to planning, research, or execution agents.
> Decisions are captured in CONTEXT.md — this log preserves the alternatives considered.

**Date:** 2026-08-29
**Phase:** 02-security-hardening
**Areas discussed:** Docker sandbox scope, Per-engagement workdirs, WAL mode scope, VerificationLoop existence

---

## Docker sandbox scope (SEC-01)

| Option | Description | Selected |
|--------|-------------|----------|
| Fix in place, leave unwired | Replace subprocess.exec with real Docker isolation inside sandbox.py itself. Satisfies SEC-01 literally; ready for v1.1 Phase 9 to call it. No new wiring now. | ✓ |
| Also wire it up now | Additionally connect custom_tool_generator.py so the sandbox is actually exercised in this phase — pulls some v1.1 Phase 9 scope forward. | |

**User's choice:** Fix in place, leave unwired
**Notes:** `backend/tools/backends/sandbox.py` (`SandboxOnDemandBackend`) has zero live callers today. This decision keeps Phase 2 from expanding into v1.1 Phase 9's wiring work.

---

## Per-engagement workdirs (SEC-02)

| Option | Description | Selected |
|--------|-------------|----------|
| Scope at SSHClient/ShellManager | Construct SSHClient/ShellManager with engagement_id; every command gets `cd /engagements/{id} && ...` prefixed centrally. Sub-agents don't need to change their command strings. | ✓ |
| Scope at each sub-agent | Each of the 7 sub-agents explicitly builds engagement-scoped paths in its own command strings. | |

**User's choice:** Scope at SSHClient/ShellManager
**Notes:** Centralizing avoids touching all 7 sub-agents' command strings. Flagged a follow-up check: any sub-agent using a hardcoded non-`/tmp` absolute path needs individual verification once centralized scoping lands.

---

## WAL mode scope (DATA-01)

| Option | Description | Selected |
|--------|-------------|----------|
| Narrow scope: existing connections only | Apply PRAGMA journal_mode=WAL to the two existing sqlite3.connect() sites as literally worded. Real session persistence stays Phase 3's PERSIST-01 job. | ✓ |
| Also stand up session persistence now | Give session_store.py real SQLite-backed persistence in this phase, ahead of Phase 3. | |

**User's choice:** Narrow scope: existing connections only
**Notes:** Both current SQLite sites (`client_profile.py`, `research_kb.py`) are orphaned/dead code — WAL mode still applies to the connection code itself, per DATA-01's literal wording.

---

## VerificationLoop existence (DATA-02)

| Option | Description | Selected |
|--------|-------------|----------|
| Build a minimal stub now | Create a bare-bones VerificationLoop class in this phase with just engagement-scoped _request_counts and a budget check — enough to satisfy DATA-02. Full CONFIRMED/FALSE_POSITIVE/MANUAL_REVIEW logic stays deferred to v1.1 Phase 5. | ✓ |
| Defer DATA-02 to v1.1 Phase 5 | Drop DATA-02 from Phase 2's scope entirely and move it into the v1.1 Verification Loop phase where the real class gets built. | |

**User's choice:** Build a minimal stub now
**Notes:** No `VerificationLoop` class exists at all — it was deleted in Phase 1 cleanup as dead code. This stub consumes the existing (also currently unused) `VerificationPolicy` dataclass rather than reimplementing limits.

---

## Claude's Discretion

- Exact mechanism for prefixing `cd /engagements/{id}/` (wrapper method vs. constructor option vs. decorator)
- Location of the new `VerificationLoop` stub file (leaning `backend/verification/` alongside `VerificationPolicy`)
- Exact Docker image/base for the SEC-01 sandbox container

## Deferred Ideas

- Wiring `custom_tool_generator.py` to the fixed Docker sandbox — v1.1 Phase 9
- Full `VerificationLoop` (CONFIRMED/FALSE_POSITIVE/MANUAL_REVIEW, OmO Reviewer role) — v1.1 Phase 5
- Real SQLite-backed session persistence — Phase 3, PERSIST-01
