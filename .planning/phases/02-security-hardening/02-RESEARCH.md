# Phase 2: Security Hardening - Research

**Researched:** 2026-08-29
**Domain:** Container isolation (Docker-in-Docker patterns), SSH command scoping (Paramiko), SQLite WAL durability, in-memory rate-limiting state design
**Confidence:** MEDIUM-HIGH (code-verified for all four targets; one architectural tension flagged for explicit operator decision)

<user_constraints>
## User Constraints (from CONTEXT.md)

### Locked Decisions

**Docker sandbox (SEC-01)**
- **D-01:** Fix `backend/tools/backends/sandbox.py` (`SandboxOnDemandBackend.run_tool_code()`) in place — replace the host `asyncio.create_subprocess_exec("python3", ...)` call with real Docker container isolation (`--network=none --memory=256m --rm`).
- **D-02:** Do NOT wire `custom_tool_generator.py` (or any other caller) to this backend in this phase. It has zero live callers today and stays that way — wiring it up is v1.1 Phase 9 (Auto Research & Strategy Evolution) scope. This phase only makes the backend itself correct and ready to be called later.

**Per-engagement Kali workdirs (SEC-02)**
- **D-03:** Scope `/engagements/{engagement_id}/` centrally at `SSHClient`/`ShellManager`, not per sub-agent. Both classes take `engagement_id` at construction; every command executed through `ShellManager.execute()` gets `cd /engagements/{engagement_id}/ && ...` prefixed (or equivalent) before being sent to `SSHClient.execute()`.
- **D-04:** The 7 live sub-agents (`recon_agent.py`, `scan_agent.py`, `exploit_agent.py`, `cloud_agent.py`, `iam_agent.py`, `endpoint_agent.py`, `data_sec_agent.py`) do NOT need their own command strings changed — they keep building relative paths (e.g. `/tmp/recon.txt` → becomes relative or engagement-scoped automatically via the centralized `cd`). Verify each agent's hardcoded `/tmp/...` paths still resolve correctly once workdir scoping is centralized — if any agent assumes an absolute non-`/tmp` path, that agent needs a follow-up fix.
- **D-05:** `engagement_id` must be threaded from `EngagementSession` down to wherever `SSHClient`/`ShellManager` gets constructed for that engagement's tool calls.

**WAL mode (DATA-01)**
- **D-06:** Scope narrowly: apply `PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;` immediately after connection at the two existing `sqlite3.connect()` call sites — `backend/memory/client_profile.py` and `backend/intelligence/research_kb.py`. Both are currently orphaned (no live caller), but the requirement is about the connection code being correct, not about wiring them into the live path.
- **D-07:** Do NOT stand up real SQLite-backed session persistence in this phase. `session_store.py` stays pure in-memory — that's Phase 3's PERSIST-01, explicitly out of scope here.

**VerificationLoop existence (DATA-02)**
- **D-08:** Build a minimal `VerificationLoop` class in this phase — just enough to hold `_request_counts: Dict[str, int]` keyed by `f"{engagement_id}:{finding_id}"`, plus a method to check/increment against `VerificationPolicy.max_requests_per_finding`. This satisfies DATA-02's literal requirement: finding counts don't bleed across concurrent engagements.
- **D-09:** Do NOT implement the full verification loop (CONFIRMED / FALSE_POSITIVE / MANUAL_REVIEW classification, OmO Reviewer role, actual tool dispatch) in this phase. That's the full F3 feature — v1.1 Phase 5. This phase's `VerificationLoop` is intentionally a scoping-only stub; v1.1 Phase 5 will extend it, not replace it.

### Claude's Discretion
- Exact mechanism for prefixing `cd /engagements/{id}/` (wrapper method on `ShellManager` vs. `SSHClient` constructor option vs. a decorator) — pick whichever fits existing code style with least churn.
- Whether `VerificationLoop`'s stub lives in `backend/verification/` (alongside `verification_policy.py`) or a new location — planner's call, but `backend/verification/` is the natural home given `VerificationPolicy` is already there.
- Exact Docker image/base used for the SEC-01 sandbox container.

### Deferred Ideas (OUT OF SCOPE)
- Wiring `custom_tool_generator.py` to the fixed Docker sandbox — v1.1 Phase 9 (Auto Research & Strategy Evolution)
- Full `VerificationLoop` (CONFIRMED/FALSE_POSITIVE/MANUAL_REVIEW, OmO Reviewer role, verification tool dispatch) — v1.1 Phase 5 (Autonomous Verification Loop)
- Real SQLite-backed session persistence for `session_store.py` — Phase 3 (Orchestration Upgrade), PERSIST-01
</user_constraints>

<phase_requirements>
## Phase Requirements

| ID | Description | Research Support |
|----|-------------|------------------|
| SEC-01 | Generated tool code executes inside a Docker container (`--network=none --memory=256m --rm`) — no host subprocess execution of untrusted code | Docker SDK for Python (`docker` 7.2.0) pattern documented below with exact `containers.run()` kwargs; DooD vs. host-sidecar tension flagged as Open Question #1 with architecture-doc precedent |
| SEC-02 | Each engagement's Kali SSH commands run inside `/engagements/{engagement_id}/` working directory | `mkdir -p && cd &&` prefix pattern verified safe for every current command string; **critical finding**: 4 of the 7 agents' commands use absolute `/tmp/...` output paths that a `cd` prefix will NOT scope — documented as Pitfall #1, corrects D-04's assumption |
| DATA-01 | Every SQLite connection applies `PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;` immediately after connection | Verified via sqlite.org docs: `journal_mode=WAL` is file-persistent (set once), `synchronous=NORMAL` is per-connection (must reissue every time) — both files already have `check_same_thread=False`, no additional change needed there |
| DATA-02 | `VerificationLoop._request_counts` dictionary keys are prefixed with `{engagement_id}:` | Prior (deleted) implementation recovered from git history informs forward-compatible stub interface; exact bug being fixed identified (old code keyed by bare `finding_id`) |
</phase_requirements>

## Summary

This phase touches four independent, currently-orphaned code paths — none of them have live callers in the running application today, which significantly lowers the blast radius of getting the fix wrong, but also means none of the fixes can be validated end-to-end through the chat UI. Each fix must be validated via direct unit/integration tests against the target class.

The two SQLite fixes (DATA-01) are mechanical and low-risk: `PRAGMA journal_mode=WAL` is a one-time, file-persistent setting and `PRAGMA synchronous=NORMAL` must be reissued per connection — both files already use `check_same_thread=False` correctly, so no additional threading changes are needed. The `VerificationLoop` stub (DATA-02) is well-informed by a prior, now-deleted implementation recovered from git history, which confirms the exact bug this phase fixes (the old class keyed its budget dict by bare `finding_id` with no engagement scoping) and suggests a forward-compatible method shape.

The SSH workdir scoping (SEC-02) has one critical gap the planner must address that CONTEXT.md's D-04 did not anticipate: `cd {dir} && {command}` prefixing only scopes *relative* paths. Grep of all 7 live sub-agents shows 4 commands (`recon_agent.py`, `scan_agent.py`, `cloud_agent.py`, `data_sec_agent.py`) write output to **absolute** `/tmp/...` paths, which a leading `cd` cannot redirect. Those 4 command strings must be edited to use relative or explicitly engagement-scoped paths, or SEC-02's success criterion #2 (no cross-contamination between concurrent engagements) will not actually hold for those 4 tools' output files even after the `cd` prefix is added everywhere else.

The Docker sandbox fix (SEC-01) has a genuine architectural tension worth surfacing before planning: `OPTIMUS_PRIME_ARCHITECTURE.md` §15.5/§17.2 explicitly designed sandbox container lifecycle to run through a **host-level sidecar process** (`SandboxManager`, listening on a Unix socket) specifically so that **no container ever gets the Docker socket mounted into it** — and this exact pattern is already implemented elsewhere in this codebase (`backend/tools/sandbox_manager.py`'s `RuntimeWatchdog`, whose docstring says "This runs as a host process (NOT in a container) for Docker socket access"). CONTEXT.md's D-01, by contrast, says fix `run_tool_code()` "in place," which — given the backend itself runs inside a Docker container with no socket currently mounted (verified in `docker-compose.yml`) — most straightforwardly means mounting `/var/run/docker.sock` into the **backend container** (Docker-outside-of-Docker), which is precisely the pattern the architecture doc and the existing watchdog code avoid. This is flagged as Open Question #1, not silently resolved, because it is a real security/architecture tradeoff, not just an implementation detail.

**Primary recommendation:** Use the Docker SDK for Python (`docker` 7.2.0, verified `[OK]` via slopcheck against PyPI) inside `SandboxOnDemandBackend`, wrapped in `asyncio.to_thread` since docker-py is synchronous; mount `/var/run/docker.sock` into the backend container as the pragmatic fix matching D-01's literal scope, but flag the DooD tradeoff explicitly for operator sign-off before v1.1 Phase 9 wires this backend up to a live caller. For SEC-02, centralize a `mkdir -p "{workdir}" && cd "{workdir}" && {command}` prefix in `ShellManager.execute()`, and separately fix the 4 absolute-path commands identified in Pitfall #1. For DATA-01, add two lines after each `sqlite3.connect()` call. For DATA-02, build the stub with a budget-check method whose signature anticipates the future classification return type without importing anything from the deleted `backend.core` module tree.

## Architectural Responsibility Map

| Capability | Primary Tier | Secondary Tier | Rationale |
|------------|-------------|----------------|-----------|
| Generated tool code execution isolation (SEC-01) | Tool Execution (`backend/tools/backends/`) | Host/Docker daemon | The backend process orchestrates container lifecycle; actual isolation is enforced by the Docker daemon, not application code |
| Per-engagement Kali workdir scoping (SEC-02) | Tool Execution (`backend/execution/`) | Kali container filesystem | `SSHClient`/`ShellManager` own command construction; the Kali container's filesystem is where isolation is physically enforced |
| SQLite WAL durability (DATA-01) | Data / Storage (`backend/memory/`, `backend/intelligence/`) | — | Each DB class owns its own connection lifecycle; no cross-tier coordination needed |
| Verification request budget scoping (DATA-02) | Tool Execution / Verification (`backend/verification/`) | Session (`EngagementSession`) | `VerificationLoop` owns the counter state; `EngagementSession` is only the source of `engagement_id`, not a co-owner of the budget logic |

## Package Legitimacy Audit

One new external dependency is introduced this phase: `docker` (Docker SDK for Python), needed for SEC-01.

| Package | Registry | Age | Downloads | Source Repo | slopcheck | Disposition |
|---------|----------|-----|-----------|-------------|-----------|-------------|
| `docker` | PyPI | 7.2.0 is current stable (long-running project, multi-year history under `docker/docker-py`) | High (foundational Docker tooling package) | github.com/docker/docker-py | [OK] | Approved |

**Verification method:** `slopcheck install docker` run against PyPI in this session returned `[OK]`. Cross-verified against official docs at `docker-py.readthedocs.io` (Context7 not available in this environment — CLI/MCP not configured; used WebFetch against the official ReadTheDocs page instead, which is an authoritative source). Package name and API shape confirmed against official documentation, not training data alone, so this is tagged `[VERIFIED: PyPI + official docs]` rather than `[ASSUMED]`.

**Packages removed due to slopcheck [SLOP] verdict:** none.
**Packages flagged as suspicious [SUS]:** none.

## Standard Stack

### Core
| Library | Version | Purpose | Why Standard |
|---------|---------|---------|--------------|
| `docker` (docker-py) | 7.2.0 [VERIFIED: PyPI `pip index versions docker`, current as of this session] | Programmatic control of the Docker Engine API from Python, used to launch the SEC-01 sandbox container | Official SDK maintained under the `docker/` GitHub org; avoids shelling out to the `docker` CLI binary (which would need to be installed separately in the backend image) |

No other new dependencies are required — `paramiko==3.5.0` (SEC-02), `sqlite3` (DATA-01, stdlib), and plain dataclasses (DATA-02) are already present.

**Installation:**
```bash
# Add to backend/requirements.txt
docker==7.2.0
```

**Version verification:** `pip index versions docker` returned `7.2.0` as latest, run in this research session against the live PyPI index.

## Architecture Patterns

### System Architecture Diagram

```
Operator (not wired to these paths yet this phase — see note below)
    |
    v
[EngagementSession] --engagement_id-->  (7 sub-agents' execute() methods)
                                              |
                    +-------------------------+-------------------------+
                    |                                                   |
                    v                                                   v
        [SSHClient(engagement_id)]                         [SandboxOnDemandBackend]
        [ShellManager(ssh, engagement_id)]                  .run_tool_code(code, tool_name,
                    |                                                target, timeout)
        every command gets:                                          |
        'mkdir -p "{workdir}" &&                          Docker SDK (docker-py, via
         cd "{workdir}" && {command}'                       asyncio.to_thread)
                    |                                                 |
                    v                                                 v
        paramiko.exec_command()  ---SSH--->  [Kali container]   Docker Engine API
        (fresh shell per call, no                              (unix:///var/run/docker.sock,
         persistent cwd across calls)                            mounted into backend container)
                                                                        |
                                                                        v
                                                            [ephemeral sandbox container]
                                                            --network=none --memory=256m --rm
                                                            runs generated code, captures
                                                            stdout/stderr/exit_code, auto-removes

[ClientProfileDB.initialize()]  --sqlite3.connect()--> apply PRAGMA journal_mode=WAL;
[ResearchKB.initialize()]                               PRAGMA synchronous=NORMAL;
                                                          (both stdlib sqlite3, already
                                                           check_same_thread=False)

[VerificationLoop(policy=VerificationPolicy)]
    ._request_counts: Dict[str, int]  keyed by f"{engagement_id}:{finding_id}"
    .check_budget(engagement_id, finding_id) -> bool   # stub only, no classification yet
```

**Important caveat on this diagram:** the top edge (`EngagementSession -> sub-agent execute()`) does **not exist in the live call chain today.** `Orchestrator.process()` calls only `LLMRouter.complete()` directly; it never calls `EngineRouter.dispatch()` or `InfrastructureEngine.execute()`, and `InfrastructureEngine.execute(task, sub_agent)` (the one class that does call `sub_agent.execute(target)`) itself has zero callers. This means SEC-02/DATA-02's "thread `engagement_id` from `EngagementSession`" work is a **component-level API change** (add `engagement_id` to constructors/method signatures) — there is no live orchestrator wiring to update, because none exists yet. Validation for this phase must happen via direct instantiation in tests, not via the chat UI. [VERIFIED: grep across `backend/agent/`, `backend/engines/`]

### Recommended Project Structure
No new directories needed — all four fixes live in existing files/modules:
```
backend/
├── tools/backends/sandbox.py       # SEC-01: swap subprocess for docker-py
├── execution/
│   ├── ssh_client.py                # SEC-02: add engagement_id param, cwd scoping
│   └── shell_manager.py             # SEC-02: prefix cd/mkdir on every execute()
├── memory/client_profile.py         # DATA-01: add PRAGMA calls after connect
├── intelligence/research_kb.py      # DATA-01: add PRAGMA calls after connect
└── verification/
    ├── verification_policy.py       # existing, unchanged — stub's constructor dependency
    └── verification_loop.py         # DATA-02: new stub file (natural home per D-08 discretion note)
```

### Pattern 1: Docker SDK for Python — ephemeral sandbox container
**What:** Replace `asyncio.create_subprocess_exec("python3", ...)` with a `docker-py` container run, wrapped in `asyncio.to_thread` since the SDK is synchronous.
**When to use:** Any time untrusted generated code needs to execute with hard isolation (no network, memory cap, auto-cleanup).
**Example (pattern, not copy-paste — verify against `docker-py.readthedocs.io/en/stable/containers.html` at implementation time):**
```python
# Source: docker-py official docs (containers.run/wait/logs), cross-verified via WebFetch
import asyncio
import docker
from docker.errors import ContainerError, ImageNotFound, APIError

SANDBOX_IMAGE = "optimus-sandbox:latest"

def _run_sync(script_path, target, timeout):
    client = docker.from_env()  # reads DOCKER_HOST or defaults to unix:///var/run/docker.sock
    container = client.containers.run(
        SANDBOX_IMAGE,
        command=["python3", "/work/script.py", target],
        volumes={str(script_path.parent): {"bind": "/work", "mode": "ro"}},
        network_mode="none",       # SEC-01: no network access
        mem_limit="256m",          # SEC-01: memory cap
        detach=True,               # need detach=True to get exit_code via wait() + logs() separately
        remove=False,              # remove manually after reading logs — auto_remove=True races log reads
    )
    try:
        result = container.wait(timeout=timeout)   # blocks until stop; raises on read-timeout
        exit_code = result.get("StatusCode", -1)
        stdout = container.logs(stdout=True, stderr=False).decode("utf-8", errors="replace")
        stderr = container.logs(stdout=False, stderr=True).decode("utf-8", errors="replace")
        return exit_code, stdout, stderr
    finally:
        container.remove(force=True)   # --rm equivalent, done explicitly to guarantee log capture first

async def run_tool_code(self, code, tool_name, target, timeout=SANDBOX_TIMEOUT):
    # ... write code to tmp_dir as today ...
    try:
        exit_code, stdout, stderr = await asyncio.wait_for(
            asyncio.to_thread(_run_sync, script_path, target, timeout),
            timeout=timeout + 5,  # outer guard slightly longer than inner container.wait timeout
        )
    except asyncio.TimeoutError:
        # container.wait() timeout leaves the container running — must kill+remove explicitly
        ...
```
**Key gotchas verified via docs/community sources (MEDIUM confidence — docker-py GitHub issues, not official docs):**
- `auto_remove=True` combined with reading logs afterward is a known race (`docker/docker-py#1813`, `#3289`) — the container can be removed by the daemon before the client reads its logs. Use `remove=False` + explicit `container.logs()` + `container.remove(force=True)` instead, or pass `remove=True` only when you don't need output back.
- `containers.run(..., detach=False)` with `stderr=True` and `stdout=True` returns *combined* bytes, not separable — use `detach=True` + `container.wait()` + two separate `container.logs()` calls to get stdout/stderr independently, which the existing `run_tool_code()` interface requires (it returns separate `stdout`/`stderr` keys).
- `container.wait(timeout=N)` is a client-side read timeout on the wait-for-exit HTTP call, not a guarantee the container itself is killed — on timeout you must still explicitly `container.kill()` / `container.remove(force=True)`, mirroring the existing `proc.kill()` fallback in the current subprocess-based code.

### Pattern 2: Paramiko command-scoping via shell prefix
**What:** Since `paramiko.SSHClient.exec_command()` opens a fresh non-interactive shell per call with no persisted state between calls, per-engagement workdir scoping must be re-applied on every single command, not set once.
**When to use:** Centralizing `SEC-02`'s workdir isolation at `ShellManager.execute()`.
**Example:**
```python
# Source: verified against current backend/execution/shell_manager.py + backend/execution/ssh_client.py
class ShellManager:
    def __init__(self, ssh_client: SSHClient, engagement_id: str):
        self.ssh = ssh_client
        self.engagement_id = engagement_id
        self._workdir = f"/engagements/{engagement_id}"
        self.active_sessions: dict = {}

    async def execute(self, command: str, timeout: int = 60) -> str:
        # mkdir -p guards against first-use-per-engagement (dir may not exist yet);
        # idempotent, so safe to run on every call rather than once at construction.
        scoped = f'mkdir -p "{self._workdir}" && cd "{self._workdir}" && {command}'
        return await self.ssh.execute(scoped)
```
**Why `mkdir -p` on every call instead of once at connect time:** `SSHClient.connect()` is lazy (only connects on first `execute()`), and there is no dedicated "session start" hook where a one-time `mkdir` could reliably run before the first real command. Prefixing `mkdir -p` is idempotent (near-zero cost on an existing directory) and removes the need for connection-lifecycle bookkeeping.
**Verified safe against every current command string** (grep across all 7 agents): none of the 25 command strings in the 7 live sub-agents themselves use `&&`, `;`, or backgrounding — the only place that matters is `ShellManager.create_session()`'s `bash -c 'sleep 999999' &`, and standard bash operator precedence means `cd DIR && bash -c '...' &` correctly backgrounds the *whole* `cd && bash -c ...` pipeline, not just the `bash -c` part. [VERIFIED: grep of `backend/agent/sub_agents/*.py`, bash operator-precedence is standard POSIX shell behavior]

### Pattern 3: SQLite WAL mode application
**What:** Apply both pragmas immediately after `sqlite3.connect()`, before any `executescript()`/table creation.
**Example:**
```python
# Source: sqlite.org/pragma.html (journal_mode, synchronous), verified via WebFetch
self._conn = await asyncio.to_thread(
    sqlite3.connect, str(self._db_path), check_same_thread=False,
)
self._conn.row_factory = sqlite3.Row
await asyncio.to_thread(self._conn.execute, "PRAGMA journal_mode=WAL")
await asyncio.to_thread(self._conn.execute, "PRAGMA synchronous=NORMAL")
# ... existing executescript() for CREATE TABLE follows unchanged ...
```
**Why both pragmas, not just `journal_mode`:** `journal_mode=WAL` is stored in the database file header and persists across connections/restarts — set it once and it stays. `synchronous` is a per-connection setting with no file-level persistence; it silently reverts to the connection default (`FULL` in most driver defaults) unless reissued every time a new connection is opened. Since both `ClientProfileDB` and `ResearchKB` open exactly one connection per process lifetime (`initialize()` is called once, connection cached on `self._conn`), reissuing per-connection here means "once per process," which satisfies DATA-01 as written. [VERIFIED: sqlite.org/pragma.html via WebFetch]

### Pattern 4: VerificationLoop budget stub, forward-compatible with future classification
**What:** A minimal class holding `_request_counts` keyed by `f"{engagement_id}:{finding_id}"`, with a budget-check method shaped so v1.1 Phase 5 can extend it without a breaking signature change.
**Example, informed by the prior (now-deleted) implementation recovered from git history (`git show 29d02a7^:backend/verification/verification_loop.py`):**
```python
# Source: pattern derived from deleted backend/verification/verification_loop.py
# (git commit 29d02a7^), adapted to new-system conventions and DATA-02's narrower scope.
# The old class keyed self._request_counts by bare finding_id — this IS the cross-
# engagement bleed bug DATA-02 exists to fix.
from __future__ import annotations
from dataclasses import dataclass, field
from typing import Dict

from backend.verification.verification_policy import (
    DEFAULT_VERIFICATION_POLICY,
    VerificationPolicy,
)


class VerificationLoop:
    """Scoping-only stub (DATA-02). Full CONFIRMED/FALSE_POSITIVE/MANUAL_REVIEW
    classification logic is v1.1 Phase 5 scope — do not add it here."""

    def __init__(self, policy: VerificationPolicy | None = None) -> None:
        self._policy = policy or DEFAULT_VERIFICATION_POLICY
        self._request_counts: Dict[str, int] = {}

    @property
    def policy(self) -> VerificationPolicy:
        return self._policy

    def _key(self, engagement_id: str, finding_id: str) -> str:
        return f"{engagement_id}:{finding_id}"

    def check_and_increment(self, engagement_id: str, finding_id: str) -> bool:
        """Increment and check the per-(engagement, finding) request budget.

        Returns True if still within VerificationPolicy.max_requests_per_finding,
        False if the budget is exhausted. Deliberately returns a bool, not a
        FindingClassification enum — that enum belongs to the full loop (v1.1
        Phase 5) and does not exist in the new system yet (it lived in the
        deleted backend.core.models module).
        """
        key = self._key(engagement_id, finding_id)
        count = self._request_counts.get(key, 0) + 1
        self._request_counts[key] = count
        return count <= self._policy.max_requests_per_finding
```
**Why `check_and_increment(engagement_id, finding_id)` rather than a single combined-string param:** keeping the two IDs as separate arguments (rather than requiring the caller to pre-build the `f"{engagement_id}:{finding_id}"` key) means the v1.1 Phase 5 full implementation can add a `verify_finding(engagement_id, finding, ...)` method that calls this same budget check internally without any signature migration on the budget-check method itself. [Design reasoning — not sourced from docs, tag as reasoned recommendation]

## Don't Hand-Roll

| Problem | Don't Build | Use Instead | Why |
|---------|-------------|-------------|-----|
| Docker container lifecycle management (create, wait, log capture, cleanup, timeout) | Manual `subprocess.run(["docker", "run", ...])` string-building + manual `docker ps`/`docker rm` polling | `docker` SDK (`docker-py`) `client.containers.run(...)` / `.wait()` / `.logs()` / `.remove()` | The SDK handles Docker Engine API versioning, connection reuse, and structured error types (`ImageNotFound`, `ContainerError`, `APIError`) that a raw CLI-shelling approach would have to reimplement by parsing stderr text |
| SQLite WAL/checkpoint tuning | Manual `-wal`/`-shm` file management or custom checkpoint scheduling | Stock `PRAGMA journal_mode=WAL` + default auto-checkpoint (SQLite's built-in 1000-page threshold) | SQLite's own WAL implementation already handles checkpoint scheduling safely; overriding it without a specific measured need adds risk for no benefit at this scale (personal-use, single-operator write volume) |

**Key insight:** both SEC-01 and DATA-01 are cases where the underlying engine (Docker daemon, SQLite) already solves the hard problem (isolation, durable concurrent I/O) — the fix in both cases is "call the existing mechanism correctly," not "build new isolation/concurrency logic."

## Common Pitfalls

### Pitfall 1: `cd` prefix does not scope absolute-path command arguments (SEC-02)
**What goes wrong:** D-03's `cd /engagements/{id}/ && {command}` prefix pattern only affects paths *relative* to the shell's working directory. Any command argument that is itself an absolute path (leading `/`) is completely unaffected by the `cd`.
**Why it happens:** Grep of all 25 command strings across the 7 live sub-agents shows 4 commands write output to hardcoded absolute `/tmp/...` paths:
- `recon_agent.py:21` — `sublist3r -d {target} -o /tmp/recon.txt`
- `scan_agent.py:21` — `nmap -sV -sC -oA /tmp/scan {target}`
- `cloud_agent.py:27` — `scoutsuite --provider {provider} --report-dir /tmp/cloud`
- `data_sec_agent.py:73` — `testssl.sh --jsonfile /tmp/tls.json {host}`

Prefixing `cd /engagements/{id} &&` in front of these does not change where `-o /tmp/recon.txt` writes — it still writes to the single, global, shared `/tmp/recon.txt` on the Kali container regardless of which engagement issued the command. Two concurrent engagements running `sublist3r` would overwrite each other's output file, directly contradicting SEC-02's success criterion #2 ("no cross-contamination").

The remaining 21 commands (e.g. `amass enum -d {target}`, `nikto -h {target}`, `sqlmap -u {target} --batch`) write only to stdout, which is captured by the SSH channel itself — cwd is irrelevant for those, so the `cd` prefix alone is sufficient for them.

**How to avoid:** The planner must include a task to edit these 4 specific command strings to use relative paths (e.g. `-o recon.txt`, `-oA scan`, `--report-dir cloud`, `--jsonfile tls.json`) instead of `/tmp/...`. Since the centralized `cd` prefix already lands the shell in `/engagements/{engagement_id}/` before the command runs, a relative filename will then correctly resolve inside the per-engagement directory. This is a small, mechanical change (4 string edits) but it is required for SEC-02 to actually satisfy its own success criterion — D-04's text ("if any agent assumes an absolute non-`/tmp` path, that agent needs a follow-up fix") appears to have assumed `/tmp/` paths were already acceptable/scoped; code inspection shows they are not.
**Warning signs:** A test that runs the same tool from two different `engagement_id`s and checks both `/engagements/{A}/recon.txt` and `/engagements/{B}/recon.txt` exist independently will fail for these 4 commands specifically if left unchanged, even though 21 of 25 commands would pass.

### Pitfall 2: `auto_remove=True` races log capture in docker-py (SEC-01)
**What goes wrong:** Setting `auto_remove=True` on `containers.run()` can cause the daemon to remove the container before the client has read its logs, especially for very fast-exiting scripts.
**Why it happens:** Documented upstream in `docker/docker-py` issues #1813 and #3289 — `auto_remove` is a daemon-side trigger tied to process exit, which races the client-side `container.logs()` HTTP call.
**How to avoid:** Use `detach=True`, `remove=False` on `containers.run()`; explicitly call `container.wait()` to block for exit, then `container.logs(stdout=True, stderr=False)` and `container.logs(stdout=False, stderr=True)` separately, then `container.remove(force=True)` as the very last step. This preserves the `--rm` *behavior* (container never persists after use) without the race.
**Warning signs:** Intermittent `docker.errors.NotFound` exceptions when reading logs, more frequent under load or for scripts that exit in well under a second.

### Pitfall 3: `--network=none` blocks the sandbox's own DVWA validation target (SEC-01, forward-looking)
**What goes wrong:** `SandboxOnDemandBackend`'s constructor defaults to `dvwa_url: str = "http://sandbox:80"`, implying the sandboxed code is meant to be tested by making HTTP requests against a DVWA container reachable at `sandbox:80` on the `optimus_internal` Docker network. `--network=none` (locked by SEC-01/D-01) severs **all** networking, including reachability to that DVWA container.
**Why it happens:** SEC-01's literal requirement text and ROADMAP's success criterion both hardcode `--network=none`, which is the correct choice for isolating *arbitrary generated code from the host and from lateral movement*, but it also means no generated tool that needs to reach a network target (which is the sandbox's entire stated purpose — validating tools against DVWA) can function once actually wired up.
**How to avoid — not this phase's problem to solve (D-02 keeps this backend unwired), but must be flagged for v1.1 Phase 9:** when this backend is wired up, someone will need to resolve the tension between "no network" (security requirement) and "must reach DVWA" (functional requirement) — likely via a custom isolated Docker network containing *only* the sandbox and DVWA containers (network segmentation) rather than `--network=none` outright, or by accepting that G2 validation becomes a static/offline check only. This phase should not attempt to resolve it (out of scope per D-02), but the plan's code comments/docstring in `sandbox.py` should note this so v1.1 Phase 9 doesn't rediscover it from scratch.
**Warning signs:** None visible this phase (backend has zero callers) — this is a documentation/comment recommendation, not a test-detectable pitfall right now.

### Pitfall 4: `PRAGMA synchronous` silently reverts if forgotten on any future new-connection code path (DATA-01)
**What goes wrong:** Because `journal_mode=WAL` persists at the file level but `synchronous` does not, a future code change that opens an *additional* connection to the same database file (e.g., a second reader) would silently get the driver's default `synchronous` value (not `NORMAL`) unless that new connection code also reissues the pragma.
**Why it happens:** This is a genuine asymmetry in SQLite's pragma design, not a project-specific bug — but it is a latent trap for future contributors.
**How to avoid:** Note in a code comment at each `PRAGMA synchronous=NORMAL` call site that this must be reissued on *every* new connection, unlike `journal_mode`. No action needed beyond the comment for this phase, since both `ClientProfileDB` and `ResearchKB` open exactly one connection per process lifetime.
**Warning signs:** N/A for this phase (single-connection-per-process pattern already in place).

## Code Examples

See Pattern 1–4 above under Architecture Patterns — all four are directly copy-adaptable to the target files, not generic boilerplate.

## State of the Art

| Old Approach | Current Approach | When Changed | Impact |
|--------------|------------------|---------------|--------|
| Raw `subprocess.run(["docker", ...])` CLI shelling for container orchestration | `docker` SDK (docker-py) talking to the Engine API directly | Docker SDK for Python has been the recommended approach for years; no recent deprecation of the CLI-shelling approach, but SDK avoids needing the `docker` binary installed in the image | Simpler `backend/Dockerfile` (no extra `apt-get install docker-cli`), structured exceptions instead of stderr string parsing |

**Deprecated/outdated:** none identified specific to this phase's scope — Paramiko, stdlib `sqlite3`, and dataclass-based state machines are all still the current standard approach for this codebase's established conventions.

## Assumptions Log

| # | Claim | Section | Risk if Wrong |
|---|-------|---------|---------------|
| A1 | Docker-outside-of-Docker (mounting `/var/run/docker.sock` into the backend container) is the pragmatic implementation for D-01's "fix in place" instruction, given the backend already runs inside its own container and D-02 forbids building the full host-sidecar architecture this phase | Summary, Open Question #1 | If the operator actually wants the host-sidecar pattern (matching `OPTIMUS_PRIME_ARCHITECTURE.md` §15.5 and the precedent set by `backend/tools/sandbox_manager.py`'s `RuntimeWatchdog`), the planner would need a fundamentally different, larger plan (a new host-level Python process + Unix socket protocol) instead of a docker-compose.yml volume-mount change |
| A2 | The recommended sandbox base image should be a custom-built local image (not pulled fresh from a public registry per run) pre-populated with common libraries generated tool code might import (e.g. `requests`) | Pattern 1, Claude's Discretion note in CONTEXT.md | If generated code needs a library not baked into the image, the tool will fail at runtime with an ImportError inside the network-isolated container — but since this backend has zero live callers this phase, this doesn't block SEC-01's acceptance criteria for this phase |
| A3 | `container.wait(timeout=N)` client-side timeout leaves the container running (does not auto-kill it) and must be paired with an explicit `container.kill()`/`remove(force=True)` fallback | Pattern 1 | If wrong (i.e., if docker-py's wait timeout does auto-kill), the extra fallback code is harmless but redundant; if the assumption is correct and the fallback is omitted, containers could leak past their timeout, undermining the "short-lived" guarantee SEC-01's success criterion depends on |

## Open Questions (RESOLVED)

1. **DooD (Docker socket in backend container) vs. host-sidecar architecture for SEC-01**
   - **RESOLVED:** CONTEXT.md locked decision D-10 chose DooD (Docker socket mounted into the backend container) over the host-sidecar architecture. This phase implements DooD per D-10; the host-sidecar approach is not built.
   - What we know: `OPTIMUS_PRIME_ARCHITECTURE.md` explicitly designed sandbox container spin-up to go through a host-level sidecar (`SandboxManager` on a Unix socket) specifically to avoid ever mounting the Docker socket into a container, and this exact avoidance pattern is already implemented for a different purpose in `backend/tools/sandbox_manager.py` (`RuntimeWatchdog`, whose docstring reads "This runs as a host process (NOT in a container) for Docker socket access"). CONTEXT.md's D-01 says fix `run_tool_code()` "in place," which, absent a host-sidecar build-out, most directly implies mounting the Docker socket into the backend container.
   - What's unclear: Whether the user intended D-01's "fix in place" to include quietly accepting this DooD tradeoff, or whether they'd want the (larger, architecturally-consistent) host-sidecar approach if they knew about this tension.
   - Recommendation: Default to DooD (socket mount) for this phase, since it's the smallest change consistent with D-01's literal text and D-02's "don't build more than needed" framing, but the plan should surface this explicitly as a checkpoint for human confirmation before the docker-compose.yml change is applied — this is a real security posture decision (backend container root-equivalent host access), not a routine implementation detail.

2. **Sandbox image contents**
   - **RESOLVED:** Plan 02-01 Task 3 locked the sandbox base image to `SANDBOX_IMAGE = "python:3.12-slim"` (stdlib-only). No live caller exists this phase, so image contents don't block acceptance; Phase 9 can extend the image once real generated-code samples exist.
   - What we know: Generated tool code's AST gate (`custom_tool_generator.py`'s G1) does not restrict which modules can be imported — only `subprocess(shell=True)`, `eval`/`exec`, `os.system`, unsafe file writes, and dunder-import tricks are blocked. This means generated code could plausibly `import requests` or other common libraries.
   - What's unclear: Exactly which third-party libraries the LLM-generated tool code is likely to import, since there's no existing corpus of generated tools to inspect (the generator has never run against a live target — G2 gate has zero historical invocations).
   - Recommendation: Start with a minimal `python:3.12-slim`-based sandbox image with stdlib only; this phase has no live caller so the image's exact contents don't block acceptance. Document the image Dockerfile location clearly so v1.1 Phase 9 can extend it once real generated-code samples exist.

## Environment Availability

| Dependency | Required By | Available | Version | Fallback |
|------------|------------|-----------|---------|----------|
| Docker Engine (daemon) | SEC-01 (container isolation) | Yes | 29.5.2 (verified via `docker info` in this session) | — |
| Docker socket (`/var/run/docker.sock`) mounted into backend container | SEC-01 | Not currently mounted — verified via `docker-compose.yml` inspection (no such volume entry on the `backend` service today) | — | Must be added as part of this phase's `docker-compose.yml` change; see Open Question #1 |
| `docker` Python package (docker-py) | SEC-01 | Not currently in `backend/requirements.txt` | Needs to be added: `docker==7.2.0` | — |
| Paramiko | SEC-02 | Listed in `backend/requirements.txt` (3.5.0) but not present in the host's system Python (project runs inside Docker; no local venv found on this dev host) | 3.5.0 (pinned) | Run tests inside the backend Docker container or a project-managed venv, not directly against system Python on this host |
| SQLite | DATA-01 | Yes (stdlib, no separate install) | 3.46.1 (system Python) | — |

**Missing dependencies with no fallback:**
- Docker socket mount into the backend container — must be added to `docker-compose.yml` as part of this phase's implementation (this is a plan task, not a blocker, but flagged here since it's a required infra change, not just a code change).

**Missing dependencies with fallback:**
- `docker` package — trivial `pip install`/requirements.txt addition, no fallback needed, just an implementation task.
- Local Paramiko/pytest execution — tests for SEC-02 should run inside the backend container (`docker compose run backend pytest ...`) or a project venv, since this host has no venv and system Python 3.14 lacks the pinned dependencies. Not a blocker, just a note for how the planner should frame test-execution tasks.

## Validation Architecture

### Test Framework
| Property | Value |
|----------|-------|
| Framework | pytest 8.3.3 + pytest-asyncio 0.24.0 (`asyncio_mode = "auto"`) |
| Config file | `pyproject.toml` (`testpaths = ["tests"]`) |
| Quick run command | `pytest tests/execution/ tests/tools/test_sandbox_docker.py tests/verification/ -x --tb=short` |
| Full suite command | `pytest` (repo root, per `pyproject.toml` `addopts = "-v --tb=short"`) |

### Phase Requirements → Test Map
| Req ID | Behavior | Test Type | Automated Command | File Exists? |
|--------|----------|-----------|-------------------|-------------|
| SEC-01 | `run_tool_code()` launches an isolated container (`--network=none --memory=256m --rm`), captures stdout/stderr/exit_code, cleans up after itself and after timeout | integration (requires live Docker daemon) | `pytest tests/tools/test_sandbox_docker.py -x` | ❌ Wave 0 |
| SEC-02 | `ShellManager.execute()` prefixes every command with `mkdir -p "{workdir}" && cd "{workdir}" &&`; the 4 absolute-`/tmp` commands are rewritten to relative paths | unit (mock `SSHClient`, assert the exact string sent to `exec_command`) | `pytest tests/execution/test_shell_manager_scoping.py -x` | ❌ Wave 0 |
| DATA-01 | Both `ClientProfileDB` and `ResearchKB` report `journal_mode=wal` via `PRAGMA journal_mode;` after `initialize()` | unit (real temp-file sqlite connection, query the pragma back) | `pytest tests/memory/test_client_profile.py tests/intelligence/test_research_kb_wal.py -x` | Partially — `tests/memory/test_client_profile.py` exists (extend it); `tests/intelligence/test_research_kb_wal.py` ❌ Wave 0 |
| DATA-02 | `VerificationLoop.check_and_increment(engagement_id, finding_id)` tracks independent counters per `f"{engagement_id}:{finding_id}"` key; two engagements verifying the same `finding_id` do not share/exhaust each other's budget | unit | `pytest tests/verification/test_verification_loop.py -x` | ❌ Wave 0 |

### Sampling Rate
- **Per task commit:** targeted test file for the task just completed (see table above)
- **Per wave merge:** `pytest` (full suite, repo root)
- **Phase gate:** Full suite green before `/gsd:verify-work`

### Wave 0 Gaps
- [ ] `tests/tools/test_sandbox_docker.py` — covers SEC-01; should be marked/skippable when Docker daemon is unavailable (e.g. `@pytest.mark.skipif(not docker_available(), reason="Docker daemon required")`) since not all execution environments will have Docker socket access
- [ ] `tests/execution/__init__.py` + `tests/execution/test_shell_manager_scoping.py` — covers SEC-02; new directory, needs `__init__.py`
- [ ] `tests/verification/__init__.py` + `tests/verification/test_verification_loop.py` — covers DATA-02; new directory, needs `__init__.py`
- [ ] `tests/intelligence/test_research_kb_wal.py` — covers DATA-01 for `ResearchKB` (mirrors whatever pattern is used to extend `tests/memory/test_client_profile.py` for the `ClientProfileDB` half of DATA-01)

## Security Domain

### Applicable ASVS Categories

| ASVS Category | Applies | Standard Control |
|---------------|---------|-------------------|
| V2 Authentication | No | Unrelated — this phase touches execution isolation and data durability, not auth (already covered by static bearer token per CLAUDE.md constraints) |
| V3 Session Management | No | `EngagementSession` is only a data source for `engagement_id` this phase, not modified |
| V4 Access Control | No | No new access-control surface introduced |
| V5 Input Validation | Partially — SEC-02 | Command strings still interpolate `target`/`provider`/`host` via unescaped f-strings (pre-existing pattern, not newly introduced or fixed by this phase) — see note below |
| V6 Cryptography | No | Not applicable to this phase's scope |
| V12 File and Resources (Docker isolation) | Yes — SEC-01 | `--network=none`, `mem_limit`, ephemeral `--rm` container as the standard control for untrusted-code execution isolation |

**Note on V5 (out of scope but worth flagging):** all 7 sub-agents build shell commands via unescaped f-string interpolation of `target`/`provider`/`host`/`ptype` values directly into the command string (e.g. `f"sublist3r -d {target} -o /tmp/recon.txt"`). This is a pre-existing command-injection-shaped risk *unrelated to and not fixed by* SEC-02 (SEC-02 only adds a `cd`/`mkdir` prefix, it does not touch the existing interpolation pattern). Not in scope for this phase's requirements (SEC-01/SEC-02/DATA-01/DATA-02 do not mention input sanitization), but noted here for honesty since the plan will be touching these exact command-construction call sites and a reviewer might reasonably expect it to be addressed. Recommend the planner explicitly note this as "observed, not fixed, out of scope" rather than silently leaving it unmentioned.

### Known Threat Patterns for this stack

| Pattern | STRIDE | Standard Mitigation |
|---------|--------|---------------------|
| Untrusted generated code executing with host filesystem/process access | Elevation of Privilege | Docker container isolation with `--network=none`, memory cap, `--rm` (this is exactly SEC-01) |
| Docker socket exposure to a container granting host-root-equivalent access | Elevation of Privilege | Host-level sidecar process (architecture doc's original design) or, if DooD is accepted as a pragmatic tradeoff, restrict exposure to only the backend's own trusted first-party code path — never let the sandboxed *generated* code itself touch the socket (only the orchestrating `SandboxOnDemandBackend` class does) |
| Cross-engagement data bleed via shared filesystem/state (Kali `/tmp`, `VerificationLoop` counters) | Information Disclosure / Tampering | Per-engagement directory scoping (SEC-02) and per-engagement-keyed counters (DATA-02) — this is exactly what this phase implements |
| Concurrent SQLite writers corrupting a shared database file | Tampering / Denial of Service | WAL mode (DATA-01) — allows concurrent readers with a single writer, reducing (not eliminating) lock contention; note WAL does not provide true concurrent writes (verified via community sources), only reader/writer non-blocking behavior |

## Sources

### Primary (HIGH confidence)
- Direct code inspection: `backend/tools/backends/sandbox.py`, `backend/execution/ssh_client.py`, `backend/execution/shell_manager.py`, `backend/memory/client_profile.py`, `backend/intelligence/research_kb.py`, `backend/verification/verification_policy.py`, `backend/session/engagement_session.py`, all 7 live sub-agents, `backend/agent/orchestrator.py`, `backend/engines/infrastructure_engine.py`, `backend/agent/engine_router.py`, `docker-compose.yml`, `backend/Dockerfile`, `backend/config.py`, `pyproject.toml`, `tests/conftest.py`
- `git show 29d02a7^:backend/verification/verification_loop.py` — recovered deleted prior implementation, used to inform DATA-02 stub design and confirm the exact bug being fixed
- `OPTIMUS_PRIME_ARCHITECTURE.md` §6.2, §6.4, §15.5, §17.1, §17.2 — sandbox architecture design intent, host-sidecar pattern precedent
- `backend/tools/sandbox_manager.py` (`RuntimeWatchdog`) — confirms the "no Docker socket in any container" pattern is already established project convention elsewhere
- sqlite.org `PRAGMA` documentation (fetched via WebFetch) — `journal_mode` persistence, `synchronous` per-connection behavior
- `docker-py.readthedocs.io/en/stable/containers.html` (fetched via WebFetch) — `containers.run()` parameter reference

### Secondary (MEDIUM confidence)
- docker-py GitHub issues #1813, #3289, #2450, #2745, #2087 (via WebSearch) — `auto_remove` log-capture race, exit-code capture nuances; community-reported, not official docs, but consistent across multiple independent reports
- WebSearch on Docker-outside-of-Docker security risk (multiple independent sources: OWASP-adjacent blogs, dev.to posts) — cross-verified against this project's own architecture doc and existing `RuntimeWatchdog` precedent, which independently corroborates the same conclusion
- WebSearch on SQLite WAL concurrent-writer behavior — cross-verified against sqlite.org's own WAL documentation semantics (readers don't block writers, writers still serialize)

### Tertiary (LOW confidence)
- None — all findings in this document were either directly verified against the codebase, official documentation, or corroborated by this project's own architecture documentation.

## Metadata

**Confidence breakdown:**
- Standard stack: HIGH — single new dependency (`docker` 7.2.0), verified via `pip index versions` and slopcheck against live PyPI
- Architecture: MEDIUM-HIGH — patterns verified against official docs and existing codebase conventions; the DooD-vs-sidecar tension (Open Question #1) is a genuine unresolved decision, not a confidence gap in the research itself
- Pitfalls: HIGH — Pitfall #1 (absolute `/tmp` paths) is directly verified via grep of all 25 command strings in the live codebase, not inferred; Pitfalls #2–4 verified against official/community docs

**Research date:** 2026-08-29
**Valid until:** 30 days (stable domain — Docker SDK, Paramiko, and SQLite pragma semantics change rarely; re-verify docker-py version if this research is reused after October 2026)
