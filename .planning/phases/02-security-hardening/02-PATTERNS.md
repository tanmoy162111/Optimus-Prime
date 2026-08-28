# Phase 2: Security Hardening - Pattern Map

**Mapped:** 2026-08-29
**Files analyzed:** 18 (7 modified core, 4 sub-agent path fixes, 7 sub-agent instantiation-site changes overlap, 1 new module, 2 config, 5 new/extended tests)
**Analogs found:** 18 / 18 (all files have at least a role-match analog; 1 file — `verification_loop.py` — analog is a recovered deleted file from git history, not a currently-live file)

## File Classification

| New/Modified File | Role | Data Flow | Closest Analog | Match Quality |
|--------------------|------|-----------|-----------------|----------------|
| `backend/tools/backends/sandbox.py` | service | file-I/O (subprocess→container exec) | itself (existing structure) + `backend/tools/sandbox_manager.py` (`RuntimeWatchdog`) | role-match (self) / partial (container lifecycle) |
| `backend/execution/ssh_client.py` | service | request-response | `backend/tools/backends/kali_ssh.py` (`KaliConnectionManager`) | partial-match (more advanced SSH pattern, same domain) |
| `backend/execution/shell_manager.py` | service | request-response | itself (existing structure); command-prefix idiom is new | exact (self) |
| `backend/agent/sub_agents/recon_agent.py` | service (agent) | request-response | `backend/agent/sub_agents/scan_agent.py` (sibling, same shape) | exact |
| `backend/agent/sub_agents/scan_agent.py` | service (agent) | request-response | `backend/agent/sub_agents/recon_agent.py` (sibling) | exact |
| `backend/agent/sub_agents/cloud_agent.py` | service (agent) | request-response | `backend/agent/sub_agents/recon_agent.py` (sibling) | exact |
| `backend/agent/sub_agents/data_sec_agent.py` | service (agent) | request-response | `backend/agent/sub_agents/cloud_agent.py` (sibling, multi-branch shape) | exact |
| `backend/agent/sub_agents/exploit_agent.py`, `iam_agent.py`, `endpoint_agent.py` | service (agent) | request-response | `backend/agent/sub_agents/recon_agent.py` (construction-site only, no cmd string changes) | exact |
| `backend/memory/client_profile.py` | model | CRUD | `backend/intelligence/research_kb.py` (sibling sqlite class, same `initialize()` shape) | exact |
| `backend/intelligence/research_kb.py` | model | CRUD | `backend/memory/client_profile.py` (sibling sqlite class) | exact |
| `backend/verification/verification_loop.py` (new) | service/utility | event-driven (counter/budget check) | recovered deleted `backend/verification/verification_loop.py` (git `29d02a7^`) | role-match (prior impl, bug-for-bug informs the fix) |
| `docker-compose.yml` | config | — | `ml-runtime` service block (security_opt/cap_drop precedent) | partial-match |
| `backend/requirements.txt` | config | — | itself (flat pinned-version list) | exact |
| `tests/tools/test_sandbox_docker.py` (new) | test | integration | `tests/tools/test_kali_connection_mgr.py` (mock-heavy unit/integration pattern) | partial-match |
| `tests/execution/test_shell_manager_scoping.py` (new) | test | unit | `tests/tools/test_kali_connection_mgr.py` (`_make_mock_client` paramiko mocking) | role-match |
| `tests/verification/test_verification_loop.py` (new) | test | unit | `tests/memory/test_client_profile.py` (dataclass-driven unit test structure) | role-match |
| `tests/intelligence/test_research_kb_wal.py` (new) | test | unit | `tests/memory/test_client_profile.py` (`tmp_path` fixture, `pytest.mark.asyncio`) | exact (same DB pattern) |
| `tests/memory/test_client_profile.py` (extend) | test | unit | itself (extend in place) | exact |

## Pattern Assignments

### `backend/tools/backends/sandbox.py` (service, file-I/O)

**Analog:** itself (`backend/tools/backends/sandbox.py`, current version) — preserve method signature, effectiveness-scoring, and cleanup shape; only the execution mechanism changes.

**Current imports** (lines 1-15):
```python
from __future__ import annotations

import asyncio
import logging
import tempfile
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

SANDBOX_TIMEOUT = 120  # Maximum execution time in seconds
```
Add `import docker` and `from docker.errors import ContainerError, ImageNotFound, APIError` here; keep everything else.

**Current core pattern to replace** (lines 70-114, `run_tool_code()` subprocess block):
```python
try:
    proc = await asyncio.create_subprocess_exec(
        "python3", str(script_path), target,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        cwd=str(tmp_dir),
    )
    try:
        stdout, stderr = await asyncio.wait_for(
            proc.communicate(), timeout=timeout,
        )
        ...
    except asyncio.TimeoutError:
        proc.kill()
        return {"status": "timeout", ...}
except Exception as exc:
    return {"status": "error", "tool": tool_name, "error": str(exc), ...}
finally:
    try:
        script_path.unlink(missing_ok=True)
        tmp_dir.rmdir()
    except OSError:
        pass
```
Replace `asyncio.create_subprocess_exec` with a synchronous `docker.from_env().containers.run(...)` call wrapped in `asyncio.to_thread`, per RESEARCH.md Pattern 1 (already fully worked out there — copy that code block, not the subprocess block above). Preserve the outer `try/except Exception`/`finally` structure and the existing `_compute_effectiveness()`/`_count_findings()` helpers unchanged — only the body inside the inner `try` changes from `proc.communicate()` to `container.wait()` + two `container.logs()` calls + `container.remove(force=True)`.

**Error handling pattern to keep** (lines 107-114): the outer `except Exception as exc: return {"status": "error", ...}` — extend to also catch `docker.errors.ImageNotFound`/`APIError`/`ContainerError` explicitly before the generic `Exception` catch, following the existing dict-shaped error-response convention (`status`, `tool`, `error`, `passed`, `effectiveness_score`).

**Secondary analog — container lifecycle async wrapping:** `backend/tools/sandbox_manager.py` `RuntimeWatchdog._kill_container()` (lines 112-154) shows the project's existing convention for wrapping blocking Docker calls: `await asyncio.to_thread(subprocess.run, [...], capture_output=True, timeout=5)` and catching `(subprocess.TimeoutExpired, FileNotFoundError, OSError)`. Mirror this same `asyncio.to_thread` + explicit timeout + explicit exception tuple style for the new docker-py calls (adapted to `docker.errors.*` exception types instead of subprocess ones).

**Docstring note to add** (per RESEARCH.md Pitfall #3): document that `--network=none` blocks reachability to the `dvwa_url` sandbox target, and that this is a known, deliberately-deferred tension for v1.1 Phase 9.

---

### `backend/execution/ssh_client.py` (service, request-response)

**Analog:** `backend/tools/backends/kali_ssh.py` (`KaliConnectionManager`/`KaliConnection`) — a more advanced sibling implementation in the same domain (SSH-to-Kali). Not a 1:1 copy target (that class does connection pooling, out of scope here), but confirms the project's paramiko usage conventions and exception handling style for this phase's smaller change (adding `engagement_id` to the constructor).

**Current file, full** (18 lines relevant, `backend/execution/ssh_client.py` lines 1-43):
```python
import paramiko
import logging
from typing import Optional
from backend import config

logger = logging.getLogger(__name__)


class SSHClient:
    def __init__(self):
        self.client: Optional[paramiko.SSHClient] = None

    async def connect(self) -> paramiko.SSHClient:
        if self.client is None:
            self.client = paramiko.SSHClient()
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            await self.client.connect(
                hostname=config.settings.kali_host,
                port=config.settings.kali_port,
                username=config.settings.kali_user,
                password=config.settings.kali_password,
            )
        return self.client

    async def execute(self, command: str) -> str:
        client = await self.connect()
        stdin, stdout, stderr = client.exec_command(command)
        output = stdout.read().decode()
        error = stderr.read().decode()
        if error:
            logger.warning(f"SSH command error: {error}")
        return output
```
**Change required (D-03/D-05):** add `engagement_id: str | None = None` to `__init__`, store as `self.engagement_id`. Keep `connect()`/`execute()` bodies unchanged — `SSHClient.execute()` stays a dumb command-runner; workdir scoping is applied one layer up in `ShellManager` (see below), not here. This matches CONTEXT.md D-03 ("Both classes take `engagement_id` at construction") without duplicating the `cd` prefix logic in two places.

---

### `backend/execution/shell_manager.py` (service, request-response)

**Analog:** itself (current 3-method structure) — RESEARCH.md Pattern 2 provides the exact target implementation, already verified safe against all 25 live command strings.

**Current file, full** (`backend/execution/shell_manager.py` lines 1-30):
```python
from typing import Optional, List
import logging

from backend.execution.ssh_client import SSHClient

logger = logging.getLogger(__name__)


class ShellManager:
    def __init__(self, ssh_client: SSHClient):
        self.ssh = ssh_client
        self.active_sessions: dict = {}

    async def execute(self, command: str, timeout: int = 60) -> str:
        logger.info(f"Executing: {command}")
        output = await self.ssh.execute(command)
        return output

    async def create_session(self, session_id: str, target: str) -> str:
        session_shell = await self.ssh.execute(f"bash -c 'sleep 999999' &")
        self.active_sessions[session_id] = session_shell
        return session_id
```

**Target pattern (copy directly from RESEARCH.md Pattern 2):**
```python
class ShellManager:
    def __init__(self, ssh_client: SSHClient, engagement_id: str):
        self.ssh = ssh_client
        self.engagement_id = engagement_id
        self._workdir = f"/engagements/{engagement_id}"
        self.active_sessions: dict = {}

    async def execute(self, command: str, timeout: int = 60) -> str:
        scoped = f'mkdir -p "{self._workdir}" && cd "{self._workdir}" && {command}'
        logger.info(f"Executing: {scoped}")
        return await self.ssh.execute(scoped)
```
**Verified safe interaction with `create_session()`'s trailing `&`:** bash operator precedence means `cd DIR && bash -c '...' &` backgrounds the whole `cd && bash -c ...` pipeline correctly — no change needed to `create_session()`/`send_to_session()` beyond them now going through the same scoped `execute()`.

**Logging pattern to preserve:** `logger.info(f"Executing: {command}")` — module-level logger, f-string interpolation, matches project-wide logging convention (see Shared Patterns below).

---

### `backend/agent/sub_agents/{recon,scan,cloud,data_sec}_agent.py` (service/agent, request-response)

**Analog:** the 7 sub-agents are mutual analogs — identical construction-site shape (`SSHClient()` + `ShellManager(ssh)` inline inside `execute()`). Use `recon_agent.py` as the canonical shape reference.

**Current construction-site pattern, present in all 7 agents identically** (e.g. `backend/agent/sub_agents/recon_agent.py` lines 13-18):
```python
async def execute(self, target: str, **kwargs):
    from backend.execution.ssh_client import SSHClient
    from backend.execution.shell_manager import ShellManager

    ssh = SSHClient()
    shell = ShellManager(ssh)
```
**Change required in all 7 files (D-05):** thread `engagement_id` through. Since `EngagementSession.engagement_id` is not yet reachable at this call site (RESEARCH.md's "important caveat" — no live orchestrator wiring calls `sub_agent.execute()` today), the pattern must accept `engagement_id` as a kwarg on `execute()` (matching the existing `**kwargs` idiom already used for `exploit_type`, `provider`, `phase`, `type` in sibling agents) rather than inventing new constructor wiring with no caller:
```python
async def execute(self, target: str, **kwargs):
    from backend.execution.ssh_client import SSHClient
    from backend.execution.shell_manager import ShellManager

    engagement_id = kwargs.get("engagement_id", "default")
    ssh = SSHClient(engagement_id=engagement_id)
    shell = ShellManager(ssh, engagement_id=engagement_id)
```
This mirrors the exact `kwargs.get(...)` idiom already used in `exploit_agent.py:20` (`kwargs.get("exploit_type", "sqlmap")`), `cloud_agent.py:17-18`, `iam_agent.py:17`, `endpoint_agent.py:20`, `data_sec_agent.py:20` — no new pattern introduced, just applied one more time.

**4 absolute-path fixes required (RESEARCH.md Pitfall #1) — exact line-level diffs:**
| File:Line | Current | Required change |
|-----------|---------|------------------|
| `recon_agent.py:21` | `f"sublist3r -d {target} -o /tmp/recon.txt"` | `f"sublist3r -d {target} -o recon.txt"` |
| `scan_agent.py:21` | `f"nmap -sV -sC -oA /tmp/scan {target}"` | `f"nmap -sV -sC -oA scan {target}"` |
| `cloud_agent.py:27` | `f"scoutsuite --provider {provider} --report-dir /tmp/cloud"` | `f"scoutsuite --provider {provider} --report-dir cloud"` |
| `data_sec_agent.py:73` | `f"testssl.sh --jsonfile /tmp/tls.json {host}"` | `f"testssl.sh --jsonfile tls.json {host}"` |

These 4 relative paths resolve correctly once `ShellManager.execute()`'s `cd "{workdir}" &&` prefix (above) lands the shell in `/engagements/{engagement_id}/` before the command runs. The remaining 21 command strings across all 7 agents (stdout-only tools like `amass`, `nikto`, `sqlmap`) need no changes.

**`exploit_agent.py`, `iam_agent.py`, `endpoint_agent.py`:** construction-site change only (the `SSHClient(engagement_id=...)`/`ShellManager(ssh, engagement_id=...)` pattern above) — per D-04, no command-string edits needed, all their command strings are already relative or stdout-only.

---

### `backend/memory/client_profile.py` and `backend/intelligence/research_kb.py` (model, CRUD)

**Analog:** each is the other's closest analog — both are single-connection-per-process SQLite classes with an identical `initialize()` shape.

**Current pattern in both files** (`client_profile.py` lines 51-57 / `research_kb.py` lines 53-58):
```python
async def initialize(self) -> None:
    async with self._lock:
        self._conn = await asyncio.to_thread(
            sqlite3.connect, str(self._db_path), check_same_thread=False,
        )
        self._conn.row_factory = sqlite3.Row
        await asyncio.to_thread(
            self._conn.executescript,
            """
            CREATE TABLE IF NOT EXISTS ...
            """,
        )
        await asyncio.to_thread(self._conn.commit)
```
**Change required in both files (D-06) — insert immediately after `self._conn.row_factory = sqlite3.Row` and before the `executescript` call**, per RESEARCH.md Pattern 3:
```python
        self._conn.row_factory = sqlite3.Row
        await asyncio.to_thread(self._conn.execute, "PRAGMA journal_mode=WAL")
        await asyncio.to_thread(self._conn.execute, "PRAGMA synchronous=NORMAL")
        # NOTE: journal_mode persists in the DB file; synchronous does NOT —
        # must be reissued on every new connection (see RESEARCH.md Pitfall #4).
```
Both files use this identical `initialize()` shape, so the same 3-line insertion applies verbatim in each, at `client_profile.py:57` and `research_kb.py:58` respectively (immediately after the `row_factory` line in each file).

---

### `backend/verification/verification_loop.py` (new file, service/utility, event-driven)

**Analog:** recovered deleted implementation at `git show 29d02a7^:backend/verification/verification_loop.py` — this is the ONLY analog for this new file, and it directly demonstrates the bug DATA-02 exists to fix.

**The bug being fixed, verified via git history** (deleted file, lines 52, 71, 101):
```python
# line 52:
self._request_counts: dict[str, int] = {}
# line 71:
current_count = self._request_counts.get(finding_id, 0)     # <- bare finding_id, no engagement scoping
# line 101:
self._request_counts[finding_id] = current_count + 1        # <- same bug on write
```
This confirms: the old class keyed its budget dict by bare `finding_id` alone — two concurrent engagements verifying a finding with the same `finding_id` would share (and could exhaust) each other's request budget. This is exactly the cross-engagement bleed DATA-02 requires fixing.

**New stub to write — copy directly from RESEARCH.md Pattern 4 (already fully specified there, reproduced here for convenience):**
```python
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
        key = self._key(engagement_id, finding_id)
        count = self._request_counts.get(key, 0) + 1
        self._request_counts[key] = count
        return count <= self._policy.max_requests_per_finding
```
**Constructor-injection pattern to follow:** `VerificationPolicy` is consumed as an injected constructor dependency, not reimplemented — this mirrors `verification_policy.py`'s own `DEFAULT_VERIFICATION_POLICY` singleton-default idiom (`verification_policy.py` line 70-71: `DEFAULT_VERIFICATION_POLICY = VerificationPolicy()`), and the `policy: X | None = None; self._policy = policy or DEFAULT_X` constructor shape is otherwise unprecedented in this codebase — introduce it here as the first instance, since it's the cleanest way to satisfy "take this as a constructor dependency, not reimplement limits" from CONTEXT.md's Reusable Assets note.

**Module docstring convention to follow** (per project style — see `verification_policy.py` lines 1-6 and `sandbox_manager.py` lines 1-8): open with a one-line summary, cite the architecture doc section (`§7.4 (N9)` per CONTEXT.md canonical refs), then bullet what the class does/doesn't do — explicitly state this stub excludes classification logic (v1.1 Phase 5 scope), matching the "stub, not full feature" framing CONTEXT.md D-09 requires.

---

## Shared Patterns

### Module-level logging
**Source:** every touched module already follows this — `backend/execution/ssh_client.py:6`, `backend/execution/shell_manager.py:6`, `backend/memory/client_profile.py:19`, `backend/intelligence/research_kb.py:18`
```python
logger = logging.getLogger(__name__)
```
**Apply to:** any new file (`verification_loop.py`) that logs; not strictly required for the stub (no logging in RESEARCH.md's Pattern 4) but should be added if `check_and_increment` needs a warning log on budget exhaustion (Claude's discretion — the stub interface doesn't mandate it).

### Async wrapping of blocking calls
**Source:** `backend/memory/client_profile.py:54-58`, `research_kb.py:55-59` (`asyncio.to_thread(sqlite3.connect, ...)`); `backend/tools/sandbox_manager.py:116-121` (`asyncio.to_thread(subprocess.run, ...)`)
```python
await asyncio.to_thread(blocking_call, *args)
```
**Apply to:** `sandbox.py`'s new docker-py calls (`client.containers.run`, `container.wait`, `container.logs`, `container.remove`) — docker-py is synchronous, same wrapping idiom as the two SQLite classes and the existing watchdog.

### Dataclass-driven test fixtures with `tmp_path`
**Source:** `tests/memory/test_client_profile.py` lines 65-72
```python
@pytest.fixture
async def profile_db(tmp_path):
    db = ClientProfileDB(db_path=tmp_path / "test_profiles.db")
    await db.initialize()
    ...
    yield db
    await db.close()
```
**Apply to:** `tests/intelligence/test_research_kb_wal.py` (same `tmp_path`-backed real-file-connection pattern, verifying `PRAGMA journal_mode` via a follow-up query rather than mocking).

### Mocked paramiko SSH client for unit tests
**Source:** `tests/tools/test_kali_connection_mgr.py` lines 55-69
```python
def _make_mock_client(active: bool = True):
    client = MagicMock()
    client.get_transport.return_value = _make_mock_transport(active)
    stdin_mock = MagicMock()
    stdout_mock = MagicMock()
    stderr_mock = MagicMock()
    stdout_mock.channel.recv_exit_status.return_value = 0
    stdout_mock.read.return_value = b"scan results here"
    stderr_mock.read.return_value = b""
    client.exec_command.return_value = (stdin_mock, stdout_mock, stderr_mock)
    return client
```
**Apply to:** `tests/execution/test_shell_manager_scoping.py` — mock `SSHClient.execute()` directly (simpler than mocking paramiko internals, since `ShellManager` only calls `self.ssh.execute(scoped_command)`) and assert the exact scoped string passed in, per RESEARCH.md's test-map row for SEC-02 ("mock `SSHClient`, assert the exact string sent to `exec_command`").

### `kwargs.get(...)` for optional per-call parameters on agent `execute()`
**Source:** `backend/agent/sub_agents/exploit_agent.py:20`, `cloud_agent.py:17-18`, `iam_agent.py:17`, `endpoint_agent.py:20`, `data_sec_agent.py:20` — all use `kwargs.get("<name>", <default>)` inside `execute(self, target: str, **kwargs)`
**Apply to:** threading `engagement_id` into all 7 sub-agents' `execute()` methods (see per-agent section above) — this is the established idiom for optional per-invocation parameters in this codebase, no new pattern needed.

## No Analog Found

None — every file in scope has at least a partial-match analog in the current codebase or (for `verification_loop.py`) a directly recoverable prior implementation via git history. The weakest matches are:

| File | Role | Data Flow | Reason match is partial |
|------|------|-----------|--------------------------|
| `backend/tools/backends/sandbox.py` (docker-py portion only) | service | file-I/O | No existing code in this repo uses `docker-py`/the Docker SDK — closest precedent (`RuntimeWatchdog`) shells out to the `docker` CLI via `subprocess`, not the SDK. RESEARCH.md Pattern 1/Pitfalls 2-3 are the primary source for the SDK-specific mechanics; the codebase only supplies the surrounding async/error-handling conventions. |
| `docker-compose.yml` (socket mount) | config | — | No existing service in `docker-compose.yml` mounts `/var/run/docker.sock`; the `ml-runtime` service's `security_opt`/`cap_drop`/`network_mode: none` block is the closest precedent for security-conscious container config syntax, but for the opposite direction (locking a container down, not granting it host Docker access). |

## Metadata

**Analog search scope:** `backend/execution/`, `backend/tools/`, `backend/tools/backends/`, `backend/agent/sub_agents/`, `backend/memory/`, `backend/intelligence/`, `backend/verification/`, `backend/session/`, `tests/tools/`, `tests/memory/`, `tests/intelligence/`, `tests/agent/`, git history (`29d02a7^`)
**Files scanned:** 20 (9 read in full for pattern extraction, 1 recovered from git history, plus directory listings of `tests/`, `docker-compose.yml`, `backend/requirements.txt`)
**Pattern extraction date:** 2026-08-29

---

*Phase: 02-security-hardening*
*Patterns mapped: 2026-08-29*
