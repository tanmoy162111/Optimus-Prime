---
phase: 02-security-hardening
reviewed: 2026-08-29T10:07:39Z
depth: standard
files_reviewed: 20
files_reviewed_list:
  - backend/agent/sub_agents/cloud_agent.py
  - backend/agent/sub_agents/data_sec_agent.py
  - backend/agent/sub_agents/endpoint_agent.py
  - backend/agent/sub_agents/exploit_agent.py
  - backend/agent/sub_agents/iam_agent.py
  - backend/agent/sub_agents/recon_agent.py
  - backend/agent/sub_agents/scan_agent.py
  - backend/execution/shell_manager.py
  - backend/execution/ssh_client.py
  - backend/intelligence/research_kb.py
  - backend/memory/client_profile.py
  - backend/requirements.txt
  - backend/tools/backends/sandbox.py
  - backend/verification/verification_loop.py
  - docker-compose.yml
  - tests/execution/test_shell_manager_scoping.py
  - tests/intelligence/test_research_kb_wal.py
  - tests/memory/test_client_profile.py
  - tests/tools/test_sandbox_docker.py
  - tests/verification/test_verification_loop.py
findings:
  critical: 2
  warning: 5
  info: 2
  total: 9
status: issues_found
---

# Phase 2: Code Review Report

**Reviewed:** 2026-08-29T10:07:39Z
**Depth:** standard
**Files Reviewed:** 20
**Status:** issues_found

## Summary

Reviewed the SEC-01 (Docker sandbox isolation), SEC-02 (per-engagement Kali workdir scoping), DATA-01 (SQLite WAL mode), and DATA-02 (VerificationLoop budget stub) deliverables for Phase 2.

The `VerificationLoop` stub (DATA-02) is small, correct, and well-tested — no issues found there. The WAL pragma additions to `research_kb.py`/`client_profile.py` are correctly placed (applied on every new connection, matching the documented "synchronous does not persist" pitfall).

Two blockers were found. First, `SSHClient.connect()` awaits `paramiko.SSHClient.connect()`, which is a synchronous method that returns `None` — `await None` raises `TypeError` at runtime, meaning **every** SSH command execution (including all 7 sub-agents this phase just wired for workdir scoping) will crash before a single command reaches Kali. This is pre-existing (not touched by this diff beyond adding the `engagement_id` constructor param), but it directly negates the value of this phase's SEC-02 work: the scoping prefix is correct, but the transport underneath it cannot currently run. Second, the new `SandboxOnDemandBackend.run_tool_code()` (SEC-01) takes an unsanitized `tool_name` and uses it to build both a host-side file path and a Docker tar-archive entry name with no validation — a `tool_name` containing `../` segments is a path-traversal write primitive on the host and a tar-slip risk inside the sandbox container.

The docker-compose Docker-socket mount (DooD, D-10) is a locked, operator-approved decision and is not re-flagged here. The pre-existing unescaped f-string command interpolation in the 7 sub-agents (T-02-06) is a documented, explicitly-accepted risk in the phase's own threat register and is likewise not re-flagged.

## Critical Issues

### CR-01: `SSHClient.connect()` awaits a synchronous paramiko call — every SSH execution crashes

**File:** `backend/execution/ssh_client.py:19-24`
**Issue:** `paramiko.SSHClient.connect()` is a blocking, synchronous method — it is not a coroutine and does not return an awaitable (it returns `None`). The code does:
```python
await self.client.connect(
    hostname=config.settings.kali_host,
    port=config.settings.kali_port,
    username=config.settings.kali_user,
    password=config.settings.kali_password,
)
```
Awaiting the `None` result of a synchronous call raises `TypeError: object NoneType can't be used in 'await' expression` at runtime. Every one of this phase's 7 sub-agents now constructs `SSHClient(engagement_id=...)` and calls `shell.execute()` → `ssh.execute()` → `connect()`, so the SEC-02 scoping work is layered on top of a transport that cannot currently connect at all. None of the new/updated tests catch this because `tests/execution/test_shell_manager_scoping.py` mocks `SSHClient` entirely — there is no integration test that exercises the real `paramiko` call path.
**Fix:** Run the blocking call in a thread (matching the pattern already used elsewhere in this same phase, e.g. `research_kb.py`'s `asyncio.to_thread(sqlite3.connect, ...)`):
```python
await asyncio.to_thread(
    self.client.connect,
    hostname=config.settings.kali_host,
    port=config.settings.kali_port,
    username=config.settings.kali_user,
    password=config.settings.kali_password,
)
```
(`client.exec_command()` in `execute()` a few lines below is the same kind of blocking call and should get the same treatment while this file is being fixed, though that one doesn't crash — it just blocks the event loop.)

### CR-02: Unsanitized `tool_name` enables path traversal / tar-slip in `SandboxOnDemandBackend`

**File:** `backend/tools/backends/sandbox.py:88-90, 155-174, 195-197`
**Issue:** `run_tool_code()` builds a host-side path directly from the caller-supplied `tool_name` with no validation:
```python
tmp_dir = Path(tempfile.mkdtemp(prefix="optimus_sandbox_"))
script_path = tmp_dir / f"{tool_name}.py"
script_path.write_text(code)
```
`pathlib`'s `/` operator does not sanitize `..` segments — a `tool_name` such as `"../../../../home/user/.ssh/authorized_keys"` (or any absolute-looking segment) causes `write_text()` to write attacker-controlled `code` content outside `tmp_dir`, anywhere the backend process's filesystem permissions allow. The same unsanitized `tool_name` is also used to build the Docker tar-archive entry name in `_build_script_tar()`:
```python
info = tarfile.TarInfo(name=f"work/{tool_name}.py")
```
which is streamed into the container via `put_archive("/", tar_bytes)` — a `tool_name` with `../` segments is a classic tar-slip pattern that may let the extracted entry land outside the intended `/work/` directory inside the sandboxed container, depending on the Docker/containerd version's own tar-extraction hardening (which should not be relied on as the only defense).
This backend has no live caller yet (D-02), so it isn't reachable via the chat UI today, but the code itself — which is what SEC-01 was scoped to fix — ships with this write primitive, and any future caller (e.g. the deferred `custom_tool_generator.py` wiring) inherits it silently.
**Fix:** Validate `tool_name` against an allowlist pattern before using it in either path, e.g.:
```python
import re
_SAFE_TOOL_NAME = re.compile(r"^[A-Za-z0-9_-]{1,64}$")

if not _SAFE_TOOL_NAME.match(tool_name):
    return {"status": "error", "error": f"Invalid tool_name: {tool_name!r}"}
```
applied at the top of `run_tool_code()` before either `script_path` or the tar entry name is constructed.

## Warnings

### WR-01: Sandbox writes untrusted code to local disk for no reason (also the CR-02 vector)

**File:** `backend/tools/backends/sandbox.py:88-90`
**Issue:** `run_tool_code()` writes `code` to `script_path` on local disk (`tmp_dir / f"{tool_name}.py"`), but `_run_sync()`/`_build_script_tar()` never read `script_path` — they re-derive the tar archive directly from the `code` string parameter. `tmp_dir`/`script_path` are otherwise unused (only referenced again in the `finally` cleanup block). This is dead code that also happens to be the write primitive described in CR-02.
**Fix:** Remove the unused host-side write entirely (drop `tmp_dir`/`script_path`/the `write_text` call and the matching cleanup), since `_build_script_tar()` already has everything it needs from the `code`/`tool_name` arguments directly.

### WR-02: Sandbox container lacks the hardening flags used elsewhere in this same compose file

**File:** `backend/tools/backends/sandbox.py:194-200`
**Issue:** `_run_sync()` creates the ephemeral container with only `network_mode="none"` and `mem_limit="256m"`:
```python
container = client.containers.create(
    SANDBOX_IMAGE,
    command=["python3", f"/work/{tool_name}.py", target],
    network_mode="none",
    mem_limit="256m",
)
```
It runs as root by default with the full default capability set and a writable root filesystem. The module docstring for D-01 describes this as "real Docker container isolation," and this same repository's `ml-runtime` service in `docker-compose.yml` already establishes the intended hardening baseline for untrusted-code execution (`cap_drop: ALL`, `security_opt: no-new-privileges:true`, `read_only: true`, non-root `user`). The sandbox — which exists specifically to run LLM-generated, untrusted tool code — has none of these.
**Fix:** Add the same defense-in-depth flags docker-py supports directly on `containers.create()`:
```python
container = client.containers.create(
    SANDBOX_IMAGE,
    command=["python3", f"/work/{tool_name}.py", target],
    network_mode="none",
    mem_limit="256m",
    cap_drop=["ALL"],
    security_opt=["no-new-privileges:true"],
    read_only=True,
    user="nobody",
)
```
(A writable `/tmp` may be needed via a `tmpfs` mount if the executed tool code needs scratch space under `read_only=True`.)

### WR-03: `engagement_id` silently defaults to `"default"` with no upstream wiring or format validation

**File:** `backend/execution/shell_manager.py:10-13`, and all 7 `backend/agent/sub_agents/*.py:` construction sites
**Issue:** D-05 required threading a real `engagement_id` from `EngagementSession` down into `SSHClient`/`ShellManager`. What actually shipped is `engagement_id = kwargs.get("engagement_id", "default")` inside each sub-agent's `execute()` — and nothing in `backend/agent/orchestrator.py` or `backend/agent/engine_router.py` currently calls any sub-agent's `execute()` at all, so this is honestly unreachable today (confirmed: no `ReconAgent()`/`ScanAgent()`/etc. instantiation exists anywhere under `backend/`). The risk is latent rather than live: when this gets wired up in a future phase, any call site that forgets to pass `engagement_id` explicitly will silently land in `/engagements/default/` and collide with every other caller that also forgot — defeating SEC-02's entire isolation guarantee with no error, warning, or log line. Separately, `ShellManager._workdir = f"/engagements/{engagement_id}"` is interpolated into a double-quoted shell string (`mkdir -p "{workdir}" && cd "{workdir}" && ...`) with no validation that `engagement_id` cannot itself contain a `"` — the SEC-02 threat model (T-02-05) asserts "`engagement_id` originates from `EngagementSession`, not user input," but nothing in the code enforces or checks that assumption at the point of use.
**Fix:** At minimum, raise instead of silently defaulting when `engagement_id` is missing (fail loud rather than silently collide):
```python
engagement_id = kwargs.get("engagement_id")
if not engagement_id:
    raise ValueError("engagement_id is required for scoped Kali execution")
```
and/or validate the format in `ShellManager.__init__` (e.g. `re.fullmatch(r"[A-Za-z0-9_-]+", engagement_id)`) so a malformed id fails fast instead of producing a broken or exploitable shell prefix.

### WR-04: Check-then-act connection init race risks a leaked `sqlite3.Connection`

**File:** `backend/intelligence/research_kb.py:104-105, 171-172, 200-202, 208-211, 219-222`; `backend/memory/client_profile.py:108-109, 138-139, 151-152`
**Issue:** Every public method follows the same pattern:
```python
if self._conn is None:
    await self.initialize()
```
This check happens *outside* `self._lock` (the lock is only acquired inside `initialize()` itself). If two coroutines call e.g. `ingest()`/`save_profile()` concurrently before the connection exists, both observe `self._conn is None`, both call `initialize()`, and both proceed to `sqlite3.connect()` — the second call's connection silently replaces `self._conn`, orphaning the first connection object (never closed, never referenced again). This directly undermines DATA-01's stated goal ("without concurrent DB writes corrupting findings") for the one code path — first-use initialization — that isn't already protected by the lock.
**Fix:** Guard the check itself with the lock, or use a double-checked pattern:
```python
async def _ensure_conn(self) -> None:
    if self._conn is not None:
        return
    async with self._lock:
        if self._conn is not None:
            return
        self._conn = await asyncio.to_thread(...)
        ...
```
and call `await self._ensure_conn()` from every public method instead of the current unguarded `if self._conn is None: await self.initialize()`.

### WR-05: Naive "last two labels" base-domain heuristic mismatches multi-label public suffixes

**File:** `backend/memory/client_profile.py:210-215`
**Issue:**
```python
query_parts = query.split(".")
domain_parts = domain_lower.split(".")
if len(query_parts) >= 2 and len(domain_parts) >= 2:
    if query_parts[-2:] == domain_parts[-2:]:
        best = max(best, 0.7)
```
This treats the last two dot-separated labels as the "base domain." For any registrable domain under a multi-label public suffix (e.g. `.co.uk`, `.com.au`, `.org.uk`), two completely unrelated clients' domains share the same last-two-labels (`co`, `uk`), so `foo.co.uk` and `bar.co.uk` score a false-positive 0.7 "partial domain match" against each other even though they are unrelated organizations. Since `ClientProfileDB` is a per-client data store (recurring weaknesses, remediation history, report preferences), an auto-match suggestion mixing up two different clients under a shared public suffix is a real (if "suggestion only, operator confirms") data-attribution risk.
**Fix:** Either drop the last-two-labels heuristic for domains with more than 2 labels total unless using a real public-suffix list (e.g. the `publicsuffix2` / `tldextract` package), or at minimum guard against the known multi-label-suffix case:
```python
MULTI_LABEL_SUFFIXES = {"co.uk", "com.au", "org.uk", "gov.uk", "co.jp", ...}
base = ".".join(domain_parts[-2:])
if base in MULTI_LABEL_SUFFIXES:
    continue  # last two labels alone are not a valid registrable-domain signal here
```

## Info

### IN-01: `payload_crafter` declared as an allowed tool but never invoked

**File:** `backend/agent/sub_agents/exploit_agent.py:9`
**Issue:** `allowed_tools=["sqlmap", "dalfox", "commix", "ffuf", "msfconsole", "payload_crafter"]` lists `payload_crafter`, but `execute()` never builds a `payload_crafter` command (only `sqlmap`/`dalfox`/`commix`/`ffuf` branches exist, with `msfconsole` unused too).
**Fix:** Either wire an `exploit_type == "payload_crafter"` / `"msfconsole"` branch, or drop the unused entries from `allowed_tools` so the declared capability list matches what `execute()` can actually do.

### IN-02: Redundant local `import re` instead of a single module-level import

**File:** `backend/agent/sub_agents/data_sec_agent.py:73, 116`
**Issue:** `import re` is repeated inside both `_scan_tls()` and `_scan_pii()` rather than imported once at module level (the rest of the file's imports, and the project's own convention per `CLAUDE.md`, favor top-of-file imports).
**Fix:** Move `import re` to the top of the file alongside the (implicit) module imports and remove both local copies.

---

_Reviewed: 2026-08-29T10:07:39Z_
_Reviewer: Claude (gsd-code-reviewer)_
_Depth: standard_
