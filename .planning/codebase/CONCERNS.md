# Codebase Concerns

**Analysis Date:** 2026-05-12

## Critical Security Issues

### Subprocess Sandbox — RCE Risk
**Issue:** Custom tool code execution via direct subprocess without sandboxing

**Files:** `backend/tools/backends/sandbox.py` (lines 71-76)

**Details:**
```python
proc = await asyncio.create_subprocess_exec(
    "python3", str(script_path), target,
    stdout=asyncio.subprocess.PIPE,
    stderr=asyncio.subprocess.PIPE,
    cwd=str(tmp_dir),
)
```

**Risk:** No actual containerization despite class name `SandboxOnDemandBackend`. Code is executed directly on the host Python interpreter. If AI-generated tool code contains malicious payloads or input injection, attacker gains RCE on backend host. Cleanup is basic (file deletion only).

**Impact:** CRITICAL — Complete system compromise possible

**Fix approach:** 
- Implement actual Docker/OCI container isolation with `docker run` instead of subprocess
- Pass user code into container as read-only mount
- Enforce resource limits (memory, CPU, execution time) at container level
- Strip dangerous imports (os.system, subprocess, socket) from generated code before execution

---

### SSH Command Execution — No Working Directory Enforcement
**Issue:** SSH commands execute in shell default directory, not engagement-scoped workdir

**Files:** 
- `backend/execution/ssh_client.py` (lines 27-38)
- `backend/tools/backends/kali_ssh.py` (lines 86-102)

**Details:**
Both files use `client.exec_command(command)` without `cd` prefix or PWD enforcement. Commands like `nmap` or custom tools run in whatever directory Kali's SSH daemon starts in (typically `/root` or home dir). This creates:
- No per-engagement isolation of output files
- Cross-engagement data leakage risk
- Difficult artifact tracking

**Impact:** HIGH — Data isolation violation, audit trail problems

**Fix approach:**
- Prepend `cd /engagements/{engagement_id}/ && ` to all commands
- Create/validate engagement workdir on KaliConnection.connect()
- Store all artifacts under engagement namespace
- Implement workdir cleanup on engagement close

---

### Missing Authentication Middleware
**Issue:** No global auth middleware on API endpoints

**Files:** 
- `backend/app.py` (lines 33-42)
- `backend/api/ws_handler.py` (lines 32-94)
- `backend/auth.py` (lines 1-23)

**Details:**
Token verification exists in `auth.py` but is never applied to REST or WebSocket routes. Only hardcoded in individual handlers. WebSocket auth is checked via query param (line 19: `token = websocket.query_params.get("token", "")`) which can be logged in access logs.

```python
# In app.py — no middleware registered
app.add_middleware(CORSMiddleware, ...)  # Only CORS, no auth

# In ws_handler.py — manual verification
async def websocket_chat(websocket: WebSocket):
    await websocket.accept()  # Accept before auth check
    try:
        await verify_ws_token(websocket)
    except Exception:
        return  # But already accepted
```

**Impact:** HIGH — Unauthenticated access possible; bearer token exposed in logs

**Fix approach:**
- Add authentication middleware that wraps all routes
- Implement OpenAPI security scheme
- Move token to HTTP header (Authorization: Bearer) instead of query param
- Use dependency injection (FastAPI `Security`) on all endpoints
- Never accept WebSocket before verifying token

---

### Invalid Claude Model String
**Issue:** Model name `claude-opus-4-7` does not exist in Anthropic API

**Files:** `backend/config.py` (line 8)

**Details:**
```python
claude_model: str = "claude-opus-4-7"
```

This is silently invalid. Anthropic SDK does not error; instead, it may fall back to Ollama (line 54 in `backend/agent/llm_router.py`):
```python
except Exception as e:
    logger.error(f"Claude error: {e}, falling back to Ollama")
    return await self._ollama_complete(messages)
```

Valid models as of 2026: `claude-3-5-sonnet`, `claude-3-opus`, `claude-3-haiku`.

**Impact:** MEDIUM — All Claude calls fail silently, degrading to Ollama without user awareness

**Fix approach:**
- Update to valid model: `claude-3-5-sonnet-20241022`
- Add model validation on Settings initialization
- Log explicitly when fallback occurs
- Add health check endpoint that tests LLM connectivity

---

## Data Persistence & Reliability

### SQLite Without Write-Ahead Logging
**Issue:** Zero WAL mode configuration in SQLite connections

**Files:**
- `backend/core/event_bus.py` (lines 40-73)
- `backend/intelligence/research_kb.py` (similar pattern)
- `backend/memory/client_profile.py` (similar pattern)

**Details:**
SQLite connections use default journal mode (DELETE) instead of WAL:
```python
self._conn = await asyncio.to_thread(
    sqlite3.connect, str(self._db_path), check_same_thread=False
)
# No PRAGMA journal_mode=WAL
```

This means:
- Readers block writers and vice versa
- Slow concurrent access under load
- No resilience to power loss mid-write
- Event log (DurableEventLog) can lose data on crash

**Impact:** MEDIUM — Data loss risk during failure; poor concurrency

**Fix approach:**
- Add `PRAGMA journal_mode=WAL` after each SQLite connection
- Enable `PRAGMA synchronous=NORMAL` (safer than FULL but faster than OFF)
- Test recovery: kill process mid-write, verify no corruption
- Document retention/cleanup of WAL files

---

### SmartMemory Stub Implementation
**Issue:** Core memory system is non-functional

**Files:** `backend/memory/smart_memory.py` (lines 25-35)

**Details:**
```python
def _load(self):
    if os.path.exists(self.db_path):
        pass  # No-op

def _save(self):
    os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
    # No-op — nothing written
```

The class pretends to persist memory (store/search) but `_load()` and `_save()` do nothing. All data is in-memory only. On backend restart, all memory is lost.

**Impact:** MEDIUM — Engagement context loss across restarts; feature incomplete

**Fix approach:**
- Implement actual SQLite backend with proper schema
- Or switch to vector DB (pgvector, Chroma) for semantic search
- Implement async `_load()` to hydrate in-memory entries from disk
- Implement `_save()` to write entries with embeddings
- Test memory retention across restarts

---

## Architectural & Design Issues

### VerificationLoop — Instance-Level Request Counting (Not Engagement-Scoped)
**Issue:** `_request_counts` dict is per-instance, not per-engagement

**Files:** `backend/verification/verification_loop.py` (lines 39-52, 101)

**Details:**
```python
class VerificationLoop:
    def __init__(self, ...):
        self._request_counts: dict[str, int] = {}  # Instance-level

    async def verify_finding(self, finding_id: str, ...):
        current_count = self._request_counts.get(finding_id, 0)
        if current_count >= self._policy.max_requests_per_finding:
            ...
        self._request_counts[finding_id] = current_count + 1
```

If `VerificationLoop` is instantiated once and reused across multiple engagements (likely given singleton pattern in agent/orchestrator.py), request counts bleed across engagements. Engagement A's findings consume budget for Engagement B.

**Impact:** MEDIUM — Cross-engagement resource quota violation; policy bypass

**Fix approach:**
- Add `engagement_id` parameter to constructor
- Change `_request_counts` to `dict[str, dict[str, int]]` (engagement -> finding -> count)
- Or pass `engagement_scope` and namespace all state by it
- Add test: verify two engagements have independent request budgets

---

### Dead Code: Dual Agent Systems
**Issue:** Two parallel agent systems coexist; old one not actively used

**Files:**
- `backend/agents/` (10 files, ~100KB) — Old implementation
- `backend/agent/` (sub_agents/, orchestrator, llm_router, etc.) — New system
- `backend/main.py` (846 lines) — Entrypoint for old system; current entrypoint is `backend/app.py` (51 lines)

**Details:**
- `backend/agents/cloud_agent.py`, `exploit_agent.py`, etc. are imported nowhere
- `backend/main.py` wires them all up but is not used (app starts from `backend/app.py`)
- Old system uses different agent pattern, permission model, and tool executor
- Maintenance burden: bug fixes must be applied to both systems

**Impact:** MEDIUM — Confusion, maintenance overhead, stale security patches

**Fix approach:**
- Audit which system is actually running in production (likely `backend/app.py`)
- Deprecate and remove old `backend/agents/` directory
- Remove `backend/main.py` or document it as historical
- Update STRUCTURE.md to reflect single system

---

### Orphaned Frontend Component
**Issue:** `frontend/components/ChatPane.tsx` exists but not imported anywhere

**Files:**
- `frontend/components/ChatPane.tsx` (exists, 50+ lines)
- `frontend/src/App.jsx` (defines `ChatPanel` at line 1015; no reference to ChatPane)

**Details:**
`ChatPane.tsx` is a TypeScript/Socket.IO component that is never imported or used. `App.jsx` defines its own `ChatPanel` function instead. Component imports socket.io but the backend uses native WebSockets.

**Impact:** LOW — Dead code, potential confusion for developers

**Fix approach:**
- Delete `frontend/components/ChatPane.tsx` or integrate it properly
- Verify `frontend/src/App.jsx` ChatPanel is correct implementation
- Remove unused socket.io imports if not needed

---

### WebSocket Handler Creates New Orchestrator Per Message
**Issue:** Stateless instantiation causes loss of context and state

**Files:** `backend/api/ws_handler.py` (line 71)

**Details:**
```python
elif msg_type == "chat":
    from backend.agent.orchestrator import Orchestrator
    orchestrator = Orchestrator()  # New instance every message
```

Each incoming chat message creates a fresh Orchestrator (which creates new LLMRouter, EngineRouter, etc.). No state is retained between messages in the same session. If orchestrator had caches, learning, or stateful routing logic, it would be reset per message.

**Impact:** MEDIUM — Performance overhead; lost opportunity for learning/optimization

**Fix approach:**
- Create Orchestrator once per session (in session_store or session object)
- Pass it into WebSocket handler
- Reuse across all messages in session
- Verify memory/cleanup on session expiration

---

### Large Monolithic Files
**Issue:** Several files exceed 500 lines; harder to test and maintain

**Files:**
- `backend/main.py` (846 lines) — Entire old system wired up
- `backend/core/omx.py` (569 lines) — Complex orchestration logic
- `backend/intelligence/custom_tool_generator.py` (526 lines) — Tool generation pipeline

**Impact:** LOW-MEDIUM — High cyclomatic complexity, harder to test, harder to refactor

**Fix approach:**
- `backend/main.py` — Delete if unused (see Dead Code section)
- `backend/core/omx.py` — Split into omx_planner.py, omx_executor.py, omx_models.py
- `backend/intelligence/custom_tool_generator.py` — Extract AST analyzer, type checker, code generator into separate modules

---

## Missing Critical Features

### No Engagement Working Directory Isolation
**Issue:** No per-engagement temp/output directory structure

**Details:**
When an engagement runs, artifacts (tool output, reports, logs) are not organized by engagement. All temporary files go to system temp or same directory. Makes cleanup, replay, and audit trails difficult.

**Impact:** MEDIUM — Audit/compliance issue; difficult recovery

**Fix approach:**
- Create `data/engagements/{engagement_id}/` on engagement creation
- Store all tool output, logs, and reports there
- Implement cleanup policy (retention for N days, then purge)
- Verify no cross-engagement file access

---

### No Automatic Backup/Retention Policy
**Issue:** SQLite event log and databases have no backup or archive strategy

**Details:**
- Event log at `data/events/event_log.db` grows unbounded
- No pruning beyond 24h mention in comments (line 25: `PRUNE_AGE_HOURS = 24`)
- No backup mechanism documented or implemented
- If DB corrupts, all event history is lost

**Impact:** MEDIUM — Compliance/audit issue; data loss risk

**Fix approach:**
- Implement automated daily backup to secondary location (S3, network share)
- Document retention policy in ARCHITECTURE.md
- Add cleanup job to prune events older than policy
- Test recovery from backup

---

## Integration & Dependency Risks

### Paramiko Auto-Add Host Key Policy (No SSH Key Verification)
**Issue:** SSH connections accept unknown hosts automatically

**Files:** 
- `backend/execution/ssh_client.py` (line 16)
- `backend/tools/backends/kali_ssh.py` (line 53)

**Details:**
```python
client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
```

Accepts any SSH host without verification. Vulnerable to MITM attacks if Kali host is compromised or attacker intercepts connection.

**Impact:** MEDIUM — MITM/credential theft risk

**Fix approach:**
- Load known_hosts or pinned host keys instead
- Use `paramiko.WarningPolicy()` or `RejectPolicy()` and fail explicitly
- Store expected Kali host key in config/secrets
- Add health check that verifies host key matches

---

### Hardcoded Bearer Token in Settings
**Issue:** Default token is development placeholder

**Files:** `backend/config.py` (line 5)

**Details:**
```python
bearer_token: str = "dev-token"
```

If `.env` is not present, defaults to "dev-token". If deployed with default, anyone can access the API.

**Impact:** HIGH — Production access control bypass

**Fix approach:**
- Remove default value; raise error if not in .env
- Generate random token on first startup if missing
- Document that bearer_token MUST be set in .env
- Audit all deployment scripts to verify .env is present

---

## Testing & Quality Gaps

### No Integration Test Coverage for WebSocket Reconnection
**Issue:** WebSocket reconnection logic in frontend (`frontend/src/App.jsx` lines 66-180) has no tests

**Files:** `frontend/src/App.jsx`

**Details:**
Exponential backoff, lastSeq tracking, event replay logic are all in frontend but not tested. If sequence number tracking breaks, events are silently lost.

**Impact:** LOW-MEDIUM — Stale UI, lost events in production

**Fix approach:**
- Add Cypress or Playwright E2E test for reconnect scenario
- Simulate WebSocket close mid-message
- Verify lastSeq is preserved across reconnect
- Verify event replay works

---

### No Mocking of External SSH Service
**Issue:** Tests may connect to real Kali host if configured

**Files:** `backend/tests/test_kali_connection_mgr.py` (466 lines)

**Details:**
Connection pool tests import real `KaliConnectionManager`. If KALI_HOST is reachable during test runs, tests hit real system instead of mock. Tests should use mock SSH server.

**Impact:** LOW — Brittle tests; test environment dependency

**Fix approach:**
- Use `unittest.mock.patch` or `responses` library for SSH mocking
- Create fixture with FakeSSHServer or paramiko.Transport mock
- Ensure tests pass without network access

---

## Performance Bottlenecks

### EventBus Prune Loop Not Optimized
**Issue:** Pruning old events requires full table scan + delete

**Files:** `backend/core/event_bus.py` (implied; prune logic not shown but mentioned)

**Details:**
No documented index on `published_at` column. Prune query likely scans entire table. On high-volume systems, this becomes slow.

**Impact:** LOW — Startup/scheduled prune may be slow

**Fix approach:**
- Add index on `published_at` column
- Use `DELETE WHERE published_at < ?` with prepared statement
- Consider archiving old events to separate table instead of deleting

---

### LLM Router Fallback Path Logs Are Unstructured
**Issue:** Claude errors trigger log but don't expose error details to user

**Files:** `backend/agent/llm_router.py` (line 54)

**Details:**
```python
except Exception as e:
    logger.error(f"Claude error: {e}, falling back to Ollama")
    return await self._ollama_complete(messages)
```

If Claude fails, user gets Ollama response silently. No indication of downgrade. If error is quota/auth, user may not realize their API key is wrong.

**Impact:** MEDIUM — Hard to debug production issues

**Fix approach:**
- Add structured logging with error codes
- Publish LLM_FALLBACK event to EventBus
- Return error metadata to client (which model was used, why fallback)
- Add metrics: track fallback rate

---

## Configuration & Hardening

### Ollama Host Hardcoded to Localhost
**Issue:** Ollama inference not exposed to remote deployments properly

**Files:** `backend/config.py` (line 7)

**Details:**
```python
ollama_host: str = "http://localhost:11434"
```

Assumes Ollama is on same host. In cloud deployment, Ollama may be on different service. Current default breaks in containerized environments unless properly overridden in .env.

**Impact:** LOW-MEDIUM — Deployment friction

**Fix approach:**
- Default to environment variable with fallback to sensible cloud default
- Document in deployment guide
- Add health check for Ollama connectivity at startup

---

### CORS Allows All Origins
**Issue:** Overly permissive CORS configuration

**Files:** `backend/app.py` (lines 33-39)

**Details:**
```python
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)
```

Allows any origin to make requests. Combined with weak auth (hardcoded token), exposes API to attacks.

**Impact:** MEDIUM — CSRF/XSS attack surface

**Fix approach:**
- Restrict `allow_origins` to specific frontend URLs (or whitelist in config)
- Consider removing `allow_credentials=True` if not needed
- Use SameSite cookie attributes on any session cookies
- Document CORS policy in security guide

---

## Summary Table

| Issue | Severity | Type | Fix Effort |
|-------|----------|------|-----------|
| Subprocess RCE sandbox | CRITICAL | Security | High |
| SSH command workdir | HIGH | Security | Medium |
| Missing auth middleware | HIGH | Security | Medium |
| Invalid Claude model | MEDIUM | Reliability | Low |
| SQLite no WAL | MEDIUM | Reliability | Low |
| SmartMemory stub | MEDIUM | Feature | Medium |
| VerificationLoop scoping | MEDIUM | Architecture | Medium |
| Dead agent code | MEDIUM | Maintainability | Medium |
| Paramiko host key policy | MEDIUM | Security | Low |
| Bearer token default | HIGH | Security | Low |
| Hardcoded localhost | LOW | Config | Low |
| CORS too permissive | MEDIUM | Security | Low |
| Orphaned frontend component | LOW | Code quality | Low |
| WebSocket orchestrator per-message | MEDIUM | Performance | Medium |
| Large monolithic files | LOW | Maintainability | Medium |

---

*Concerns audit: 2026-05-12*
