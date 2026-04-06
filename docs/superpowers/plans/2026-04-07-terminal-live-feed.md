# Terminal Live Feed Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace the dashboard `EventFeed` panel with a `TerminalPanel` that streams real-time Kali SSH command output and backend Python logs, with a manual operator shell input bar.

**Architecture:** A new `TerminalBroadcaster` singleton fans out structured JSON terminal events to all `/ws/terminal` WebSocket clients. The existing `KaliConnectionManager.execute()` method is wrapped to publish every command's stdout/stderr after it returns. A `TerminalLogHandler` feeds Python log records into the same broadcaster. The frontend `EventFeed` component is replaced wholesale by `TerminalPanel`.

**Tech Stack:** Python 3.12, FastAPI WebSockets, pytest (asyncio_mode=auto), React 18, Tailwind CSS, Vite

---

## File Map

| File | Action | Responsibility |
|---|---|---|
| `backend/core/terminal_broadcaster.py` | **Create** | `TerminalBroadcaster` (WebSocket fan-out) + `TerminalLogHandler` (logging bridge) |
| `backend/tools/backends/kali_ssh.py` | **Modify** | Accept optional `terminal_broadcaster` in `__init__`; publish stdout/stderr in `execute()` |
| `backend/main.py` | **Modify** | Register broadcaster at startup, attach log handler, add `/ws/terminal` + `POST /terminal/exec` |
| `frontend/src/App.jsx` | **Modify** | Replace `EventFeed` with `TerminalPanel` (+ `TerminalLine`, `TerminalInput` sub-components) |
| `backend/tests/test_terminal_broadcaster.py` | **Create** | Unit tests for broadcaster fan-out, log handler, and exec endpoint |

---

## Task 1: Create `TerminalBroadcaster` and `TerminalLogHandler`

**Files:**
- Create: `backend/core/terminal_broadcaster.py`
- Create: `backend/tests/test_terminal_broadcaster.py`

- [ ] **Step 1.1: Write failing tests for `TerminalBroadcaster`**

Create `backend/tests/test_terminal_broadcaster.py`:

```python
"""Tests for TerminalBroadcaster and TerminalLogHandler."""
from __future__ import annotations

import asyncio
import logging
from unittest.mock import AsyncMock, MagicMock

import pytest

from backend.core.terminal_broadcaster import TerminalBroadcaster, TerminalLogHandler


class TestTerminalBroadcaster:
    async def test_publish_fans_out_to_all_connections(self):
        broadcaster = TerminalBroadcaster()
        ws1 = AsyncMock()
        ws2 = AsyncMock()
        broadcaster._connections = [ws1, ws2]

        event = {"type": "kali_output", "data": "hello"}
        await broadcaster.publish(event)

        ws1.send_json.assert_awaited_once_with(event)
        ws2.send_json.assert_awaited_once_with(event)

    async def test_publish_skips_failed_connections(self):
        broadcaster = TerminalBroadcaster()
        ws_good = AsyncMock()
        ws_bad = AsyncMock()
        ws_bad.send_json.side_effect = Exception("closed")
        broadcaster._connections = [ws_bad, ws_good]

        await broadcaster.publish({"type": "kali_output", "data": "x"})

        ws_good.send_json.assert_awaited_once()

    async def test_connect_adds_websocket(self):
        broadcaster = TerminalBroadcaster()
        ws = AsyncMock()
        await broadcaster.connect(ws)
        assert ws in broadcaster._connections

    def test_disconnect_removes_websocket(self):
        broadcaster = TerminalBroadcaster()
        ws = MagicMock()
        broadcaster._connections = [ws]
        broadcaster.disconnect(ws)
        assert ws not in broadcaster._connections

    def test_disconnect_noop_if_not_connected(self):
        broadcaster = TerminalBroadcaster()
        ws = MagicMock()
        broadcaster.disconnect(ws)  # must not raise


class TestTerminalLogHandler:
    async def test_emit_publishes_backend_log_event(self):
        broadcaster = TerminalBroadcaster()
        broadcaster.publish = AsyncMock()

        handler = TerminalLogHandler(broadcaster)
        record = logging.LogRecord(
            name="backend.agents.recon_agent",
            level=logging.INFO,
            pathname="",
            lineno=0,
            msg="ReconAgent dispatching nmap",
            args=(),
            exc_info=None,
        )
        handler.emit(record)

        # give the event loop a tick to run the coroutine
        await asyncio.sleep(0)

        broadcaster.publish.assert_awaited_once()
        call_args = broadcaster.publish.call_args[0][0]
        assert call_args["type"] == "backend_log"
        assert call_args["source"] == "backend"
        assert call_args["level"] == "INFO"
        assert call_args["logger"] == "backend.agents.recon_agent"
        assert "ReconAgent dispatching nmap" in call_args["data"]

    async def test_emit_does_not_raise_on_broadcaster_error(self):
        broadcaster = TerminalBroadcaster()
        broadcaster.publish = AsyncMock(side_effect=Exception("boom"))

        handler = TerminalLogHandler(broadcaster)
        record = logging.LogRecord(
            name="backend.test",
            level=logging.ERROR,
            pathname="",
            lineno=0,
            msg="error",
            args=(),
            exc_info=None,
        )
        handler.emit(record)  # must not raise
        await asyncio.sleep(0)
```

- [ ] **Step 1.2: Run tests to verify they fail**

```bash
cd C:/Projects/Optimus
pytest backend/tests/test_terminal_broadcaster.py -v
```

Expected: `ModuleNotFoundError: No module named 'backend.core.terminal_broadcaster'`

- [ ] **Step 1.3: Implement `backend/core/terminal_broadcaster.py`**

```python
"""TerminalBroadcaster — fans out terminal events to all /ws/terminal clients.

Two public classes:
  TerminalBroadcaster  — WebSocket connection manager + event fan-out
  TerminalLogHandler   — logging.Handler that feeds records into the broadcaster
"""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from fastapi import WebSocket

logger = logging.getLogger(__name__)


class TerminalBroadcaster:
    """Singleton that fans out structured terminal events to all /ws/terminal clients."""

    def __init__(self) -> None:
        self._connections: list[WebSocket] = []

    async def connect(self, ws: WebSocket) -> None:
        """Accept and register a new WebSocket connection."""
        await ws.accept()
        self._connections.append(ws)

    def disconnect(self, ws: WebSocket) -> None:
        """Remove a WebSocket connection (no-op if not registered)."""
        if ws in self._connections:
            self._connections.remove(ws)

    async def publish(self, event: dict) -> None:
        """Fan out an event to all registered connections, silently dropping dead ones."""
        dead: list[WebSocket] = []
        for ws in list(self._connections):
            try:
                await ws.send_json(event)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(ws)


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class TerminalLogHandler(logging.Handler):
    """Feeds Python log records into TerminalBroadcaster as backend_log events.

    Attach to the 'backend' logger in main.py startup:
        handler = TerminalLogHandler(broadcaster)
        handler.setLevel(logging.DEBUG)
        logging.getLogger("backend").addHandler(handler)
    """

    def __init__(self, broadcaster: TerminalBroadcaster) -> None:
        super().__init__()
        self._broadcaster = broadcaster

    def emit(self, record: logging.LogRecord) -> None:
        """Publish the log record as a backend_log event. Never raises."""
        try:
            event = {
                "type": "backend_log",
                "source": "backend",
                "level": record.levelname,
                "logger": record.name,
                "data": self.format(record) if self.formatter else record.getMessage(),
                "ts": _now_iso(),
            }
            # schedule the coroutine on the running event loop
            try:
                loop = asyncio.get_running_loop()
                loop.create_task(self._broadcaster.publish(event))
            except RuntimeError:
                pass  # no running loop (e.g., during tests without async context)
        except Exception:
            self.handleError(record)
```

- [ ] **Step 1.4: Run tests to verify they pass**

```bash
cd C:/Projects/Optimus
pytest backend/tests/test_terminal_broadcaster.py -v
```

Expected: all 7 tests **PASSED**

- [ ] **Step 1.5: Commit**

```bash
cd C:/Projects/Optimus
git add backend/core/terminal_broadcaster.py backend/tests/test_terminal_broadcaster.py
git commit -m "feat: add TerminalBroadcaster and TerminalLogHandler"
```

---

## Task 2: Wire `TerminalBroadcaster` into `KaliConnectionManager`

**Files:**
- Modify: `backend/tools/backends/kali_ssh.py` — `__init__` (line ~60) and `execute()` (line ~244)
- Modify: `backend/tests/test_kali_connection_mgr.py` — add broadcaster broadcast assertion

- [ ] **Step 2.1: Write a failing test for the broadcast hook**

Add this test class to `backend/tests/test_kali_connection_mgr.py` (append at end of file):

```python
class TestKaliConnectionManagerBroadcast:
    """Verify that execute() publishes stdout/stderr to TerminalBroadcaster."""

    async def test_execute_broadcasts_stdout(self):
        from unittest.mock import AsyncMock, MagicMock, patch
        from backend.core.terminal_broadcaster import TerminalBroadcaster

        broadcaster = TerminalBroadcaster()
        broadcaster.publish = AsyncMock()

        mgr = KaliConnectionManager(
            host="kali", port=22, username="root", password="optimus",
            event_bus=MagicMock(),
            terminal_broadcaster=broadcaster,
        )

        mock_conn = MagicMock()
        mock_conn.exec_command.return_value = ("scan complete\n", "", 0)
        mgr._pool = [mock_conn]
        mgr._semaphore = asyncio.Semaphore(3)

        mock_spec = MagicMock()
        mock_spec.timeout_seconds = 30

        with patch.object(mgr, "_get_healthy_connection", return_value=mock_conn):
            result = await mgr.execute(
                tool_name="nmap",
                tool_input={"target": "10.0.0.1"},
                tool_spec=mock_spec,
            )

        assert result["stdout"] == "scan complete\n"

        broadcaster.publish.assert_awaited()
        call_event = broadcaster.publish.call_args_list[0][0][0]
        assert call_event["type"] == "kali_output"
        assert call_event["source"] == "kali"
        assert call_event["tool"] == "nmap"
        assert call_event["stream"] == "stdout"
        assert "scan complete" in call_event["data"]

    async def test_execute_broadcasts_stderr_when_non_empty(self):
        from unittest.mock import AsyncMock, MagicMock, patch
        from backend.core.terminal_broadcaster import TerminalBroadcaster

        broadcaster = TerminalBroadcaster()
        broadcaster.publish = AsyncMock()

        mgr = KaliConnectionManager(
            host="kali", port=22, username="root", password="optimus",
            event_bus=MagicMock(),
            terminal_broadcaster=broadcaster,
        )

        mock_conn = MagicMock()
        mock_conn.exec_command.return_value = ("", "permission denied\n", 1)
        mgr._pool = [mock_conn]
        mgr._semaphore = asyncio.Semaphore(3)

        mock_spec = MagicMock()
        mock_spec.timeout_seconds = 30

        with patch.object(mgr, "_get_healthy_connection", return_value=mock_conn):
            await mgr.execute(
                tool_name="nmap",
                tool_input={"target": "10.0.0.1"},
                tool_spec=mock_spec,
            )

        calls = [c[0][0] for c in broadcaster.publish.call_args_list]
        stderr_calls = [c for c in calls if c.get("stream") == "stderr"]
        assert len(stderr_calls) == 1
        assert "permission denied" in stderr_calls[0]["data"]

    async def test_execute_without_broadcaster_does_not_raise(self):
        """broadcaster=None (default) must be backward-compatible."""
        from unittest.mock import MagicMock, patch

        mgr = KaliConnectionManager(
            host="kali", port=22, username="root", password="optimus",
            event_bus=MagicMock(),
        )

        mock_conn = MagicMock()
        mock_conn.exec_command.return_value = ("ok\n", "", 0)
        mgr._pool = [mock_conn]
        mgr._semaphore = asyncio.Semaphore(3)

        mock_spec = MagicMock()
        mock_spec.timeout_seconds = 30

        with patch.object(mgr, "_get_healthy_connection", return_value=mock_conn):
            result = await mgr.execute(
                tool_name="nmap",
                tool_input={"target": "10.0.0.1"},
                tool_spec=mock_spec,
            )

        assert result["status"] == "success"
```

- [ ] **Step 2.2: Run tests to verify they fail**

```bash
cd C:/Projects/Optimus
pytest backend/tests/test_kali_connection_mgr.py::TestKaliConnectionManagerBroadcast -v
```

Expected: `TypeError` — `KaliConnectionManager.__init__` does not accept `terminal_broadcaster`

- [ ] **Step 2.3: Modify `KaliConnectionManager.__init__` to accept broadcaster**

Open `backend/tools/backends/kali_ssh.py`. Find the `__init__` method of `KaliConnectionManager` (search for `def __init__`). Add `terminal_broadcaster` as an optional parameter and store it:

```python
# BEFORE (find the __init__ signature — it looks like this):
def __init__(
    self,
    host: str,
    port: int,
    username: str,
    password: str,
    event_bus: Any,
) -> None:
    self._host = host
    # ... rest of existing init body ...

# AFTER — add terminal_broadcaster parameter (keep all existing lines unchanged):
def __init__(
    self,
    host: str,
    port: int,
    username: str,
    password: str,
    event_bus: Any,
    terminal_broadcaster: Any | None = None,
) -> None:
    self._terminal_broadcaster = terminal_broadcaster
    self._host = host
    # ... rest of existing init body unchanged ...
```

- [ ] **Step 2.4: Add broadcast calls inside `execute()`**

In `backend/tools/backends/kali_ssh.py`, locate the `execute()` method. After the `return` dict on line ~283 (the success return), insert broadcast calls **before** the return:

```python
# Find this block (lines ~282-289):
            return {
                "status": "success" if exit_code == 0 else "error",
                "tool": tool_name,
                "stdout": stdout,
                "stderr": stderr,
                "exit_code": exit_code,
            }

# Replace with:
            if self._terminal_broadcaster is not None:
                ts = datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")
                if stdout:
                    await self._terminal_broadcaster.publish({
                        "type": "kali_output",
                        "source": "kali",
                        "agent": tool_input.get("_agent_name"),
                        "tool": tool_name,
                        "stream": "stdout",
                        "data": stdout,
                        "ts": ts,
                    })
                if stderr:
                    await self._terminal_broadcaster.publish({
                        "type": "kali_output",
                        "source": "kali",
                        "agent": tool_input.get("_agent_name"),
                        "tool": tool_name,
                        "stream": "stderr",
                        "data": stderr,
                        "ts": ts,
                    })

            return {
                "status": "success" if exit_code == 0 else "error",
                "tool": tool_name,
                "stdout": stdout,
                "stderr": stderr,
                "exit_code": exit_code,
            }
```

Also add `from datetime import datetime` to the imports at the top of `kali_ssh.py` if not already present (check with `grep "from datetime" backend/tools/backends/kali_ssh.py`).

- [ ] **Step 2.5: Run tests to verify they pass**

```bash
cd C:/Projects/Optimus
pytest backend/tests/test_kali_connection_mgr.py -v
```

Expected: all existing tests + 3 new `TestKaliConnectionManagerBroadcast` tests **PASSED**

- [ ] **Step 2.6: Commit**

```bash
cd C:/Projects/Optimus
git add backend/tools/backends/kali_ssh.py backend/tests/test_kali_connection_mgr.py
git commit -m "feat: hook KaliConnectionManager.execute() to broadcast terminal output"
```

---

## Task 3: Register broadcaster in `main.py` and add endpoints

**Files:**
- Modify: `backend/main.py` — lifespan startup, two new endpoints

- [ ] **Step 3.1: Write failing tests for the new endpoints**

Add to `backend/tests/test_terminal_broadcaster.py` (append at end):

```python
class TestTerminalExecEndpoint:
    """Integration tests for POST /terminal/exec."""

    async def test_empty_command_returns_400(self):
        from fastapi.testclient import TestClient
        from backend.main import app

        client = TestClient(app)
        resp = client.post("/terminal/exec", json={"command": "  "})
        assert resp.status_code == 400

    async def test_missing_command_field_returns_422(self):
        from fastapi.testclient import TestClient
        from backend.main import app

        client = TestClient(app)
        resp = client.post("/terminal/exec", json={})
        assert resp.status_code == 422
```

- [ ] **Step 3.2: Run tests to verify they fail**

```bash
cd C:/Projects/Optimus
pytest backend/tests/test_terminal_broadcaster.py::TestTerminalExecEndpoint -v
```

Expected: `404 Not Found` (endpoint doesn't exist yet)

- [ ] **Step 3.3: Add import and register `TerminalBroadcaster` in `main.py` lifespan**

In `backend/main.py`, add the import near the top (after the existing `from backend.core.*` imports):

```python
from backend.core.terminal_broadcaster import TerminalBroadcaster, TerminalLogHandler
```

In the `lifespan()` function, add broadcaster initialization **before** the `KaliConnectionManager` block (around line 139). Insert:

```python
    # TerminalBroadcaster — must be created before KaliConnectionManager
    terminal_broadcaster = TerminalBroadcaster()
    _state["terminal_broadcaster"] = terminal_broadcaster

    # Attach log handler to capture all backend.* log output
    _terminal_log_handler = TerminalLogHandler(terminal_broadcaster)
    _terminal_log_handler.setLevel(logging.DEBUG)
    logging.getLogger("backend").addHandler(_terminal_log_handler)
```

Then update the `KaliConnectionManager` constructor call (around line 140) to pass `terminal_broadcaster`:

```python
    kali_mgr = KaliConnectionManager(
        host=os.environ.get("KALI_HOST", "kali"),
        port=int(os.environ.get("KALI_PORT", "22")),
        username=os.environ.get("KALI_USER", "root"),
        password=os.environ.get("KALI_PASSWORD", "optimus"),
        event_bus=event_bus,
        terminal_broadcaster=terminal_broadcaster,   # ADD THIS LINE
    )
```

In the teardown section (after `yield`), add cleanup for the log handler:

```python
    logging.getLogger("backend").removeHandler(_terminal_log_handler)
```

- [ ] **Step 3.4: Add `TerminalExecRequest` model and two endpoints**

Add a Pydantic model near the other request handling code in `backend/main.py`. Search for `class` in `main.py` — there are no Pydantic models currently, so add this near the top (after imports, before `logger = ...`):

```python
from pydantic import BaseModel

class TerminalExecRequest(BaseModel):
    command: str
```

Add the two endpoints at the end of `backend/main.py`, before the final `if __name__ == "__main__":` block (or at the very end if there is none):

```python
# ---------------------------------------------------------------------------
# WebSocket: Terminal stream
# ---------------------------------------------------------------------------

@app.websocket("/ws/terminal")
async def websocket_terminal(websocket: WebSocket):
    """Fan out terminal events (Kali stdout/stderr + backend logs) to the dashboard."""
    broadcaster: TerminalBroadcaster | None = _get("terminal_broadcaster")
    if broadcaster is None:
        await websocket.close(code=1011)
        return
    await broadcaster.connect(websocket)
    try:
        while True:
            await websocket.receive_text()  # keep-alive; client sends nothing
    except WebSocketDisconnect:
        broadcaster.disconnect(websocket)
    except Exception:
        broadcaster.disconnect(websocket)


# ---------------------------------------------------------------------------
# REST: Operator manual shell command
# ---------------------------------------------------------------------------

@app.post("/terminal/exec")
async def terminal_exec(body: TerminalExecRequest):
    """Execute an operator-typed command on Kali SSH and broadcast the result.

    The command bypasses all agent permission layers — this is a direct
    operator shell. Returns stdout, stderr, and exit_code.
    """
    if not body.command.strip():
        raise HTTPException(status_code=400, detail="command is empty")

    kali_mgr: KaliConnectionManager | None = _get("kali_mgr")
    broadcaster: TerminalBroadcaster | None = _get("terminal_broadcaster")

    if kali_mgr is None:
        raise HTTPException(status_code=503, detail="Kali SSH not initialized")

    from datetime import datetime, timezone

    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    # Echo operator input to terminal stream
    if broadcaster:
        await broadcaster.publish({
            "type": "operator_input",
            "source": "operator",
            "data": body.command,
            "ts": ts,
        })

    # Execute directly on a pool connection (raw command, not tool dispatch)
    try:
        async with kali_mgr._semaphore:
            conn = await kali_mgr._get_healthy_connection()
            stdout, stderr, exit_code = await asyncio.to_thread(
                conn.exec_command, body.command, 60
            )
    except Exception as exc:
        raise HTTPException(status_code=503, detail=f"Kali SSH error: {exc}")

    # Broadcast result (reuse the same path as agent output, agent=None signals operator)
    if broadcaster:
        if stdout:
            await broadcaster.publish({
                "type": "kali_output",
                "source": "kali",
                "agent": None,
                "tool": None,
                "stream": "stdout",
                "data": stdout,
                "ts": ts,
            })
        if stderr:
            await broadcaster.publish({
                "type": "kali_output",
                "source": "kali",
                "agent": None,
                "tool": None,
                "stream": "stderr",
                "data": stderr,
                "ts": ts,
            })

    return {"stdout": stdout, "stderr": stderr, "exit_code": exit_code}
```

- [ ] **Step 3.5: Run tests to verify they pass**

```bash
cd C:/Projects/Optimus
pytest backend/tests/test_terminal_broadcaster.py -v
```

Expected: all tests **PASSED**

- [ ] **Step 3.6: Run the full test suite to verify no regressions**

```bash
cd C:/Projects/Optimus
pytest backend/tests/ -v --tb=short
```

Expected: all pre-existing tests still **PASSED**

- [ ] **Step 3.7: Commit**

```bash
cd C:/Projects/Optimus
git add backend/main.py
git commit -m "feat: register TerminalBroadcaster and add /ws/terminal + /terminal/exec endpoints"
```

---

## Task 4: Replace `EventFeed` with `TerminalPanel` in the frontend

**Files:**
- Modify: `frontend/src/App.jsx`
  - Remove: `EventFeed` function (lines 414–474)
  - Add: `TerminalLine`, `TerminalInput`, `TerminalPanel` functions
  - Update: layout render (line 1249–1251) — swap `<EventFeed>` for `<TerminalPanel>`
  - Update: `App()` state — replace `events` / `setEvents` usage for terminal

No frontend test framework is present in this project — verify by manual browser check in Step 4.5.

- [ ] **Step 4.1: Add `TerminalLine` component**

In `frontend/src/App.jsx`, find the line:

```js
function EventFeed({ events }) {
```

**Before** that line, insert the three new components. Add `TerminalLine` first:

```jsx
// ─── Terminal components ───────────────────────────────────────────────────────

function TerminalLine({ line }) {
  const { type, source, agent, tool, stream, level, data, ts } = line

  const timestamp = ts
    ? new Date(ts).toLocaleTimeString('en-US', { hour12: false, hour: '2-digit', minute: '2-digit', second: '2-digit' })
    : ''

  let label = ''
  let labelColor = ''
  let textColor = 'text-zinc-300'

  if (type === 'operator_input') {
    label = '[OPERATOR]'
    labelColor = 'text-cyan-300'
    textColor = 'text-cyan-200 opacity-60'
  } else if (type === 'kali_output' && agent == null) {
    label = '[OPERATOR]'
    labelColor = 'text-cyan-400'
    textColor = stream === 'stderr' ? 'text-red-400' : 'text-cyan-100'
  } else if (type === 'kali_output') {
    label = `[${agent || '?'} › ${tool || '?'}]`
    labelColor = 'text-emerald-400'
    textColor = stream === 'stderr' ? 'text-red-400' : 'text-zinc-200'
  } else if (type === 'backend_log') {
    label = '[backend]'
    if (level === 'WARNING') {
      labelColor = 'text-amber-400'
      textColor = 'text-amber-200'
    } else if (level === 'ERROR') {
      labelColor = 'text-red-400'
      textColor = 'text-red-300'
    } else {
      labelColor = 'text-zinc-500'
      textColor = 'text-zinc-500'
    }
  } else {
    label = `[${source || type}]`
    labelColor = 'text-zinc-600'
  }

  // Render each line of multi-line data as a separate visual row
  const rows = (data || '').split('\n').filter(Boolean)

  return (
    <>
      {rows.map((row, i) => (
        <div key={i} className="flex items-start gap-2 px-3 py-0.5 hover:bg-zinc-900/40 group">
          <span className="font-mono text-xs text-zinc-700 shrink-0 w-16 select-none">{i === 0 ? timestamp : ''}</span>
          <span className={`font-mono text-xs shrink-0 ${labelColor}`}>{i === 0 ? label : ''}</span>
          <span className={`font-mono text-xs break-all whitespace-pre-wrap ${textColor}`}>{row}</span>
        </div>
      ))}
    </>
  )
}
```

- [ ] **Step 4.2: Add `TerminalInput` component**

Immediately after `TerminalLine`, before the existing `EventFeed`, add:

```jsx
function TerminalInput({ agentActive, onExec }) {
  const [cmd, setCmd] = useState('')
  const [running, setRunning] = useState(false)
  const [error, setError] = useState(null)
  const inputRef = useRef(null)

  const handleSubmit = async () => {
    const command = cmd.trim()
    if (!command || running) return
    setRunning(true)
    setError(null)
    try {
      const resp = await fetch(`${API_BASE}/terminal/exec`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ command }),
      })
      if (!resp.ok) {
        const err = await resp.json().catch(() => ({}))
        setError(err.detail || `HTTP ${resp.status}`)
      } else {
        setCmd('')
      }
    } catch (e) {
      setError(String(e))
    } finally {
      setRunning(false)
      inputRef.current?.focus()
    }
  }

  const handleKey = (e) => {
    if (e.key === 'Enter') { e.preventDefault(); handleSubmit() }
  }

  return (
    <div className="shrink-0 border-t border-zinc-800">
      {agentActive && (
        <div className="flex items-center gap-2 px-3 py-1 bg-amber-900/20 border-b border-amber-800/40">
          <AlertTriangle size={11} className="text-amber-400 shrink-0" />
          <span className="font-mono text-xs text-amber-400">Agent active — commands will run concurrently</span>
        </div>
      )}
      {error && (
        <div className="px-3 py-1 bg-red-900/20 border-b border-red-800/40">
          <span className="font-mono text-xs text-red-400">{error}</span>
        </div>
      )}
      <div className="flex items-center gap-2 px-3 py-2">
        <span className="font-mono text-xs text-emerald-600 shrink-0 select-none">kali@optimus:~$</span>
        <input
          ref={inputRef}
          type="text"
          value={cmd}
          onChange={e => setCmd(e.target.value)}
          onKeyDown={handleKey}
          disabled={running}
          placeholder="enter command..."
          className="flex-1 bg-transparent font-mono text-xs text-zinc-200 placeholder:text-zinc-700 outline-none disabled:opacity-40"
        />
        <button
          onClick={handleSubmit}
          disabled={running || !cmd.trim()}
          className="font-mono text-xs px-2 py-1 rounded bg-zinc-800 border border-zinc-700 text-zinc-300 hover:bg-zinc-700 disabled:opacity-30 disabled:cursor-not-allowed transition-colors"
        >
          {running ? '...' : 'RUN'}
        </button>
      </div>
    </div>
  )
}
```

- [ ] **Step 4.3: Add `TerminalPanel` component and remove `EventFeed`**

Immediately after `TerminalInput`, add `TerminalPanel`:

```jsx
function TerminalPanel({ lines, agentActive, wsConnected }) {
  const bottomRef = useRef(null)
  const containerRef = useRef(null)
  const [autoScroll, setAutoScroll] = useState(true)

  useEffect(() => {
    if (autoScroll) {
      bottomRef.current?.scrollIntoView({ behavior: 'smooth' })
    }
  }, [lines, autoScroll])

  const handleScroll = () => {
    const el = containerRef.current
    if (!el) return
    const atBottom = el.scrollHeight - el.scrollTop - el.clientHeight < 40
    setAutoScroll(atBottom)
  }

  return (
    <div className="panel flex flex-col h-full relative scan-lines">
      <div className="panel-header shrink-0">
        <div className="flex items-center gap-2">
          <Terminal size={13} className="text-zinc-500" />
          <span className="label-xs">Terminal</span>
          {wsConnected && (
            <span className="flex items-center gap-1.5 ml-1">
              <span className="dot-live" />
            </span>
          )}
        </div>
        <div className="flex items-center gap-3">
          <span className="font-mono text-xs text-zinc-600">{lines.length} lines</span>
          {!autoScroll && (
            <button
              onClick={() => { setAutoScroll(true); bottomRef.current?.scrollIntoView() }}
              className="btn-ghost text-xs py-1 px-2"
            >
              ↓ resume
            </button>
          )}
        </div>
      </div>

      <div
        ref={containerRef}
        onScroll={handleScroll}
        className="flex-1 overflow-y-auto"
      >
        {lines.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-full text-center px-6">
            <Terminal size={24} className="text-zinc-700 mb-3" />
            <p className="font-mono text-xs text-zinc-600">Waiting for terminal output...</p>
            <p className="text-xs text-zinc-700 mt-1">Start an engagement or type a command below</p>
          </div>
        ) : (
          lines.map((line, i) => <TerminalLine key={i} line={line} />)
        )}
        <div ref={bottomRef} />
      </div>

      <TerminalInput agentActive={agentActive} />
    </div>
  )
}
```

Now **delete** the old `EventFeed` function entirely (lines 414–474):

```js
// DELETE this entire block — it is replaced by TerminalPanel above:
function EventFeed({ events }) {
  ...
}
```

- [ ] **Step 4.4: Update `App()` state and render**

In `App()` (around line 1025), the `events` state and its WebSocket are still needed by the `handleEventMessage` callback for agent tracking, findings, engagement state, etc. **Keep them.** Only the UI render changes.

Find the terminal state and WebSocket. Add new state variables inside `App()` after the existing state declarations:

```js
  // Terminal panel state
  const [terminalLines, setTerminalLines] = useState([])
  const [terminalWsConnected, setTerminalWsConnected] = useState(false)
```

Add the terminal WebSocket hook inside `App()`, after the existing `useWebSocket` calls:

```js
  const handleTerminalMessage = useCallback((data) => {
    setTerminalLines(prev => {
      const next = [...prev, data]
      return next.length > 2000 ? next.slice(next.length - 2000) : next
    })
  }, [])

  const { connected: terminalConnected } = useWebSocket(
    `${WS_BASE}/ws/terminal`,
    handleTerminalMessage,
  )

  useEffect(() => {
    setTerminalWsConnected(terminalConnected)
  }, [terminalConnected])
```

Derive `agentActive` from the existing `agents` state (already tracked in `App()`):

```js
  const agentActive = agents.some(a => a.status === 'running')
```

Finally, in the JSX render, find line ~1249–1251:

```jsx
          {/* Event feed — takes ~45% of centre */}
          <div style={{ flex: '0 0 42%' }} className="min-h-0">
            <EventFeed events={events} />
          </div>
```

Replace with:

```jsx
          {/* Terminal feed — takes ~45% of centre */}
          <div style={{ flex: '0 0 42%' }} className="min-h-0">
            <TerminalPanel
              lines={terminalLines}
              agentActive={agentActive}
              wsConnected={terminalWsConnected}
            />
          </div>
```

- [ ] **Step 4.5: Verify in browser**

```bash
cd C:/Projects/Optimus/frontend
npm run dev
```

Open `http://localhost:5173` and verify:

1. The terminal panel appears where the event feed was — shows "Waiting for terminal output..." when empty.
2. The input bar shows `kali@optimus:~$` prompt and accepts text.
3. Type `whoami` and press Enter — the command appears as `[OPERATOR]` in cyan, followed by the result.
4. If Kali is offline, an error banner appears below the input.
5. Run a directive — Kali command output appears in green with `[AgentName › toolName]` label.
6. Backend log lines appear in grey.

- [ ] **Step 4.6: Commit**

```bash
cd C:/Projects/Optimus
git add frontend/src/App.jsx
git commit -m "feat: replace EventFeed with TerminalPanel in dashboard"
```

---

## Task 5: Final verification

- [ ] **Step 5.1: Run full test suite**

```bash
cd C:/Projects/Optimus
pytest backend/tests/ -v --tb=short
```

Expected: all tests **PASSED** with no failures.

- [ ] **Step 5.2: Build frontend for production**

```bash
cd C:/Projects/Optimus/frontend
npm run build
```

Expected: build completes with no errors. Warnings about bundle size are acceptable.

- [ ] **Step 5.3: Verify success criteria from spec**

Check each item from the spec's Section 10:

| Criterion | How to verify |
|---|---|
| Agent stdout/stderr appears within 1s of command completing | Run a directive, watch terminal panel |
| Backend logs appear in real time | Watch for grey `[backend]` lines during startup |
| Operator command result appears within 2s | Type `id` in input bar, press Enter |
| Amber banner when agent active | Start an engagement, check banner appears |
| `[OPERATOR]` label on operator commands | Type a command, verify cyan label |
| WebSocket reconnects within 5s | Restart backend, watch panel reconnect |
| Line buffer capped at 2000 | (Code review) `next.slice(next.length - 2000)` |
| Existing EventBus/findings unaffected | Verify findings still populate right panel |

- [ ] **Step 5.4: Final commit**

```bash
cd C:/Projects/Optimus
git add -p  # review any remaining unstaged changes
git commit -m "feat: terminal live feed complete — replaces EventFeed with TerminalPanel"
```

---

## Quick Reference: Key Locations

| What | Where |
|---|---|
| `TerminalBroadcaster` class | `backend/core/terminal_broadcaster.py` |
| `KaliConnectionManager.execute()` | `backend/tools/backends/kali_ssh.py:244` |
| Broadcaster registered in state | `backend/main.py` lifespan, before KaliConnectionManager |
| `/ws/terminal` endpoint | `backend/main.py` (end of file) |
| `POST /terminal/exec` endpoint | `backend/main.py` (end of file) |
| `TerminalPanel` component | `frontend/src/App.jsx` (replaces EventFeed at line 414) |
| `agentActive` derivation | `App()` in `frontend/src/App.jsx` |
| Spec | `docs/superpowers/specs/2026-04-07-terminal-live-feed-design.md` |
