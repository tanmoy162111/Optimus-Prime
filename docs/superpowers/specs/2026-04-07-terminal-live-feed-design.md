# Design Spec: Terminal Live Feed (replaces EventFeed)

**Date:** 2026-04-07
**Status:** Approved
**Feature:** Replace dashboard Live Event Feed panel with a real-time terminal panel showing Kali SSH command output, backend logs, and an operator manual shell input.

---

## 1. Problem Statement

The current `EventFeed` panel shows structured JSON events (agent lifecycle, findings, phase transitions) in a card format. This is useful for high-level status but gives no visibility into the raw output of tools being executed on the Kali container or the backend Python process. Security operators need a terminal-grade view to monitor what commands are running, what they return, and any backend errors — without leaving the dashboard.

---

## 2. Goals

- Replace the `EventFeed` component with a `TerminalPanel` that streams real-time output.
- Show every `exec_command` call made on Kali SSH by any agent, labelled with the originating agent and tool name.
- Interleave Python backend log lines into the same stream for full operational visibility.
- Provide a manual shell input bar at the bottom that sends commands directly to Kali SSH.
- Warn the operator when agents are active but do not block manual input; operator commands are labelled `[OPERATOR]` in the stream.

## 3. Non-Goals

- No xterm.js / full PTY emulation — ANSI escape codes are stripped.
- No tab completion or arrow-key shell history in the manual input bar.
- No changes to the existing `/ws` EventBus, `DurableEventLog`, findings pipeline, or any agent code.
- The manual shell input does not go through `ScopeEnforcer` or `PermissionEnforcer` — it is an operator-direct Kali shell.

---

## 4. Architecture

```
┌─────────────────────────────────────────────────────────┐
│  Dashboard (App.jsx)                                    │
│                                                         │
│  [Chat Panel]   [TerminalPanel] ← replaces EventFeed   │
│                 │                                       │
│                 ├─ scrolling terminal div               │
│                 │   • color-coded lines by source       │
│                 │   • [Agent › Tool] labels             │
│                 │   • backend log lines                 │
│                 │                                       │
│                 └─ input bar                            │
│                     • sends to POST /terminal/exec      │
│                     • "Agent active" warning banner     │
└─────────────────────────────────────────────────────────┘
           ↕ WebSocket /ws/terminal
┌─────────────────────────────────────────────────────────┐
│  Backend                                                │
│                                                         │
│  TerminalBroadcaster (singleton)                        │
│  ├─ receives from: KaliSSH hook (per exec_command)      │
│  ├─ receives from: TerminalLogHandler (Python logging)  │
│  └─ publishes structured JSON events to /ws/terminal   │
│                                                         │
│  POST /terminal/exec                                    │
│  └─ runs command on Kali SSH → broadcasts result        │
└─────────────────────────────────────────────────────────┘
```

**Key invariants:**
- `TerminalBroadcaster` is a singleton registered in `app_state` at startup, alongside `event_bus` and `kali_mgr`.
- The Kali SSH hook wraps `exec_command` at the `KaliConnectionManager.dispatch` level — all agents get terminal streaming for free with zero agent code changes.
- `/ws/terminal` is a separate WebSocket from `/ws` — raw terminal bytes never enter `DurableEventLog`.

---

## 5. Event Schema

Every message over `/ws/terminal` is a JSON envelope. Four event types:

### 5.1 Kali output from agent tool call
```json
{
  "type": "kali_output",
  "source": "kali",
  "agent": "ReconAgent",
  "tool": "nmap",
  "stream": "stdout",
  "data": "Starting Nmap 7.94...",
  "ts": "2026-04-07T10:23:01Z"
}
```
`stream` is `"stdout"` or `"stderr"`. stderr lines are rendered in red.

### 5.2 Backend Python log line
```json
{
  "type": "backend_log",
  "source": "backend",
  "level": "INFO",
  "logger": "backend.agents.recon_agent",
  "data": "ReconAgent: dispatching nmap on 192.168.1.0/24",
  "ts": "2026-04-07T10:23:00Z"
}
```
`level` is one of `DEBUG | INFO | WARNING | ERROR`.

### 5.3 Operator manual command echo
```json
{
  "type": "operator_input",
  "source": "operator",
  "data": "whoami",
  "ts": "2026-04-07T10:23:45Z"
}
```

### 5.4 Operator command result
Same shape as 5.1, with `agent: null` and `tool: null` to indicate manual origin.

---

## 6. Frontend Design

### 6.1 Component tree

```
TerminalPanel
├─ panel-header  (title, live dot, clear button, line count)
├─ terminal-body (scrolling div, font-mono text-xs, max 2000 lines FIFO)
│   └─ TerminalLine[]
│       • timestamp (HH:MM:SS)
│       • colored label badge  ([Agent › Tool], [OPERATOR], [backend])
│       • text content
└─ TerminalInput
    • amber banner: "Agent active — commands will run concurrently" (conditional)
    • kali@optimus:~$ prompt
    • text input + RUN button (Enter submits)
```

### 6.2 Label and color rules

| Event type | Label | Text color |
|---|---|---|
| `kali_output` stdout (agent) | `[AgentName › toolName]` | emerald-400 |
| `kali_output` stderr (agent) | `[AgentName › toolName]` | red-400 |
| `kali_output` stdout (operator) | `[OPERATOR]` | cyan-400 |
| `kali_output` stderr (operator) | `[OPERATOR]` | red-400 |
| `operator_input` | `[OPERATOR]` | cyan-300 (dimmed) |
| `backend_log` DEBUG/INFO | `[backend]` | zinc-500 |
| `backend_log` WARNING | `[backend]` | amber-400 |
| `backend_log` ERROR | `[backend]` | red-400 |

### 6.3 State

```js
const [lines, setLines]             = useState([])      // capped at 2000, FIFO drop oldest
const [agentActive, setAgentActive] = useState(false)   // derived from existing /ws events
const [inputCmd, setInputCmd]       = useState('')
const [running, setRunning]         = useState(false)   // POST /terminal/exec in-flight
const [wsConnected, setWsConnected] = useState(false)
```

`agentActive` is derived from the existing agent lifecycle events already flowing through the `/ws` EventBus connection in `App.jsx`. No new state plumbing: `AGENT_RUNNING` → true, `AGENT_FINISHED` / `AGENT_FAILED` (when no other agent is running) → false.

### 6.4 WebSocket connection

`TerminalPanel` opens a second WebSocket to `/ws/terminal` independently of the existing `/ws` connection. Uses the same `useWebSocket` hook pattern already in `App.jsx`. On disconnect, reconnects every 3 seconds (same as existing pattern). No replay-on-reconnect needed — terminal output is ephemeral.

### 6.5 Manual command flow

1. Operator types command → presses Enter or clicks RUN.
2. `running` set to true, input disabled.
3. `POST /terminal/exec {command: "..."}` sent to backend.
4. Backend echoes `operator_input` event via `TerminalBroadcaster` → appears in stream.
5. Backend runs command on Kali SSH → result broadcasted as `kali_output` (agent: null).
6. POST response received → `running` set to false, input cleared and re-enabled.

---

## 7. Backend Implementation

### 7.1 New file: `backend/core/terminal_broadcaster.py`

Contains two classes:

**`TerminalBroadcaster`**
```python
class TerminalBroadcaster:
    def __init__(self): self._connections: list[WebSocket] = []
    async def connect(self, ws: WebSocket) -> None: ...
    def disconnect(self, ws: WebSocket) -> None: ...
    async def publish(self, event: dict) -> None: ...  # fan-out to all connections
```

**`TerminalLogHandler`**
```python
class TerminalLogHandler(logging.Handler):
    """Feeds Python logging records into TerminalBroadcaster as backend_log events."""
    def __init__(self, broadcaster: TerminalBroadcaster): ...
    def emit(self, record: logging.LogRecord) -> None: ...
```

### 7.2 `backend/tools/backends/kali_ssh.py` — exec hook

Wrap the async `dispatch` method in `KaliConnectionManager` (around line 263). After `exec_command` returns stdout/stderr, call:

```python
await terminal_broadcaster.publish({
    "type": "kali_output",
    "source": "kali",
    "agent": task.agent_name,   # passed through from EngineTask/AgentTask
    "tool": task.tool_name,
    "stream": "stdout",
    "data": stdout,
    "ts": datetime.utcnow().isoformat() + "Z",
})
# repeat for stderr if non-empty
```

`TerminalBroadcaster` is injected into `KaliConnectionManager` at startup (same pattern as existing dependencies).

### 7.3 `backend/main.py` — startup registration

```python
terminal_broadcaster = TerminalBroadcaster()
_state["terminal_broadcaster"] = terminal_broadcaster

# Attach log handler
handler = TerminalLogHandler(terminal_broadcaster)
handler.setLevel(logging.DEBUG)
logging.getLogger("backend").addHandler(handler)
```

### 7.4 New endpoints in `backend/main.py`

**WebSocket:**
```python
@app.websocket("/ws/terminal")
async def websocket_terminal(websocket: WebSocket):
    broadcaster = _get("terminal_broadcaster")
    await broadcaster.connect(websocket)
    try:
        while True:
            await websocket.receive_text()  # keep alive, ignore client messages
    except WebSocketDisconnect:
        broadcaster.disconnect(websocket)
```

**REST:**
```python
class TerminalExecRequest(BaseModel):
    command: str

@app.post("/terminal/exec")
async def terminal_exec(body: TerminalExecRequest):
    if not body.command.strip():
        raise HTTPException(400, "command is empty")
    kali_mgr = _get("kali_mgr")
    broadcaster = _get("terminal_broadcaster")
    # echo operator input
    await broadcaster.publish({"type": "operator_input", "source": "operator",
                               "data": body.command,
                               "ts": datetime.utcnow().isoformat() + "Z"})
    # execute (dispatch hook will also broadcast the result)
    result = await kali_mgr.dispatch(command=body.command, agent_name=None, tool_name=None)
    return {"stdout": result["stdout"], "stderr": result["stderr"],
            "exit_code": result["exit_code"]}
```

---

## 8. Error Handling

| Scenario | Behaviour |
|---|---|
| `/ws/terminal` disconnects | Reconnect every 3s (frontend); broadcaster silently drops disconnected socket |
| Kali SSH unreachable | `exec_command` raises; backend publishes `backend_log` ERROR event; POST returns 503 |
| `POST /terminal/exec` with empty command | 400 response; frontend shows inline error, does not add to stream |
| Line buffer overflow (>2000 lines) | Frontend drops oldest lines (FIFO); no backend change |
| `TerminalLogHandler.emit` exception | Swallowed silently (standard logging handler contract) |

---

## 9. Files Changed

| File | Change |
|---|---|
| `backend/core/terminal_broadcaster.py` | **New** — TerminalBroadcaster + TerminalLogHandler |
| `backend/tools/backends/kali_ssh.py` | **Edit** — inject broadcaster, publish after exec_command |
| `backend/main.py` | **Edit** — register broadcaster, add /ws/terminal + POST /terminal/exec |
| `frontend/src/App.jsx` | **Edit** — replace EventFeed with TerminalPanel + TerminalLine + TerminalInput |

No other files change. Estimated additions: ~180 lines backend, ~150 lines frontend.

---

## 10. Success Criteria

- [ ] When an agent runs a tool on Kali, its stdout/stderr appears in the terminal panel within 1 second of the command completing.
- [ ] Backend log lines (INFO and above) appear in the terminal panel in real time.
- [ ] Operator can type a command in the input bar, press Enter, and see the result in the terminal stream within 2 seconds.
- [ ] When `agentActive` is true, the amber warning banner is visible but input is not blocked.
- [ ] Operator commands are labelled `[OPERATOR]` and visually distinct from agent output.
- [ ] On WebSocket disconnect, the panel reconnects automatically within 5 seconds.
- [ ] Line buffer is capped at 2000 — oldest lines drop cleanly with no memory leak.
- [ ] Existing `/ws` EventBus, findings pipeline, and all agent behaviour are unaffected.
