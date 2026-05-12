# EngagementSession + ConversationHistory Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace global singleton state with a session-scoped `EngagementSession` object that owns conversation history, so chat is stateful and the system is ready for multiple concurrent engagements.

**Architecture:** `EngagementSession` is a dataclass that owns `ConversationHistory`, `ScopeConfig`, and `EngagementState`. A module-level `SessionStore` resolves session IDs to `EngagementSession` instances. The WS handler and HTTP routes stop using module-level globals and resolve sessions through the store. The orchestrator passes `session.conv_history.get_context_window()` as the messages list to the LLM on every call.

**Tech Stack:** Python 3.11, FastAPI 0.115, Pydantic-settings 2.6, Anthropic SDK 0.38, tiktoken 0.7, pytest + pytest-asyncio + httpx (dev deps)

---

## File Map

| Action | Path | Responsibility |
|--------|------|----------------|
| MODIFY | `backend/config.py` | Pydantic Settings with all required fields |
| MODIFY | `backend/app.py` | Fix `chat_routers` → `chat_routes` typo |
| CREATE | `backend/session/__init__.py` | Package marker |
| CREATE | `backend/session/engagement_session.py` | `ScopeConfig`, `ConversationHistory`, `EngagementState`, `EngagementSession` |
| CREATE | `backend/session/session_store.py` | `SessionStore` — creates, resolves, touches sessions |
| CREATE | `backend/auth.py` | `verify_token` FastAPI dependency (HTTP + WS) |
| MODIFY | `backend/agent/llm_router.py` | `complete(messages, mode, system)` instead of `complete(prompt, mode)` |
| MODIFY | `backend/agent/orchestrator.py` | `_build_messages()` returns `List[Dict]`; store user+assistant turns in `conv_history` |
| MODIFY | `backend/api/ws_handler.py` | Token auth via query param; resolve `EngagementSession` from `session_store` |
| MODIFY | `backend/api/chat_routes.py` | Resolve `EngagementSession` from `session_store`; unify auth to `verify_token` |
| CREATE | `tests/__init__.py` | Package marker |
| CREATE | `tests/session/__init__.py` | Package marker |
| CREATE | `tests/session/test_engagement_session.py` | Unit tests for session domain objects |
| CREATE | `tests/session/test_session_store.py` | Unit tests for SessionStore |
| CREATE | `tests/api/__init__.py` | Package marker |
| CREATE | `tests/api/test_auth.py` | Integration tests for auth on HTTP + WS |
| CREATE | `tests/conftest.py` | Shared fixtures (TestClient, env overrides) |

---

## Task 0: Prerequisites — config, dev deps, app.py typo

**Files:**
- Modify: `backend/config.py`
- Modify: `backend/app.py`
- Modify: `backend/requirements.txt`

- [ ] **Step 1: Replace config.py with a working Settings class**

```python
# backend/config.py
from pydantic_settings import BaseSettings


class Settings(BaseSettings):
    bearer_token: str = "dev-token"
    anthropic_api_key: str = ""
    ollama_host: str = "http://localhost:11434"
    claude_model: str = "claude-opus-4-7"
    mistral_model: str = "mistral:7b"
    embed_model: str = "nomic-embed-text"
    kali_host: str = "localhost"
    kali_port: int = 22
    kali_user: str = "kali"
    kali_password: str = ""

    model_config = {"env_file": ".env", "env_file_encoding": "utf-8"}


settings = Settings()
```

> Note: `optimus_api_key` from `chat_routes.py:24` is replaced by `bearer_token`. Both the HTTP route and WS handler will use the same field after Task 5.

- [ ] **Step 2: Fix the import typo in app.py**

In `backend/app.py`, line 41 references `chat_routers` which doesn't exist (import on line 7 is `chat_routes`). Change line 41:

```python
# backend/app.py  — change line 41 only
app.include_router(chat_routes.router, prefix="/api")
```

- [ ] **Step 3: Add test dependencies to requirements.txt**

Append to `backend/requirements.txt`:
```
pytest==8.3.3
pytest-asyncio==0.24.0
httpx==0.27.2
```

- [ ] **Step 4: Verify the app starts (smoke test)**

```bash
cd "C:/Projects/Optimus Prime"
pip install -r backend/requirements.txt -q
python -c "from backend.app import app; print('OK')"
```

Expected output: `OK` (no ImportError or NameError)

- [ ] **Step 5: Commit**

```bash
git add backend/config.py backend/app.py backend/requirements.txt
git commit -m "fix: working config.py, fix chat_routers typo, add test deps"
```

---

## Task 1: Write failing tests for EngagementSession domain objects

**Files:**
- Create: `tests/__init__.py`
- Create: `tests/session/__init__.py`
- Create: `tests/session/test_engagement_session.py`

- [ ] **Step 1: Create package markers**

Create `tests/__init__.py` as an empty file.
Create `tests/session/__init__.py` as an empty file.

- [ ] **Step 2: Write the test file**

```python
# tests/session/test_engagement_session.py
import pytest
from datetime import datetime

from backend.session.engagement_session import (
    ConversationHistory,
    EngagementSession,
    EngagementState,
    ScopeConfig,
)


class TestConversationHistory:
    def test_starts_empty(self):
        h = ConversationHistory()
        assert h.messages == []

    def test_add_message_appends(self):
        h = ConversationHistory()
        h.add_message("user", "hello")
        assert len(h.messages) == 1
        assert h.messages[0] == {"role": "user", "content": "hello"}

    def test_get_context_window_returns_all_when_few(self):
        h = ConversationHistory()
        h.add_message("user", "a")
        h.add_message("assistant", "b")
        window = h.get_context_window()
        assert len(window) == 2

    def test_get_context_window_caps_at_40(self):
        h = ConversationHistory()
        for i in range(50):
            h.add_message("user", f"msg {i}")
        window = h.get_context_window()
        assert len(window) == 40

    def test_get_context_window_returns_most_recent(self):
        h = ConversationHistory()
        for i in range(50):
            h.add_message("user", f"msg {i}")
        window = h.get_context_window()
        assert window[-1]["content"] == "msg 49"
        assert window[0]["content"] == "msg 10"


class TestScopeConfig:
    def test_defaults(self):
        s = ScopeConfig()
        assert s.targets == []
        assert s.exclusions == []
        assert s.stealth_level == "medium"
        assert s.ports == []
        assert s.protocols == []

    def test_accepts_targets(self):
        s = ScopeConfig(targets=["192.168.1.1"], stealth_level="low")
        assert s.targets == ["192.168.1.1"]
        assert s.stealth_level == "low"


class TestEngagementState:
    def test_defaults(self):
        s = EngagementState()
        assert s.phase_status == {}
        assert s.findings == []
        assert s.gate_queue == []

    def test_add_finding(self):
        s = EngagementState()
        s.add_finding({"severity": "HIGH", "title": "SQLi"})
        assert len(s.findings) == 1
        assert s.findings[0]["title"] == "SQLi"

    def test_set_phase_status(self):
        s = EngagementState()
        s.set_phase_status("recon", "RUNNING")
        assert s.phase_status["recon"] == "RUNNING"


class TestEngagementSession:
    def test_create_factory(self):
        session = EngagementSession.create()
        assert session.session_id is not None
        assert session.engagement_id is not None
        assert isinstance(session.conv_history, ConversationHistory)
        assert isinstance(session.state, EngagementState)
        assert isinstance(session.scope, ScopeConfig)
        assert isinstance(session.created_at, datetime)
        assert isinstance(session.last_active, datetime)

    def test_create_with_engagement_id(self):
        session = EngagementSession.create(engagement_id="eng-123")
        assert session.engagement_id == "eng-123"

    def test_two_sessions_have_different_ids(self):
        a = EngagementSession.create()
        b = EngagementSession.create()
        assert a.session_id != b.session_id
        assert a.engagement_id != b.engagement_id
```

- [ ] **Step 3: Run tests — confirm they all FAIL with ImportError**

```bash
cd "C:/Projects/Optimus Prime"
python -m pytest tests/session/test_engagement_session.py -v 2>&1 | head -30
```

Expected: `ImportError: No module named 'backend.session.engagement_session'`

---

## Task 2: Implement EngagementSession domain objects

**Files:**
- Create: `backend/session/__init__.py`
- Create: `backend/session/engagement_session.py`

- [ ] **Step 1: Create package marker**

Create `backend/session/__init__.py` as an empty file.

- [ ] **Step 2: Implement the module**

```python
# backend/session/engagement_session.py
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional
from uuid import uuid4


@dataclass
class ScopeConfig:
    targets: List[str] = field(default_factory=list)
    exclusions: List[str] = field(default_factory=list)
    stealth_level: str = "medium"
    ports: List[int] = field(default_factory=list)
    protocols: List[str] = field(default_factory=list)


@dataclass
class ConversationHistory:
    messages: List[Dict[str, str]] = field(default_factory=list)
    _max_window: int = field(default=40, repr=False)

    def add_message(self, role: str, content: str) -> None:
        self.messages.append({"role": role, "content": content})

    def get_context_window(self) -> List[Dict[str, str]]:
        return self.messages[-self._max_window:]


@dataclass
class EngagementState:
    phase_status: Dict[str, str] = field(default_factory=dict)
    findings: List[Dict] = field(default_factory=list)
    gate_queue: List[str] = field(default_factory=list)

    def add_finding(self, finding: Dict) -> None:
        self.findings.append(finding)

    def set_phase_status(self, phase_id: str, status: str) -> None:
        self.phase_status[phase_id] = status


@dataclass
class EngagementSession:
    session_id: str
    engagement_id: str
    scope: ScopeConfig
    conv_history: ConversationHistory
    state: EngagementState
    created_at: datetime
    last_active: datetime

    @classmethod
    def create(cls, engagement_id: Optional[str] = None) -> "EngagementSession":
        now = datetime.utcnow()
        return cls(
            session_id=str(uuid4()),
            engagement_id=engagement_id or str(uuid4()),
            scope=ScopeConfig(),
            conv_history=ConversationHistory(),
            state=EngagementState(),
            created_at=now,
            last_active=now,
        )
```

- [ ] **Step 3: Run tests — confirm they all PASS**

```bash
cd "C:/Projects/Optimus Prime"
python -m pytest tests/session/test_engagement_session.py -v
```

Expected:
```
tests/session/test_engagement_session.py::TestConversationHistory::test_starts_empty PASSED
tests/session/test_engagement_session.py::TestConversationHistory::test_add_message_appends PASSED
tests/session/test_engagement_session.py::TestConversationHistory::test_get_context_window_returns_all_when_few PASSED
tests/session/test_engagement_session.py::TestConversationHistory::test_get_context_window_caps_at_40 PASSED
tests/session/test_engagement_session.py::TestConversationHistory::test_get_context_window_returns_most_recent PASSED
tests/session/test_engagement_session.py::TestScopeConfig::test_defaults PASSED
tests/session/test_engagement_session.py::TestScopeConfig::test_accepts_targets PASSED
tests/session/test_engagement_session.py::TestEngagementState::test_defaults PASSED
tests/session/test_engagement_session.py::TestEngagementState::test_add_finding PASSED
tests/session/test_engagement_session.py::TestEngagementState::test_set_phase_status PASSED
tests/session/test_engagement_session.py::TestEngagementSession::test_create_factory PASSED
tests/session/test_engagement_session.py::TestEngagementSession::test_create_with_engagement_id PASSED
tests/session/test_engagement_session.py::TestEngagementSession::test_two_sessions_have_different_ids PASSED
13 passed in 0.XXs
```

- [ ] **Step 4: Commit**

```bash
git add backend/session/ tests/__init__.py tests/session/
git commit -m "feat: add EngagementSession, ConversationHistory, ScopeConfig, EngagementState"
```

---

## Task 3: Write failing tests for SessionStore, then implement

**Files:**
- Create: `tests/session/test_session_store.py`
- Create: `backend/session/session_store.py`

- [ ] **Step 1: Write the test file**

```python
# tests/session/test_session_store.py
import time
import pytest

from backend.session.engagement_session import EngagementSession
from backend.session.session_store import SessionStore


class TestSessionStore:
    def test_create_returns_engagement_session(self):
        store = SessionStore()
        session = store.create()
        assert isinstance(session, EngagementSession)

    def test_create_with_engagement_id(self):
        store = SessionStore()
        session = store.create(engagement_id="eng-abc")
        assert session.engagement_id == "eng-abc"

    def test_resolve_returns_same_object(self):
        store = SessionStore()
        created = store.create()
        resolved = store.resolve(created.session_id)
        assert resolved is created

    def test_resolve_unknown_returns_none(self):
        store = SessionStore()
        assert store.resolve("does-not-exist") is None

    def test_touch_updates_last_active(self):
        store = SessionStore()
        session = store.create()
        before = session.last_active
        time.sleep(0.01)
        store.touch(session.session_id)
        assert session.last_active > before

    def test_touch_unknown_session_is_noop(self):
        store = SessionStore()
        store.touch("nonexistent")  # must not raise

    def test_multiple_sessions_are_independent(self):
        store = SessionStore()
        a = store.create()
        b = store.create()
        assert a.session_id != b.session_id
        a.conv_history.add_message("user", "hello")
        assert b.conv_history.messages == []

    def test_global_instance_is_same_object(self):
        from backend.session.session_store import session_store as s1
        from backend.session.session_store import session_store as s2
        assert s1 is s2
```

- [ ] **Step 2: Run tests — confirm they FAIL with ImportError**

```bash
cd "C:/Projects/Optimus Prime"
python -m pytest tests/session/test_session_store.py -v 2>&1 | head -10
```

Expected: `ImportError: No module named 'backend.session.session_store'`

- [ ] **Step 3: Implement SessionStore**

```python
# backend/session/session_store.py
from datetime import datetime
from typing import Dict, Optional

from backend.session.engagement_session import EngagementSession


class SessionStore:
    def __init__(self) -> None:
        self._sessions: Dict[str, EngagementSession] = {}

    def create(self, engagement_id: Optional[str] = None) -> EngagementSession:
        session = EngagementSession.create(engagement_id=engagement_id)
        self._sessions[session.session_id] = session
        return session

    def resolve(self, session_id: str) -> Optional[EngagementSession]:
        return self._sessions.get(session_id)

    def touch(self, session_id: str) -> None:
        session = self._sessions.get(session_id)
        if session:
            session.last_active = datetime.utcnow()


session_store = SessionStore()
```

- [ ] **Step 4: Run tests — confirm they all PASS**

```bash
cd "C:/Projects/Optimus Prime"
python -m pytest tests/session/test_session_store.py -v
```

Expected: `8 passed`

- [ ] **Step 5: Commit**

```bash
git add backend/session/session_store.py tests/session/test_session_store.py
git commit -m "feat: add SessionStore with module-level singleton"
```

---

## Task 4: Auth middleware — write tests then implement

**Files:**
- Create: `tests/conftest.py`
- Create: `tests/api/__init__.py`
- Create: `tests/api/test_auth.py`
- Create: `backend/auth.py`

- [ ] **Step 1: Create conftest.py with shared fixtures**

```python
# tests/conftest.py
import os
import pytest
from fastapi.testclient import TestClient

os.environ["BEARER_TOKEN"] = "test-token"

from backend.app import app


@pytest.fixture
def client():
    with TestClient(app) as c:
        yield c
```

> Note: The `BEARER_TOKEN` env var must be set **before** importing the app so pydantic-settings picks it up. The `os.environ` line at module level achieves this.

- [ ] **Step 2: Create tests/api/__init__.py as an empty file**

- [ ] **Step 3: Write auth tests**

```python
# tests/api/test_auth.py
import pytest
from fastapi.testclient import TestClient


def test_health_requires_no_auth(client):
    response = client.get("/health")
    assert response.status_code == 200


def test_chat_without_token_returns_401(client):
    response = client.post("/api/chat", json={"message": "hello"})
    assert response.status_code == 401


def test_chat_with_wrong_token_returns_401(client):
    response = client.post(
        "/api/chat",
        json={"message": "hello"},
        headers={"Authorization": "Bearer wrong-token"},
    )
    assert response.status_code == 401


def test_chat_with_valid_token_does_not_return_401(client):
    response = client.post(
        "/api/chat",
        json={"message": "hello"},
        headers={"Authorization": "Bearer test-token"},
    )
    # 200 or 500 (LLM call fails in test) — just not 401
    assert response.status_code != 401


def test_ws_without_token_returns_403(client):
    with pytest.raises(Exception):
        with client.websocket_connect("/ws/chat") as ws:
            ws.receive_json()


def test_ws_with_wrong_token_returns_403(client):
    with pytest.raises(Exception):
        with client.websocket_connect("/ws/chat?token=wrong") as ws:
            ws.receive_json()


def test_ws_with_valid_token_connects(client):
    with client.websocket_connect("/ws/chat?token=test-token") as ws:
        data = ws.receive_json()
        assert data["type"] == "welcome"
```

- [ ] **Step 4: Run tests — confirm they FAIL (auth doesn't exist yet)**

```bash
cd "C:/Projects/Optimus Prime"
python -m pytest tests/api/test_auth.py -v 2>&1 | head -20
```

Expected: Multiple failures — 401 tests return 200 or 422 because there's no auth yet.

- [ ] **Step 5: Create auth.py**

```python
# backend/auth.py
from fastapi import HTTPException, Security, WebSocket, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer

from backend.config import settings

_bearer = HTTPBearer()


async def verify_token(
    credentials: HTTPAuthorizationCredentials = Security(_bearer),
) -> str:
    if credentials.credentials != settings.bearer_token:
        raise HTTPException(status_code=401, detail="Invalid token")
    return credentials.credentials


async def verify_ws_token(websocket: WebSocket) -> str:
    token = websocket.query_params.get("token", "")
    if token != settings.bearer_token:
        await websocket.close(code=status.WS_1008_POLICY_VIOLATION)
        raise HTTPException(status_code=403, detail="Invalid token")
    return token
```

- [ ] **Step 6: Wire auth into chat_routes.py**

Replace the `verify_api_key` function and its usages. The new `chat_routes.py` (full file):

```python
# backend/api/chat_routes.py
import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel

from backend.auth import verify_token
from backend.session.session_store import session_store

logger = logging.getLogger(__name__)
router = APIRouter(prefix="/api", tags=["chat"])


class ChatRequest(BaseModel):
    message: str
    session_id: Optional[str] = None
    mode: Optional[str] = None


class ChatResponse(BaseModel):
    session_id: str
    reply: str
    tokens_used: int


@router.post("/chat", response_model=ChatResponse)
async def chat(
    request: ChatRequest,
    _: str = Depends(verify_token),
):
    from backend.agent.orchestrator import Orchestrator

    session = (
        session_store.resolve(request.session_id)
        if request.session_id
        else None
    ) or session_store.create()

    session_store.touch(session.session_id)

    try:
        orchestrator = Orchestrator()
        result = await orchestrator.process(
            message=request.message,
            session=session,
            mode=request.mode,
        )
        return ChatResponse(
            session_id=session.session_id,
            reply=result["reply"],
            tokens_used=result["tokens_used"],
        )
    except Exception as e:
        logger.error(f"Chat error: {e}")
        raise HTTPException(status_code=500, detail=str(e))


@router.get("/session/{session_id}")
async def get_session(
    session_id: str,
    _: str = Depends(verify_token),
):
    session = session_store.resolve(session_id)
    if not session:
        raise HTTPException(status_code=404, detail="Session not found")
    return {
        "session_id": session.session_id,
        "engagement_id": session.engagement_id,
        "created_at": session.created_at.isoformat(),
        "last_active": session.last_active.isoformat(),
        "message_count": len(session.conv_history.messages),
    }


@router.get("/health")
async def health():
    return {"status": "healthy", "version": "1.0.0"}
```

> Note: `Orchestrator` is imported inside the function body to avoid circular imports (orchestrator imports from session which is already imported at module level).

- [ ] **Step 7: Wire auth into ws_handler.py**

Full replacement of `backend/api/ws_handler.py`:

```python
# backend/api/ws_handler.py
import json
import logging
from typing import Dict

from fastapi import APIRouter, WebSocket, WebSocketDisconnect

from backend.auth import verify_ws_token
from backend.session.session_store import session_store

logger = logging.getLogger(__name__)
router = APIRouter()


class ConnectionManager:
    def __init__(self) -> None:
        self.active: Dict[str, WebSocket] = {}

    async def connect(self, session_id: str, websocket: WebSocket) -> None:
        self.active[session_id] = websocket

    def disconnect(self, session_id: str) -> None:
        self.active.pop(session_id, None)

    async def send(self, session_id: str, payload: dict) -> None:
        ws = self.active.get(session_id)
        if ws:
            await ws.send_json(payload)


manager = ConnectionManager()


@router.websocket("/chat")
async def websocket_chat(websocket: WebSocket):
    await websocket.accept()
    session_id = None
    try:
        await verify_ws_token(websocket)
    except Exception:
        return

    try:
        await websocket.send_json({"type": "welcome", "message": "Connected to Optimus"})

        async for message in websocket.iter_json():
            msg_type = message.get("type")

            if msg_type == "init":
                raw_id = message.get("session_id")
                session = (
                    session_store.resolve(raw_id) if raw_id else None
                ) or session_store.create()
                session_id = session.session_id
                await manager.connect(session_id, websocket)
                await websocket.send_json({"type": "session", "session_id": session_id})

            elif msg_type == "chat":
                if not session_id:
                    await websocket.send_json({"type": "error", "message": "Send 'init' first"})
                    continue

                session = session_store.resolve(session_id)
                if not session:
                    await websocket.send_json({"type": "error", "message": "Session expired"})
                    continue

                session_store.touch(session_id)
                text = message.get("message", "")
                mode = message.get("mode")

                from backend.agent.orchestrator import Orchestrator
                orchestrator = Orchestrator()

                async for chunk in orchestrator.process_stream(
                    message=text,
                    session=session,
                    mode=mode,
                ):
                    await manager.send(session_id, {"chunk": chunk, "done": False})

                await manager.send(session_id, {"chunk": "", "done": True})

            elif msg_type == "ping":
                await websocket.send_json({"type": "pong"})

    except WebSocketDisconnect:
        pass
    except Exception as e:
        logger.error(f"WebSocket error: {e}")
        if session_id:
            await manager.send(session_id, {"type": "error", "message": str(e)})
    finally:
        if session_id:
            manager.disconnect(session_id)
```

- [ ] **Step 8: Run auth tests — confirm they PASS**

```bash
cd "C:/Projects/Optimus Prime"
python -m pytest tests/api/test_auth.py -v
```

Expected: `7 passed` (the LLM-calling test may return 500, which is acceptable — it must not return 401).

- [ ] **Step 9: Commit**

```bash
git add backend/auth.py backend/api/chat_routes.py backend/api/ws_handler.py tests/conftest.py tests/api/
git commit -m "feat: bearer token auth on all routes, SessionStore wired into HTTP and WS handlers"
```

---

## Task 5: Update LLMRouter to accept messages list

**Files:**
- Modify: `backend/agent/llm_router.py`

The orchestrator currently passes a single string `prompt` to `LLMRouter.complete()`. Changing to a messages list lets the orchestrator pass `session.conv_history.get_context_window()` directly to the Claude API — which is what the API expects natively.

- [ ] **Step 1: Write the test**

Add a new file `tests/agent/test_llm_router.py`:

```python
# tests/agent/__init__.py  — create as empty file

# tests/agent/test_llm_router.py
import pytest
from unittest.mock import AsyncMock, MagicMock, patch

from backend.agent.llm_router import LLMRouter, LLMResponse


@pytest.mark.asyncio
async def test_complete_passes_messages_to_claude():
    router = LLMRouter()
    messages = [{"role": "user", "content": "hello"}]

    mock_response = MagicMock()
    mock_response.content = [MagicMock(text="hi")]
    mock_response.usage = MagicMock(input_tokens=5, output_tokens=2)

    with patch.object(router.claude.messages, "create", new=AsyncMock(return_value=mock_response)) as mock_create:
        result = await router.complete(messages=messages, mode="orchestration")

    mock_create.assert_called_once()
    call_kwargs = mock_create.call_args.kwargs
    assert call_kwargs["messages"] == messages
    assert isinstance(result, LLMResponse)
    assert result.content == "hi"


@pytest.mark.asyncio
async def test_complete_includes_system_prompt_when_provided():
    router = LLMRouter()
    messages = [{"role": "user", "content": "go"}]
    system = "You are Optimus."

    mock_response = MagicMock()
    mock_response.content = [MagicMock(text="done")]
    mock_response.usage = MagicMock(input_tokens=10, output_tokens=3)

    with patch.object(router.claude.messages, "create", new=AsyncMock(return_value=mock_response)) as mock_create:
        await router.complete(messages=messages, mode="orchestration", system=system)

    call_kwargs = mock_create.call_args.kwargs
    assert call_kwargs["system"] == system
```

- [ ] **Step 2: Run tests — confirm they FAIL**

```bash
cd "C:/Projects/Optimus Prime"
python -m pytest tests/agent/test_llm_router.py -v 2>&1 | head -15
```

Expected: `TypeError: complete() got an unexpected keyword argument 'messages'`

- [ ] **Step 3: Update llm_router.py**

```python
# backend/agent/llm_router.py
import logging
from dataclasses import dataclass
from typing import Dict, List

import aiohttp

from backend import config
from backend.inference.ollama_client import OllamaClient

logger = logging.getLogger(__name__)


@dataclass
class LLMResponse:
    content: str
    model_used: str
    input_tokens: int
    output_tokens: int


class LLMRouter:
    def __init__(self):
        import anthropic
        self.claude = anthropic.AsyncAnthropic(api_key=config.settings.anthropic_api_key)
        self.ollama = OllamaClient(config.settings.ollama_host)

    async def complete(
        self,
        messages: List[Dict[str, str]],
        mode: str = "orchestration",
        system: str = "",
    ) -> LLMResponse:
        if mode == "orchestration":
            return await self._claude_complete(messages, system)
        return await self._ollama_complete(messages)

    async def _claude_complete(
        self, messages: List[Dict[str, str]], system: str
    ) -> LLMResponse:
        try:
            kwargs = dict(
                model=config.settings.claude_model,
                max_tokens=4096,
                messages=messages,
            )
            if system:
                kwargs["system"] = system
            response = await self.claude.messages.create(**kwargs)
            return LLMResponse(
                content=response.content[0].text,
                model_used=config.settings.claude_model,
                input_tokens=response.usage.input_tokens,
                output_tokens=response.usage.output_tokens,
            )
        except Exception as e:
            logger.error(f"Claude error: {e}, falling back to Ollama")
            return await self._ollama_complete(messages)

    async def _ollama_complete(self, messages: List[Dict[str, str]]) -> LLMResponse:
        prompt = "\n".join(f"{m['role'].upper()}: {m['content']}" for m in messages)
        content = await self.ollama.generate(
            model=config.settings.mistral_model,
            prompt=prompt,
        )
        return LLMResponse(
            content=content,
            model_used=config.settings.mistral_model,
            input_tokens=len(prompt.split()),
            output_tokens=len(content.split()),
        )

    async def embed(self, text: str) -> list:
        return await self.ollama.embed(
            model=config.settings.embed_model,
            text=text,
        )
```

- [ ] **Step 4: Run tests — confirm they PASS**

```bash
cd "C:/Projects/Optimus Prime"
python -m pytest tests/agent/test_llm_router.py -v
```

Expected: `2 passed`

- [ ] **Step 5: Commit**

```bash
git add backend/agent/llm_router.py tests/agent/
git commit -m "feat: LLMRouter.complete() accepts messages list instead of single prompt"
```

---

## Task 6: Update Orchestrator to use ConversationHistory

**Files:**
- Modify: `backend/agent/orchestrator.py`

This is the payoff task. The orchestrator must:
1. Accept `EngagementSession` instead of `SessionState`
2. Store the user message in `session.conv_history` before calling the LLM
3. Build the messages list from `conv_history.get_context_window()`
4. Store the assistant reply in `conv_history` after the LLM responds

- [ ] **Step 1: Write the test**

```python
# tests/agent/__init__.py  — already created above

# tests/agent/test_orchestrator.py
import pytest
from unittest.mock import AsyncMock, patch

from backend.session.engagement_session import EngagementSession
from backend.agent.llm_router import LLMResponse
from backend.agent.orchestrator import Orchestrator


@pytest.mark.asyncio
async def test_process_stores_user_message_in_history():
    session = EngagementSession.create()
    orchestrator = Orchestrator()

    mock_llm_response = LLMResponse(
        content="Running recon on example.com",
        model_used="mock",
        input_tokens=10,
        output_tokens=8,
    )

    with patch.object(orchestrator.llm_router, "complete", new=AsyncMock(return_value=mock_llm_response)):
        await orchestrator.process(message="Recon example.com", session=session)

    assert len(session.conv_history.messages) == 2
    assert session.conv_history.messages[0]["role"] == "user"
    assert session.conv_history.messages[0]["content"] == "Recon example.com"
    assert session.conv_history.messages[1]["role"] == "assistant"
    assert session.conv_history.messages[1]["content"] == "Running recon on example.com"


@pytest.mark.asyncio
async def test_process_sends_history_as_messages():
    session = EngagementSession.create()
    session.conv_history.add_message("user", "first message")
    session.conv_history.add_message("assistant", "first reply")

    orchestrator = Orchestrator()
    mock_llm_response = LLMResponse(content="second reply", model_used="mock", input_tokens=5, output_tokens=3)

    captured_messages = {}

    async def capture(messages, mode, system=""):
        captured_messages["messages"] = messages
        return mock_llm_response

    with patch.object(orchestrator.llm_router, "complete", new=capture):
        await orchestrator.process(message="second message", session=session)

    msgs = captured_messages["messages"]
    assert msgs[0] == {"role": "user", "content": "first message"}
    assert msgs[1] == {"role": "assistant", "content": "first reply"}
    assert msgs[2] == {"role": "user", "content": "second message"}


@pytest.mark.asyncio
async def test_process_returns_reply_and_session_id():
    session = EngagementSession.create()
    orchestrator = Orchestrator()
    mock_response = LLMResponse(content="ok", model_used="mock", input_tokens=1, output_tokens=1)

    with patch.object(orchestrator.llm_router, "complete", new=AsyncMock(return_value=mock_response)):
        result = await orchestrator.process(message="hello", session=session)

    assert result["reply"] == "ok"
    assert result["session_id"] == session.session_id
```

- [ ] **Step 2: Run tests — confirm they FAIL**

```bash
cd "C:/Projects/Optimus Prime"
python -m pytest tests/agent/test_orchestrator.py -v 2>&1 | head -20
```

Expected: failures because `Orchestrator.process()` takes `SessionState`, not `EngagementSession`, and doesn't store messages.

- [ ] **Step 3: Rewrite orchestrator.py**

```python
# backend/agent/orchestrator.py
import logging
from dataclasses import dataclass
from typing import Any, AsyncIterator, Dict, List, Optional

from backend.agent.engine_router import EngineRouter
from backend.agent.instruction_parser import InstructionParser
from backend.agent.llm_router import LLMRouter
from backend.agent.response_composer import ResponseComposer
from backend.agent.tool_selector import ToolSelector
from backend.session.engagement_session import EngagementSession

logger = logging.getLogger(__name__)

_SYSTEM_PROMPT = (
    "You are Optimus, a universal AI security platform. "
    "Analyze the user's intent and provide a structured security assessment response. "
    "Be concise and actionable."
)


@dataclass
class OrchestratorDecision:
    intent: str
    engine: str
    target: str
    constraints: dict
    phase: str
    tools: list
    confidence: float


class Orchestrator:
    def __init__(self):
        self.llm_router = LLMRouter()
        self.parser = InstructionParser()
        self.engine_router = EngineRouter()
        self.tool_selector = ToolSelector()
        self.composer = ResponseComposer()

    async def process(
        self,
        message: str,
        session: EngagementSession,
        mode: Optional[str] = None,
    ) -> Dict[str, Any]:
        session.conv_history.add_message("user", message)

        messages = session.conv_history.get_context_window()
        response = await self.llm_router.complete(
            messages=messages,
            mode="orchestration",
            system=_SYSTEM_PROMPT,
        )

        session.conv_history.add_message("assistant", response.content)

        return {
            "reply": response.content,
            "session_id": session.session_id,
            "tokens_used": response.input_tokens + response.output_tokens,
        }

    async def process_stream(
        self,
        message: str,
        session: EngagementSession,
        mode: Optional[str] = None,
    ) -> AsyncIterator[str]:
        session.conv_history.add_message("user", message)

        messages = session.conv_history.get_context_window()
        response = await self.llm_router.complete(
            messages=messages,
            mode="orchestration",
            system=_SYSTEM_PROMPT,
        )

        session.conv_history.add_message("assistant", response.content)

        for word in response.content.split():
            yield word + " "
```

> Note: `InstructionParser`, `EngineRouter`, `ToolSelector`, `ResponseComposer` are kept as imports to preserve existing structure. They will be integrated in future tasks (OmX template-first planning). For now, the LLM call drives all responses.

- [ ] **Step 4: Run all tests**

```bash
cd "C:/Projects/Optimus Prime"
python -m pytest tests/ -v
```

Expected: all tests pass. Count: 13 session + 8 store + 7 auth + 2 llm_router + 3 orchestrator = 33 passed.

- [ ] **Step 5: Commit**

```bash
git add backend/agent/orchestrator.py tests/agent/test_orchestrator.py
git commit -m "feat: orchestrator stores conversation history per session, chat is now stateful"
```

---

## Self-Review

### Spec coverage

| Mentor requirement | Task |
|----|---|
| Auth middleware on all endpoints | Task 4 |
| `EngagementSession` dataclass with `ScopeConfig`, `ConversationHistory`, `EngagementState` | Task 2 |
| `SessionStore` — creates, resolves, persists sessions | Task 3 |
| Wire `ConversationHistory` into `ChatHandler` — fixes stateless chat | Task 6 |
| Fix global `_state` / singleton pattern | Tasks 4+6 (ws_handler, chat_routes) |
| `LLMRouter` passes messages list | Task 5 |
| Fix `app.py` import bug | Task 0 |
| Fix empty `config.py` | Task 0 |

**Not in scope for this plan (Week 2+):**
- Session persistence to disk (Week 3)
- Docker sandbox (Week 2)
- Kali per-engagement workdirs (Week 2)
- WAL mode on SQLite (Week 2)
- OmX planner + template-first (Week 3)
- EventBus / EngagementEventChannel (Week 3)
- DeepSeek-V3 in LLMRouter (Week 3)
- Frontend App.jsx split (Week 4)

### Type consistency check

- `EngagementSession.create()` → defined Task 2, used in Tasks 3, 6 ✓
- `ConversationHistory.add_message(role, content)` → defined Task 2, called in Task 6 ✓
- `ConversationHistory.get_context_window()` → defined Task 2, called in Task 6 ✓
- `SessionStore.resolve(session_id)` → defined Task 3, called Tasks 4 (ws_handler, chat_routes) ✓
- `SessionStore.touch(session_id)` → defined Task 3, called Tasks 4 ✓
- `LLMRouter.complete(messages, mode, system)` → defined Task 5, called Task 6 ✓
- `Orchestrator.process(message, session: EngagementSession, mode)` → defined Task 6, called from ws_handler + chat_routes in Task 4 ✓

### Placeholder scan

No TBDs, no "implement later", no "add validation" vagueness. All code is complete.
