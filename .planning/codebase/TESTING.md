# Testing Patterns

**Analysis Date:** 2026-05-12

## Test Framework

**Runner:**
- pytest 7.x+ (specified in `pyproject.toml`)
- Config: `pyproject.toml` [tool.pytest.ini_options] section
- Async support: `asyncio_mode = "auto"` enables auto-detection of async tests

**Assertion Library:**
- pytest built-in assertions (`assert` statements)
- No additional assertion libraries (no `assertpy`, `hamcrest`)

**Run Commands:**
```bash
pytest                           # Run backend/tests/ (default testpaths)
pytest --asyncio-mode=auto      # Explicit async mode
pytest -v                        # Verbose output
pytest tests/                    # Run new test suite (tests/)
pytest backend/tests/            # Run old test suite
```

**Frontend Testing:**
- Vitest 4.x (inferred from `App.test.jsx`)
- No explicit config file found
- React Testing Library for component testing
- No separate test run command detected in package.json

## Test File Organization

**Location:**
- **Old suite** (imports from `backend.core`, `backend.agents`): `backend/tests/test_*.py`
  - 323 test functions across 20+ files
  - Contains: `test_base_agent_resilience.py`, `test_exploit_agent_fallback.py`, `test_pentest_e2e.py`
- **New suite** (imports from `backend.agent`): `tests/` directory with subdirectories
  - 33 test functions across multiple files
  - Structure: `tests/agent/`, `tests/api/`, `tests/session/`, `tests/llm_validation/`
- **Frontend tests**: `frontend/src/App.test.jsx` (React component tests)

**Naming:**
- Python: `test_<feature>.py` (e.g., `test_orchestrator.py`, `test_auth.py`)
- Test functions: `test_<scenario>` (e.g., `test_process_stores_user_message_in_history`)
- Test classes: `Test<Feature>` (e.g., `TestRunLoopToolNotFound`, `TestConversationHistory`)

**Structure:**
```
backend/tests/
├── test_base_agent_resilience.py     # Agent resilience patterns
├── test_exploit_agent_fallback.py    # Exploit agent modes
├── test_pentest_e2e.py              # E2E engagement flow
├── test_event_bus.py                # Event system
├── test_kali_connection_mgr.py      # Tool execution backend
└── ... (20+ more)

tests/
├── __init__.py
├── conftest.py                       # Shared fixtures
├── agent/
│   ├── test_orchestrator.py
│   ├── test_llm_router.py
│   └── __init__.py
├── api/
│   ├── test_auth.py
│   └── __init__.py
├── session/
│   ├── test_engagement_session.py
│   ├── test_session_store.py
│   └── __init__.py
└── llm_validation/
    └── inputs.py                     # Test data

frontend/src/
└── App.test.jsx                      # React hook tests
```

## Test Structure

**Suite Organization (Python):**
```python
# backend/tests/test_pentest_e2e.py — Full E2E test
@pytest.fixture
async def event_bus(tmp_path):
    log = DurableEventLog(db_path=tmp_path / "e2e_test.db")
    bus = EventBus(durable_log=log)
    await bus.initialize()
    yield bus
    await bus.close()

class TestRunLoopToolNotFound:
    @pytest.mark.asyncio
    async def test_tool_not_found_triggers_alternative(self):
        # Setup
        executor = AsyncMock()
        agent = _SimpleAgent(...)
        
        # Act
        result = await agent.execute(_make_task())
        
        # Assert
        assert "amass" in call_log
```

**Patterns:**
- **Setup**: Fixtures with yield for cleanup (not `setup_method`)
- **Async setup**: `@pytest.fixture async def` with `await` during init/teardown
- **Teardown**: implicit via `yield` statement; cleanup code after yield
- **Assertions**: Direct `assert` statements; 552 assertions across backend/tests/
- **Mocking**: `AsyncMock()`, `MagicMock()` from `unittest.mock`
- **Patching**: `patch.object()` for method replacement

**Frontend Suite Organization (Vitest):**
```typescript
// frontend/src/App.test.jsx
describe('useWebSocket', () => {
  beforeEach(() => {
    vi.useFakeTimers()
    global.WebSocket = MockWebSocket
  })

  afterEach(() => {
    vi.useRealTimers()
    vi.restoreAllMocks()
  })

  it('connects when backend is healthy', async () => {
    const onMessage = vi.fn()
    const { result } = renderHook(() => useWebSocket('ws://localhost/ws', onMessage))
    
    await act(async () => { await flushPromises() })
    
    expect(lastWs).not.toBeNull()
  })
})
```

**Patterns:**
- `describe()` blocks for grouping related tests
- `beforeEach()` / `afterEach()` for test isolation
- `vi.useFakeTimers()` for time control
- `renderHook()` from React Testing Library for hook testing
- `await act()` wrapper for state updates
- `vi.fn()` for spy/mock functions

## Mocking

**Framework:** `unittest.mock` (Python), `vitest` spies (React)

**Python Patterns:**
```python
# AsyncMock for async functions
executor = AsyncMock()

async def mock_execute(**kwargs):
    tool = kwargs.get("tool_name")
    if tool == "sublist3r":
        return ToolResult(success=True, output={"status": "tool_not_found"})
    return ToolResult(success=True, output={"stdout": "amass output"})

executor.execute = mock_execute

# Patch method on object
with patch.object(orchestrator.llm_router, "complete", new=AsyncMock(return_value=mock_response)):
    result = await orchestrator.process(...)

# MagicMock for complex returns
mock_response = MagicMock()
mock_response.content = [MagicMock(text="hi")]
mock_response.usage = MagicMock(input_tokens=5, output_tokens=2)
```

**React Patterns:**
```typescript
// Mock WebSocket class
class MockWebSocket {
  constructor(url) { this.url = url; this.readyState = 0 }
  send(data) { this.sentMessages.push(data) }
  _open() { this.readyState = 1; this.onopen?.() }
  _message(data) { this.onmessage?.({ data: JSON.stringify(data) }) }
}

// Mock fetch
global.fetch = vi.fn().mockResolvedValue({ ok: true })

// Spy on functions
const onMessage = vi.fn()
```

**What to Mock:**
- External services: LLM APIs (Claude, Ollama), event buses, tool executors
- I/O operations: file system, database reads/writes
- Network calls: HTTP requests, WebSocket connections
- Timers: `vi.useFakeTimers()` for timer-dependent logic

**What NOT to Mock:**
- Core business logic: agent dispatch, decision trees
- Data structures: dataclasses, enums
- Utility functions: formatting, parsing
- Fixture factories that create test data

## Fixtures and Factories

**Test Data (Python):**
```python
# backend/tests/test_pentest_e2e.py
@pytest.fixture
def mock_tool_executor():
    executor = AsyncMock()
    
    async def mock_execute(**kwargs):
        tool = kwargs.get("tool_name", "unknown")
        outputs = {
            "crt_sh": ToolResult(success=True, output="*.example.com, api.example.com"),
            "nmap": ToolResult(success=True, output="80/tcp open http...", 
                             is_finding=True, findings=[{"port": 80, "service": "http"}]),
            # ... 20+ tool outputs
        }
        return outputs.get(tool, ToolResult(success=False))
    
    executor.execute = mock_execute
    return executor

# Helper to create task objects
def _make_task():
    return AgentTask(task_id="t1", agent_class="test", prompt="Execute test against 10.0.0.1")

# Agent factory for testing
class _SimpleAgent(BaseAgent):
    def __init__(self, actions, **kwargs):
        super().__init__(**kwargs)
        self._planned_actions = list(actions)
```

**Test Data (React):**
```typescript
// App.test.jsx — Mock WebSocket message data
lastWs._message({ seq: 42, event_type: 'SYSTEM_STARTED' })
lastWs._message({ 
  type: 'welcome', 
  session_id: 'abc123',
  connected: true 
})
```

**Location:**
- Python fixtures: inline in test files or `tests/conftest.py` (shared fixtures)
- Reusable data: `tests/llm_validation/inputs.py` (test inputs)
- Backend main fixture: `tests/conftest.py` sets `BEARER_TOKEN=test-token` and provides `client` fixture

## Coverage

**Requirements:** None enforced in `pyproject.toml`

**View Coverage:**
```bash
pytest --cov=backend --cov-report=html  # Not configured; manual command
pytest --cov=backend                     # Console output
```

**Current State:**
- Old test suite (`backend/tests/`): 323 test functions, extensive coverage
- New test suite (`tests/`): 33 test functions, covers new agent layer and API endpoints
- No coverage metrics enforced

## Test Types

**Unit Tests:**
- Scope: Single function/method in isolation
- Example: `test_dispatch_routes_ml_intent_to_mlai_engine()` in orchestrator tests
- Mocks: External dependencies (LLM, tools, event bus)
- Run time: <100ms per test

**Integration Tests:**
- Scope: Multiple components working together
- Example: `test_process_stores_user_message_in_history()` tests orchestrator + session + history
- Fixtures: Shared event bus, mock executors
- Covered in both suites

**E2E Tests:**
- Scope: Full engagement flow from user input to finding verification
- Example: `test_pentest_e2e.py` executes OmX plan → OmO execution → agents → verification loop
- Fixtures: DurableEventLog, mock tool executor returning realistic output
- Produces 3+ confirmed findings; verifies event sequencing

**Frontend Tests (Vitest):**
- Focus: Hook behavior (WebSocket lifecycle, retry logic)
- Not component rendering tests (no test snapshots)
- Example: `it('connects when backend is healthy')`, `it('sends heartbeat ping every 25s')`

## Common Patterns

**Async Testing:**
```python
# pytest.mark.asyncio decorator enables async/await in tests
@pytest.mark.asyncio
async def test_process_stores_user_message_in_history():
    session = EngagementSession.create()
    orchestrator = Orchestrator()
    
    with patch.object(...) as mock:
        await orchestrator.process(message="Recon example.com", session=session)
    
    assert len(session.conv_history.messages) == 2

# React: await act() for async state updates
await act(async () => { await flushPromises() })
```

**Error Testing:**
```python
# Check exception is raised
def test_frozen_session_raises_error():
    state = SessionState()
    state._frozen = True
    with pytest.raises(FrozenInstanceError):
        state.some_field = "value"

# Check fallback behavior on error
async def test_claude_error_falls_back_to_ollama():
    router = LLMRouter()
    with patch.object(router.claude.messages, "create", side_effect=Exception("API error")):
        result = await router.complete(messages=[...])  # Should call Ollama
```

**Fixture Cleanup:**
```python
# Yield pattern for guaranteed cleanup
@pytest.fixture
async def event_bus(tmp_path):
    log = DurableEventLog(db_path=tmp_path / "test.db")
    bus = EventBus(durable_log=log)
    await bus.initialize()
    yield bus               # Test runs here
    await bus.close()       # Cleanup always runs
```

**Time Control (React):**
```typescript
// Fake timers for testing retry logic
beforeEach(() => { vi.useFakeTimers() })

// Advance time to trigger delayed operations
await act(async () => { vi.advanceTimersByTime(1000) })

// Verify backoff delays were applied
// First retry: 1000ms = 2^0 * 1000
// Second retry: 2000ms = 2^1 * 1000
```

## Test Import Issues (CRITICAL)

**Import Split:**
- **backend/tests/** imports from old module paths:
  - `from backend.core.base_agent import BaseAgent`
  - `from backend.core.models import AgentTask`
  - `from backend.agents.exploit_agent import ExploitAgent`
  
- **tests/** imports from new module paths:
  - `from backend.agent.orchestrator import Orchestrator`
  - `from backend.agent.llm_router import LLMRouter`
  - `from backend.session.engagement_session import EngagementSession`

**Problem:**
- Both `backend/core/` and `backend/agent/` exist as separate implementations
- `backend/tests/` tests the old architecture; `tests/` tests the new one
- No unified test suite covering the full migrated codebase
- pytest config (`pyproject.toml`) points only to `backend/tests` — new tests in `tests/` are not run by default

**Flag:**
- `backend/tests/` must migrate imports to use `backend.agent.*` if new modules are production code
- OR: `backend/agent/` modules are stubs and `backend/core/` + `backend/agents/` remain canonical
- Verify module ownership with architecture documentation before test migration

## Coverage Gaps

**Untested Areas:**
- `backend/agent/conversation_summariser.py`: No dedicated tests (new module)
- `backend/agent/credential_vault.py`: No dedicated tests (new module)
- `backend/agent/instruction_parser.py`: Minimal tests
- `backend/agent/token_budget_manager.py`: No dedicated tests
- Frontend component rendering: No component tests (only hook tests)
- Error recovery: Limited exception path coverage in new tests
- Performance/scaling: No load tests or stress tests

**Risk:**
- New agent orchestration layer (`backend/agent/`) lacks integration test coverage
- Frontend components untested for rendering; only hooks tested
- Credential and token management not validated in test suite

---

*Testing analysis: 2026-05-12*
