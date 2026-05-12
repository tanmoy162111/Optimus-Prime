# Coding Conventions

**Analysis Date:** 2026-05-12

## Naming Patterns

**Files:**
- Python backend: lowercase with underscores (`llm_router.py`, `conversation.py`, `base_agent.py`)
- React/JSX frontend: PascalCase for components (`ChatPane.tsx`, `App.jsx`), lowercase for utilities
- Python test files: `test_<module_name>.py` pattern (e.g., `test_orchestrator.py`, `test_exploit_agent_fallback.py`)

**Functions:**
- Python: snake_case (`async def complete()`, `def dispatch()`, `async def _claude_complete()`)
- Private methods: leading underscore (`_is_ml_target()`, `_count_by_severity()`, `_plan_with_llm()`)
- React: camelCase for all functions and hooks (`useWebSocket`, `handleSend`, `fmtTime`)

**Variables:**
- Python: snake_case throughout (`session_id`, `token_budget_used`, `confirmed_findings`)
- React: camelCase for state and refs (`messagesEnd`, `socketRef`, `retryCountRef`, `connected`)
- Constants: UPPER_SNAKE_CASE when constants are module-level (e.g., `EXPLOIT_SYSTEM_PROMPT_CONTROLLED`, `_CONTROLLED_TOOLS`)

**Types:**
- Python dataclasses: PascalCase (`SessionState`, `ChatMessage`, `Finding`, `LLMResponse`, `OrchestratorDecision`)
- Python Enums: PascalCase class, UPPER_SNAKE_CASE values (`class EngineType(str, enum.Enum)` with `INFRASTRUCTURE = "infrastructure"`)
- TypeScript/React interfaces: PascalCase (`interface Message`, `interface Session`)

## Code Style

**Formatting:**
- No explicit formatter configured (no .eslintrc, .prettierrc found)
- Python: 4-space indentation (standard Python convention observed)
- React: 2-space indentation observed in JSX files
- Line length: Python files vary; some use docstring sections with `# ────` dividers

**Linting:**
- No ESLint or Prettier config detected in frontend
- Python: No explicit linting config in pyproject.toml
- Tests use pytest patterns and conventions

**Docstring Style:**
- Python modules use docstrings with section headers at top:
  ```python
  """EventBus with DurableEventLog — SQLite-backed event system (Section 10, N6).
  
  Every event is written to a SQLite append-log before delivery...
  """
  ```
- Docstrings reference architecture sections (Section 5.2, Section 10, etc.)
- Class docstrings often include mode descriptions and available tools
- No JSDoc annotations found in frontend

## Import Organization

**Order (Python):**
1. Standard library (`import asyncio`, `from dataclasses import`, `from typing import`)
2. Third-party (`import pytest`, `from unittest.mock import`, `import anthropic`)
3. Backend modules (`from backend.agent.`, `from backend.core.`, `from backend.session.`)

**Path Aliases:**
- No import aliases observed
- Full module paths always used: `from backend.agent.orchestrator import Orchestrator`

**Frontend Imports:**
- React hooks first: `import { useState, useEffect, useRef, useCallback } from 'react'`
- Third-party libraries: `import io, { Socket } from 'socket.io-client'`
- Lucide-react icons in separate import: `import { Shield, Activity, ... } from 'lucide-react'`

## Error Handling

**Patterns:**
- Python raises custom exceptions: `raise FrozenInstanceError(f"SessionState is frozen - cannot modify {name}")`
- Fallback pattern: `logger.error(f"Claude error: {e}, falling back to Ollama")` in `backend/agent/llm_router.py`
- Try-catch pattern in React WebSocket: `try { ws.send(...) } catch {}`
- Silent failures common in async operations: wrapped in try-catch with no re-raise

**Exception Classes:**
- Custom: `FrozenInstanceError` in `backend/agent/conversation.py`
- Custom: `ToolPermissionError` in `backend/agent/sub_agents/base.py`
- No exception hierarchy observed; limited use of custom exceptions

## Logging

**Framework:** Python `logging` module

**Patterns:**
- Module-level logger: `logger = logging.getLogger(__name__)`
- Used sparingly in agent layer: only found in `llm_router.py` and `agents/` modules
- Error logging on fallbacks: `logger.error(f"Claude error: {e}, falling back to Ollama")`
- No frontend logging framework detected; development uses console (implicit)

## Comments

**When to Comment:**
- Architecture section numbers cited (e.g., "Section 10, N6", "Section 5.2")
- Docstrings at module and class level for high-level behavior
- Inline comments explain complex logic (e.g., tool fallback resolution)

**JSDoc/TSDoc:**
- Not used in Python code
- Not used in React/TypeScript code
- Type annotations via TypeScript interfaces sufficient

## Function Design

**Size:** 
- Varies; small utility functions (10-20 lines) and large complex functions (100+ lines in test fixtures)
- Example: `dispatch()` in `backend/agent/engine_router.py` is ~15 lines
- Example: `test_pentest_e2e.py` fixture `mock_tool_executor()` is 100+ lines

**Parameters:**
- Dataclass-heavy: most functions accept dataclass instances rather than multiple parameters
- Example: `async def execute(self, target: str, **kwargs) -> Dict[str, Any]` in `BaseAgent`
- Kwargs pattern used for flexibility: `await agent.execute(task, **config)`

**Return Values:**
- Explicit return types in signatures: `-> Dict[str, Any]`, `-> LLMResponse`, `-> bool`
- Dataclass returns common: `LLMResponse`, `OrchestratorDecision`, `EngagementSession`
- Dict unpacking used: `decision.get("intent", "general")`

## Module Design

**Exports:**
- No `__all__` declarations observed
- Modules import specific classes: `from backend.agent.orchestrator import Orchestrator`
- Python init files exist but empty: `backend/agent/__init__.py`, `tests/agent/__init__.py`

**Barrel Files:**
- Not used; imports are fully qualified paths
- Pattern: `from backend.agent.llm_router import LLMRouter` (not from `backend.agent`)

## Async/Await Patterns

**Async Functions:**
- Prefixed with `async def` throughout agent and core modules
- Called with `await` consistently
- Example: `async def complete()`, `async def execute()`, `async def process()`

**Async Context:**
- Mock async functions in tests: `AsyncMock()` from `unittest.mock`
- Async fixtures in pytest: `@pytest.fixture async def event_bus(tmp_path):`
- WebSocket setup in React uses async/await for health checks: `await fetch('/health')`

## Type Annotations

**Python:**
- Type hints on function signatures: `def dispatch(self, intent: str, target: str = None) -> str:`
- Optional types: `Optional[str]`, `Optional[Dict]`
- Complex types: `Dict[str, Any]`, `List[Dict[str, str]]`, `AsyncIterator`
- Dataclass field types: `session_id: str`, `created_at: datetime`, `priority: int = 1`

**TypeScript/React:**
- Interfaces for complex objects: `interface Message`, `interface Session`
- Inline types in hooks: `useState<boolean>()`, `useRef<HTMLDivElement>(null)`
- No explicit return type annotations in component functions

## Data Structures

**Dataclasses:**
- Preferred for domain models: `SessionState`, `ChatMessage`, `Finding`, `LLMResponse`
- Fields with defaults: `priority: int = 1`, `mode: str = "InfrastructureEngine"`
- Factory defaults: `allowed_tools: List[str] = field(default_factory=list)`
- Post-init customization: `__post_init__` used in `SessionState` for frozen state setup

**Enums:**
- String enums common: `class EngineType(str, enum.Enum): INFRASTRUCTURE = "infrastructure"`
- State machines via enums: `ToolPromotion`, `TaskStatus`, `VerifyMode`
- Uppercase values in lowercase string enums for safety

**Collections:**
- Frozensets for tool lists: `_CONTROLLED_TOOLS = frozenset({...})`
- Dict comprehensions not observed; direct dict construction
- Lists over tuples for mutable collections

---

*Convention analysis: 2026-05-12*
