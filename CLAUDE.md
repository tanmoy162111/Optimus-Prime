<!-- GSD:project-start source:PROJECT.md -->
## Project

**Optimus Prime**

A personal-use AI security platform that orchestrates autonomous penetration testing engagements through a multi-agent system. The operator interacts via a browser-based chat UI; the system routes intent through LLM-driven agents (Recon, Scan, Exploit, Verify, Cloud, IAM, ICS, etc.) that execute real tools on a Kali Linux backend over SSH. Built for a single operator running structured, AI-guided engagements against defined targets.

**Core Value:** A solo operator can run a complete structured pentest engagement — from scoping through exploitation through reporting — with AI agents handling tool chaining and the operator reviewing findings, not running commands.

### Constraints

- **Personal use:** Single operator, no auth hardening beyond static bearer token required for now
- **Tech stack:** Python/FastAPI backend, React frontend — no stack changes
- **Kali connection:** SSH via Paramiko — operator manages their own Kali instance
- **LLM providers:** Multi-provider by design — Anthropic SDK + Ollama local + additional pay-per-call API providers (e.g. DeepSeek) as orchestration needs dictate. No rented/provisioned cloud GPU infrastructure — API-metered spend only.
- **No breaking changes to BaseAgent loop** — mentor confirmed this abstraction is correct; all agents inherit from it
<!-- GSD:project-end -->

<!-- GSD:stack-start source:codebase/STACK.md -->
## Technology Stack

## Languages
- Python 3.12 - Backend (FastAPI), ML runtimes, agents, intelligence modules
- TypeScript 5.4.0 - Frontend development (type definitions)
- JavaScript (Node.js 20) - Frontend runtime, React build system
- Bash - Docker entrypoints and container initialization (`backend/entrypoint.sh`, `kali/entrypoint.sh`)
- SQL - SQLite database schema and queries
## Runtime
- Python 3.12 (backend services via Docker)
- Node.js 20-alpine (frontend via Docker)
- Docker 3.8+ (containerization)
- pip (Python dependencies) - Lockfile: `backend/requirements.txt`
- npm (JavaScript dependencies) - Lockfile: `frontend/package-lock.json`
## Frameworks
- FastAPI 0.115.0 - REST API and WebSocket server (`backend/app.py`, `backend/main.py`)
- Uvicorn 0.32.0 - ASGI server for FastAPI
- Pydantic 2.9.2 - Data validation and settings management (`backend/config.py`)
- Pydantic-settings 2.6.1 - Environment variable configuration
- Next.js 14.2.0 - React metaframework (`frontend/pages/`, `frontend/src/`)
- React 18.3.0 - UI library
- React DOM 18.3.0 - React rendering target
- pytest 8.3.3 - Python test runner (`backend/tests/`)
- pytest-asyncio 0.24.0 - Async test support (`pyproject.toml` config: asyncio_mode="auto")
- Vitest - JavaScript test framework (configured in `frontend/vite.config.js`)
- Vite - Frontend development server and bundler (`frontend/vite.config.js`)
- npm scripts - Frontend build automation (`frontend/package.json`)
## Key Dependencies
- anthropic 0.38.0 - Claude API client for LLM orchestration (`backend/agent/llm_router.py`)
- paramiko 3.5.0 - SSH client for Kali Linux execution (`backend/execution/ssh_client.py`)
- aiohttp 3.10.10 - Async HTTP client for Ollama and external APIs (`backend/inference/ollama_client.py`, `backend/intelligence/source_adapters.py`)
- httpx 0.27.2 - Sync/async HTTP client for research sources (`backend/intelligence/source_adapters.py`)
- python-socketio[client] 5.12.0 - WebSocket client for real-time communication
- tiktoken 0.7.0 - Token counting for Claude API usage tracking
- python-json-logger 2.0.7 - Structured logging
- socket.io-client 4.7.0 - WebSocket client for real-time backend communication
- zustand 4.5.0 - State management
- adversarial-robustness-toolbox[pytorch,tensorflow] 1.20.1 - Adversarial robustness testing (`ml-runtime/requirements.txt`)
- foolbox - Adversarial examples generation
- torch - PyTorch ML framework
- tensorflow - TensorFlow ML framework
- scikit-learn - Machine learning utilities
- promptfoo - Prompt injection testing
- weasyprint 62.3 - HTML to PDF conversion for reports (`backend/requirements.txt`)
## Configuration
- Location: `.env` (template: `.env.example`)
- LLM Configuration:
- Execution Configuration:
- Tor Proxy:
- Budget Management:
- Storage:
- `backend/config.py` - Pydantic BaseSettings class loads environment variables
- `frontend/vite.config.js` - Vite server with proxy to backend
- `frontend/package.json` - npm scripts (dev, build, start)
- `tailwind.config.js` - Tailwind CSS configuration
- `postcss.config.js` - PostCSS configuration
- `pyproject.toml` - pytest configuration and project metadata
- `Dockerfile` (backend) - Python 3.12-slim base, pip install
- `Dockerfile` (frontend) - Node.js 20-alpine base, npm install
- `.env.example` - Configuration template
## Platform Requirements
- Python >= 3.12
- Node.js >= 20
- Docker and Docker Compose 3.8+
- Bash shell
- Docker with Docker Compose
- Memory allocation: Backend 4GB, Frontend 1GB, Ollama 8GB, ML-Runtime 8GB, Kali 4GB
- CPU allocation: Backend 2 cores, Frontend 1 core, Ollama 4 cores, ML-Runtime 4 cores, Kali 2 cores
- Docker Compose (local/on-premise) via `docker-compose.yml`
- Container orchestration ready (FastAPI/Uvicorn stateless, config-driven)
<!-- GSD:stack-end -->

<!-- GSD:conventions-start source:CONVENTIONS.md -->
## Conventions

## Naming Patterns
- Python backend: lowercase with underscores (`llm_router.py`, `conversation.py`, `base_agent.py`)
- React/JSX frontend: PascalCase for components (`ChatPane.tsx`, `App.jsx`), lowercase for utilities
- Python test files: `test_<module_name>.py` pattern (e.g., `test_orchestrator.py`, `test_exploit_agent_fallback.py`)
- Python: snake_case (`async def complete()`, `def dispatch()`, `async def _claude_complete()`)
- Private methods: leading underscore (`_is_ml_target()`, `_count_by_severity()`, `_plan_with_llm()`)
- React: camelCase for all functions and hooks (`useWebSocket`, `handleSend`, `fmtTime`)
- Python: snake_case throughout (`session_id`, `token_budget_used`, `confirmed_findings`)
- React: camelCase for state and refs (`messagesEnd`, `socketRef`, `retryCountRef`, `connected`)
- Constants: UPPER_SNAKE_CASE when constants are module-level (e.g., `EXPLOIT_SYSTEM_PROMPT_CONTROLLED`, `_CONTROLLED_TOOLS`)
- Python dataclasses: PascalCase (`SessionState`, `ChatMessage`, `Finding`, `LLMResponse`, `OrchestratorDecision`)
- Python Enums: PascalCase class, UPPER_SNAKE_CASE values (`class EngineType(str, enum.Enum)` with `INFRASTRUCTURE = "infrastructure"`)
- TypeScript/React interfaces: PascalCase (`interface Message`, `interface Session`)
## Code Style
- No explicit formatter configured (no .eslintrc, .prettierrc found)
- Python: 4-space indentation (standard Python convention observed)
- React: 2-space indentation observed in JSX files
- Line length: Python files vary; some use docstring sections with `# ────` dividers
- No ESLint or Prettier config detected in frontend
- Python: No explicit linting config in pyproject.toml
- Tests use pytest patterns and conventions
- Python modules use docstrings with section headers at top:
- Docstrings reference architecture sections (Section 5.2, Section 10, etc.)
- Class docstrings often include mode descriptions and available tools
- No JSDoc annotations found in frontend
## Import Organization
- No import aliases observed
- Full module paths always used: `from backend.agent.orchestrator import Orchestrator`
- React hooks first: `import { useState, useEffect, useRef, useCallback } from 'react'`
- Third-party libraries: `import io, { Socket } from 'socket.io-client'`
- Lucide-react icons in separate import: `import { Shield, Activity, ... } from 'lucide-react'`
## Error Handling
- Python raises custom exceptions: `raise FrozenInstanceError(f"SessionState is frozen - cannot modify {name}")`
- Fallback pattern: `logger.error(f"Claude error: {e}, falling back to Ollama")` in `backend/agent/llm_router.py`
- Try-catch pattern in React WebSocket: `try { ws.send(...) } catch {}`
- Silent failures common in async operations: wrapped in try-catch with no re-raise
- Custom: `FrozenInstanceError` in `backend/agent/conversation.py`
- Custom: `ToolPermissionError` in `backend/agent/sub_agents/base.py`
- No exception hierarchy observed; limited use of custom exceptions
## Logging
- Module-level logger: `logger = logging.getLogger(__name__)`
- Used sparingly in agent layer: only found in `llm_router.py` and `agents/` modules
- Error logging on fallbacks: `logger.error(f"Claude error: {e}, falling back to Ollama")`
- No frontend logging framework detected; development uses console (implicit)
## Comments
- Architecture section numbers cited (e.g., "Section 10, N6", "Section 5.2")
- Docstrings at module and class level for high-level behavior
- Inline comments explain complex logic (e.g., tool fallback resolution)
- Not used in Python code
- Not used in React/TypeScript code
- Type annotations via TypeScript interfaces sufficient
## Function Design
- Varies; small utility functions (10-20 lines) and large complex functions (100+ lines in test fixtures)
- Example: `dispatch()` in `backend/agent/engine_router.py` is ~15 lines
- Example: `test_pentest_e2e.py` fixture `mock_tool_executor()` is 100+ lines
- Dataclass-heavy: most functions accept dataclass instances rather than multiple parameters
- Example: `async def execute(self, target: str, **kwargs) -> Dict[str, Any]` in `BaseAgent`
- Kwargs pattern used for flexibility: `await agent.execute(task, **config)`
- Explicit return types in signatures: `-> Dict[str, Any]`, `-> LLMResponse`, `-> bool`
- Dataclass returns common: `LLMResponse`, `OrchestratorDecision`, `EngagementSession`
- Dict unpacking used: `decision.get("intent", "general")`
## Module Design
- No `__all__` declarations observed
- Modules import specific classes: `from backend.agent.orchestrator import Orchestrator`
- Python init files exist but empty: `backend/agent/__init__.py`, `tests/agent/__init__.py`
- Not used; imports are fully qualified paths
- Pattern: `from backend.agent.llm_router import LLMRouter` (not from `backend.agent`)
## Async/Await Patterns
- Prefixed with `async def` throughout agent and core modules
- Called with `await` consistently
- Example: `async def complete()`, `async def execute()`, `async def process()`
- Mock async functions in tests: `AsyncMock()` from `unittest.mock`
- Async fixtures in pytest: `@pytest.fixture async def event_bus(tmp_path):`
- WebSocket setup in React uses async/await for health checks: `await fetch('/health')`
## Type Annotations
- Type hints on function signatures: `def dispatch(self, intent: str, target: str = None) -> str:`
- Optional types: `Optional[str]`, `Optional[Dict]`
- Complex types: `Dict[str, Any]`, `List[Dict[str, str]]`, `AsyncIterator`
- Dataclass field types: `session_id: str`, `created_at: datetime`, `priority: int = 1`
- Interfaces for complex objects: `interface Message`, `interface Session`
- Inline types in hooks: `useState<boolean>()`, `useRef<HTMLDivElement>(null)`
- No explicit return type annotations in component functions
## Data Structures
- Preferred for domain models: `SessionState`, `ChatMessage`, `Finding`, `LLMResponse`
- Fields with defaults: `priority: int = 1`, `mode: str = "InfrastructureEngine"`
- Factory defaults: `allowed_tools: List[str] = field(default_factory=list)`
- Post-init customization: `__post_init__` used in `SessionState` for frozen state setup
- String enums common: `class EngineType(str, enum.Enum): INFRASTRUCTURE = "infrastructure"`
- State machines via enums: `ToolPromotion`, `TaskStatus`, `VerifyMode`
- Uppercase values in lowercase string enums for safety
- Frozensets for tool lists: `_CONTROLLED_TOOLS = frozenset({...})`
- Dict comprehensions not observed; direct dict construction
- Lists over tuples for mutable collections
<!-- GSD:conventions-end -->

<!-- GSD:architecture-start source:ARCHITECTURE.md -->
## Architecture

## Pattern Overview
- **Layered with clear boundaries:** New system uses FastAPI microservice pattern; old system bundles all layers into single application
- **Agent-based execution:** Security sub-agents specialized by domain (cloud, IAM, endpoint, exploit, intel, etc.)
- **LLM-driven orchestration:** Multiple LLM providers (Claude primary, Ollama fallback) for decision-making
- **Event-sourced findings:** Results published to event log and memory system
- **Session-based context:** Per-engagement session state with conversation history and scope config
- **Tool-gated execution:** Permission pipeline, hook runners, and tool executors control what runs
## Layers
- Purpose: Accept user requests via REST and WebSocket, route to orchestrator
- Location: `backend/api/ws_handler.py`, `backend/api/chat_routes.py`
- Contains: ConnectionManager, WebSocket lifecycle, message routing
- Depends on: Session store, Orchestrator
- Used by: Frontend (React), client applications
- Purpose: High-level request interpretation, agent dispatch, response composition
- Location: `backend/agent/orchestrator.py`
- Contains: Orchestrator class that coordinates LLMRouter, EngineRouter, ToolSelector, ResponseComposer
- Depends on: LLMRouter, InstructionParser, EngineRouter, ToolSelector, ResponseComposer, EngagementSession
- Used by: WebSocket handler, chat routes
- Purpose: Route user intent to appropriate engine/agent domain
- Location: `backend/agent/llm_router.py`, `backend/agent/engine_router.py`, `backend/agent/instruction_parser.py`
- Contains: 
- Depends on: Claude SDK, Ollama client, conversation history
- Used by: Orchestrator
- Purpose: Specialized security agents execute domain-specific tools
- Location: `backend/agent/sub_agents/` (new: cloud_agent.py, endpoint_agent.py, exploit_agent.py, etc.)
- Contains: BaseAgent abstract class, 12 domain-specific agents (CloudAgent, IAMAgent, ReconAgent, ScanAgent, etc.)
- Depends on: ToolSelector, ToolRegistry, execution backends (SSH, subprocess, IPC)
- Used by: EngineRouter/Orchestrator, Tool execution pipeline
- Purpose: Execute actual security tools on target systems or local environment
- Location: `backend/tools/`, `backend/execution/`, `backend/verification/`
- Contains: ToolRegistry, ToolExecutor, SSH client, shell manager, sandbox manager
- Depends on: Paramiko, subprocess, tool configurations
- Used by: Agents
- Purpose: Persist engagement state, conversation history, findings, client profiles
- Location: `backend/session/engagement_session.py`, `backend/session/session_store.py`, `backend/memory/smart_memory.py`, `backend/memory/client_profile.py`
- Contains: 
- Depends on: UUID, datetime, embeddings
- Used by: Orchestrator, API layer
- Purpose: Cross-cutting intelligence, reporting, compliance, knowledge bases
- Location: `backend/intelligence/`, `backend/reporting/`, `backend/knowledge/`
- Contains: 
- Depends on: Source adapters (NVD, CISA, GitHub PoCs, MITRE Attack, blogs, ExploitDB, dark web)
- Used by: Reporting endpoints, agents
- Purpose: Old 6-layer architecture used before refactor (retained for fallback/reference)
- Location: `backend/core/`, `backend/agents/`, `backend/main.py`
- Contains: 
- Depends on: All M0-M3 subsystems (hooks, permissions, event bus)
- Used by: Legacy code paths only
## Data Flow
- **Conversation history:** Stored in EngagementSession.conv_history.messages (List[Dict[role, content]])
- **Findings:** Stored in EngagementSession.state.findings (List[Dict])
- **Phase tracking:** EngagementSession.state.phase_status (Dict[phase_id, status])
- **Scope:** EngagementSession.scope (targets, exclusions, stealth_level, ports, protocols)
- **Global state:** SessionStore._sessions (Dict[session_id, EngagementSession]) — in-memory only
## Key Abstractions
- Purpose: Container for all session state (scope, history, findings, state machine)
- Examples: `backend/session/engagement_session.py`
- Pattern: Dataclass with factory method `EngagementSession.create(engagement_id)`
- Purpose: Tracks user/assistant messages with sliding context window
- Examples: `EngagementSession.conv_history.add_message(role, content)`
- Pattern: Append-only list with `get_context_window()` returning last N messages
- Purpose: Abstract LLM provider selection (Claude vs Ollama)
- Examples: `backend/agent/llm_router.py`
- Pattern: Strategy pattern with `complete(messages, mode, system)` returning LLMResponse
- Purpose: Abstract base for all security agents
- Examples: `backend/agent/sub_agents/base.py`
- Pattern: ABC with `async execute(target, **kwargs)` and permission checking
- Purpose: Route intent/target to appropriate execution engine
- Examples: `backend/agent/engine_router.py` → MLAIEngine, ICSEngine, InfrastructureEngine
- Pattern: Simple dispatcher with intent pattern matching and target extension detection
- Purpose: Coordinate all routing, LLM calls, tool selection
- Examples: `backend/agent/orchestrator.py`
- Pattern: Facade composing LLMRouter, EngineRouter, ToolSelector, ResponseComposer
## Entry Points
- Location: `backend/app.py` line 45: `GET /health`
- Triggers: Application liveness check
- Responsibilities: Return {"status": "healthy", "version": "1.0.0"}
- Location: `backend/api/chat_routes.py` line 26: `POST /api/chat`
- Triggers: REST client sends ChatRequest (message, session_id, mode)
- Responsibilities: Create/resolve session, call Orchestrator.process(), return ChatResponse
- Location: `backend/api/ws_handler.py` line 32: `WS /ws/chat`
- Triggers: WebSocket client connects with token query param
- Responsibilities: 
- Location: `backend/app.py` line 26-51
- Triggers: `uvicorn.run()` or application server starts
- Responsibilities:
## Error Handling
- **API errors:** Wrap orchestrator calls in try/except, return HTTPException(status_code=500, detail=str(e))
- **WebSocket errors:** Log exception, send error message to client before closing
- **LLM fallback:** On Claude error, fall back to Ollama
- **Token validation:** Close WebSocket with WS_1008_POLICY_VIOLATION on invalid token
- **Stale sessions:** Return error to client if session expires during chat
## Cross-Cutting Concerns
- Framework: Python logging module
- Format: `"%(asctime)s | %(name)-30s | %(levelname)-8s | %(message)s"`
- Usage: Each module creates logger with `logging.getLogger(__name__)`
- Example: `backend/agent/llm_router.py` line 1, 8
- Token validation via HTTPBearer in REST API: `backend/auth.py` verify_token()
- WebSocket token from query params: `backend/auth.py` verify_ws_token()
- Schema validation via Pydantic models: ChatRequest, ChatResponse in `backend/api/chat_routes.py`
- Method: Bearer token (static string from .env)
- Implementation: `backend/auth.py` with HTTPBearer and custom WebSocket handler
- Token source: `settings.bearer_token` from environment
- Creation: SessionStore.create() on first chat or explicit "init"
- Access: SessionStore.resolve(session_id) to retrieve
- Update: SessionStore.touch(session_id) updates last_active timestamp
- Cleanup: In-memory; no explicit garbage collection (relies on process lifetime)
<!-- GSD:architecture-end -->

<!-- GSD:workflow-start source:GSD defaults -->
## GSD Workflow Enforcement

Before using Edit, Write, or other file-changing tools, start work through a GSD command so planning artifacts and execution context stay in sync.

Use these entry points:
- `/gsd:quick` for small fixes, doc updates, and ad-hoc tasks
- `/gsd:debug` for investigation and bug fixing
- `/gsd:execute-phase` for planned phase work

Do not make direct repo edits outside a GSD workflow unless the user explicitly asks to bypass it.
<!-- GSD:workflow-end -->



<!-- GSD:profile-start -->
## Developer Profile

> Profile not yet configured. Run `/gsd:profile-user` to generate your developer profile.
> This section is managed by `generate-claude-profile` -- do not edit manually.
<!-- GSD:profile-end -->
