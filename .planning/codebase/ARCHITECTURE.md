# Architecture

**Analysis Date:** 2026-05-12

## Pattern Overview

**Overall:** Dual-system hybrid architecture with a new event-driven orchestration layer running alongside legacy 6-layer monolith architecture. The system is transitioning from old (`backend/core/`, `backend/agents/`, `backend/main.py`) to new (`backend/agent/`, `backend/app.py`). The new system is currently active and routes requests; legacy code remains for reference/fallback.

**Key Characteristics:**
- **Layered with clear boundaries:** New system uses FastAPI microservice pattern; old system bundles all layers into single application
- **Agent-based execution:** Security sub-agents specialized by domain (cloud, IAM, endpoint, exploit, intel, etc.)
- **LLM-driven orchestration:** Multiple LLM providers (Claude primary, Ollama fallback) for decision-making
- **Event-sourced findings:** Results published to event log and memory system
- **Session-based context:** Per-engagement session state with conversation history and scope config
- **Tool-gated execution:** Permission pipeline, hook runners, and tool executors control what runs

## Layers

**API/WebSocket Gateway:**
- Purpose: Accept user requests via REST and WebSocket, route to orchestrator
- Location: `backend/api/ws_handler.py`, `backend/api/chat_routes.py`
- Contains: ConnectionManager, WebSocket lifecycle, message routing
- Depends on: Session store, Orchestrator
- Used by: Frontend (React), client applications

**Orchestration Layer:**
- Purpose: High-level request interpretation, agent dispatch, response composition
- Location: `backend/agent/orchestrator.py`
- Contains: Orchestrator class that coordinates LLMRouter, EngineRouter, ToolSelector, ResponseComposer
- Depends on: LLMRouter, InstructionParser, EngineRouter, ToolSelector, ResponseComposer, EngagementSession
- Used by: WebSocket handler, chat routes

**Routing & Decision Layer:**
- Purpose: Route user intent to appropriate engine/agent domain
- Location: `backend/agent/llm_router.py`, `backend/agent/engine_router.py`, `backend/agent/instruction_parser.py`
- Contains: 
  - LLMRouter: Routes to Claude (orchestration mode) or Ollama (fallback)
  - EngineRouter: Dispatches to MLAIEngine, ICSEngine, or InfrastructureEngine based on intent/target
  - InstructionParser: Parses user intent from conversation
- Depends on: Claude SDK, Ollama client, conversation history
- Used by: Orchestrator

**Agent Execution Layer:**
- Purpose: Specialized security agents execute domain-specific tools
- Location: `backend/agent/sub_agents/` (new: cloud_agent.py, endpoint_agent.py, exploit_agent.py, etc.)
- Contains: BaseAgent abstract class, 12 domain-specific agents (CloudAgent, IAMAgent, ReconAgent, ScanAgent, etc.)
- Depends on: ToolSelector, ToolRegistry, execution backends (SSH, subprocess, IPC)
- Used by: EngineRouter/Orchestrator, Tool execution pipeline

**Tool Execution Layer:**
- Purpose: Execute actual security tools on target systems or local environment
- Location: `backend/tools/`, `backend/execution/`, `backend/verification/`
- Contains: ToolRegistry, ToolExecutor, SSH client, shell manager, sandbox manager
- Depends on: Paramiko, subprocess, tool configurations
- Used by: Agents

**Session & Memory Layer:**
- Purpose: Persist engagement state, conversation history, findings, client profiles
- Location: `backend/session/engagement_session.py`, `backend/session/session_store.py`, `backend/memory/smart_memory.py`, `backend/memory/client_profile.py`
- Contains: 
  - EngagementSession: per-session state wrapper
  - ConversationHistory: message tracking with context window
  - EngagementState: phase status, findings, gate queue
  - SessionStore: in-memory session registry
  - SmartMemory: semantic memory with embeddings
  - ClientProfileDB: client-specific preferences
- Depends on: UUID, datetime, embeddings
- Used by: Orchestrator, API layer

**Supporting Systems Layer:**
- Purpose: Cross-cutting intelligence, reporting, compliance, knowledge bases
- Location: `backend/intelligence/`, `backend/reporting/`, `backend/knowledge/`
- Contains: 
  - IntelligentReporter: Multi-format report generation
  - ComplianceMappingDB: NIST-CSF, PCI-DSS, GDPR, ISO27001, SOC2 mappings
  - ResearchKB: Vulnerability knowledge base
  - ResearchDaemon: Background threat intel collection
  - StrategyEvolutionEngine: Adaptive testing strategy
  - CustomToolGenerator: Generate tools from goals (three-gate pipeline)
- Depends on: Source adapters (NVD, CISA, GitHub PoCs, MITRE Attack, blogs, ExploitDB, dark web)
- Used by: Reporting endpoints, agents

**Legacy Core Layer (Deprecated but present):**
- Purpose: Old 6-layer architecture used before refactor (retained for fallback/reference)
- Location: `backend/core/`, `backend/agents/`, `backend/main.py`
- Contains: 
  - OmX/OmO: Old orchestration pipeline
  - ChatHandler: Old conversation handler
  - EventBus/DurableEventLog: Event sourcing
  - PermissionPipeline: Access control
  - TaskRegistry: Legacy task dispatch
  - TokenBudgetManager: Token tracking
  - Base agents (ReconAgent, ScanAgent, etc. old versions)
- Depends on: All M0-M3 subsystems (hooks, permissions, event bus)
- Used by: Legacy code paths only

## Data Flow

**User Chat Message Flow:**

1. Frontend sends JSON via WebSocket: `{"type": "chat", "message": "scan 192.168.1.0/24"}`
2. `ws_handler.websocket_chat()` receives, verifies token, looks up/creates EngagementSession
3. Session stored in SessionStore (in-memory Dict[session_id, EngagementSession])
4. Message sent to `Orchestrator.process_stream()`
5. Orchestrator adds message to session's `ConversationHistory`
6. LLMRouter.complete() calls Claude with conversation context window (40 messages max)
7. Claude returns orchestration response (intent, confidence, suggested agents)
8. ResponseComposer formats response
9. Response streamed back to frontend word-by-word via WebSocket chunking
10. Session state updated with assistant message and any findings
11. WebSocket client receives chunks and renders in real-time

**Tool Execution Flow (Legacy, documented for reference):**

1. Agent receives task (e.g., "nmap -p 22,80,443 target")
2. ToolSelector resolves tool from registry
3. ToolExecutor validates permissions via PermissionPipeline
4. Tool runs on execution backend (SSH to Kali, local subprocess, IPC for sandboxes)
5. Result captured and classified (finding, error, partial)
6. Finding published to DurableEventLog (persists 24h)
7. Event broadcast to all connected clients via WebSocket event stream
8. Finding stored in session's state.findings list
9. ResponseComposer incorporates findings into next LLM prompt

**Session Lifetime:**

1. `session_store.create()` → new EngagementSession with UUID session_id
2. First WebSocket `init` message associates user with session_id
3. `session_store.touch(session_id)` updates `last_active` on each message
4. Session remains in-memory; NOT persisted to disk
5. On disconnect: session may be garbage collected or kept for replay

**State Management:**

- **Conversation history:** Stored in EngagementSession.conv_history.messages (List[Dict[role, content]])
- **Findings:** Stored in EngagementSession.state.findings (List[Dict])
- **Phase tracking:** EngagementSession.state.phase_status (Dict[phase_id, status])
- **Scope:** EngagementSession.scope (targets, exclusions, stealth_level, ports, protocols)
- **Global state:** SessionStore._sessions (Dict[session_id, EngagementSession]) — in-memory only

## Key Abstractions

**EngagementSession:**
- Purpose: Container for all session state (scope, history, findings, state machine)
- Examples: `backend/session/engagement_session.py`
- Pattern: Dataclass with factory method `EngagementSession.create(engagement_id)`

**ConversationHistory:**
- Purpose: Tracks user/assistant messages with sliding context window
- Examples: `EngagementSession.conv_history.add_message(role, content)`
- Pattern: Append-only list with `get_context_window()` returning last N messages

**LLMRouter:**
- Purpose: Abstract LLM provider selection (Claude vs Ollama)
- Examples: `backend/agent/llm_router.py`
- Pattern: Strategy pattern with `complete(messages, mode, system)` returning LLMResponse

**BaseAgent:**
- Purpose: Abstract base for all security agents
- Examples: `backend/agent/sub_agents/base.py`
- Pattern: ABC with `async execute(target, **kwargs)` and permission checking

**EngineRouter:**
- Purpose: Route intent/target to appropriate execution engine
- Examples: `backend/agent/engine_router.py` → MLAIEngine, ICSEngine, InfrastructureEngine
- Pattern: Simple dispatcher with intent pattern matching and target extension detection

**Orchestrator:**
- Purpose: Coordinate all routing, LLM calls, tool selection
- Examples: `backend/agent/orchestrator.py`
- Pattern: Facade composing LLMRouter, EngineRouter, ToolSelector, ResponseComposer

## Entry Points

**HTTP Health Check:**
- Location: `backend/app.py` line 45: `GET /health`
- Triggers: Application liveness check
- Responsibilities: Return {"status": "healthy", "version": "1.0.0"}

**REST Chat API:**
- Location: `backend/api/chat_routes.py` line 26: `POST /api/chat`
- Triggers: REST client sends ChatRequest (message, session_id, mode)
- Responsibilities: Create/resolve session, call Orchestrator.process(), return ChatResponse

**WebSocket Chat Endpoint:**
- Location: `backend/api/ws_handler.py` line 32: `WS /ws/chat`
- Triggers: WebSocket client connects with token query param
- Responsibilities: 
  1. Verify token via HTTPBearer
  2. Handle "init" message → create session
  3. Handle "chat" message → stream from Orchestrator.process_stream()
  4. Handle "ping" → respond "pong"
  5. Cleanup on disconnect

**Application Startup:**
- Location: `backend/app.py` line 26-51
- Triggers: `uvicorn.run()` or application server starts
- Responsibilities:
  1. Create FastAPI app with CORS middleware
  2. Include routers (chat_routes, ws_handler)
  3. Register health check
  4. Execute lifespan startup/shutdown hooks (currently no-op)

## Error Handling

**Strategy:** Exception propagation with logging, HTTP 500 on API errors, WebSocket error messages

**Patterns:**

- **API errors:** Wrap orchestrator calls in try/except, return HTTPException(status_code=500, detail=str(e))
  - Example: `backend/api/chat_routes.py` line 41-55

- **WebSocket errors:** Log exception, send error message to client before closing
  - Example: `backend/api/ws_handler.py` line 87-90

- **LLM fallback:** On Claude error, fall back to Ollama
  - Example: `backend/agent/llm_router.py` line 54-55

- **Token validation:** Close WebSocket with WS_1008_POLICY_VIOLATION on invalid token
  - Example: `backend/auth.py` line 19-22

- **Stale sessions:** Return error to client if session expires during chat
  - Example: `backend/api/ws_handler.py` line 62-64

## Cross-Cutting Concerns

**Logging:**
- Framework: Python logging module
- Format: `"%(asctime)s | %(name)-30s | %(levelname)-8s | %(message)s"`
- Usage: Each module creates logger with `logging.getLogger(__name__)`
- Example: `backend/agent/llm_router.py` line 1, 8

**Validation:**
- Token validation via HTTPBearer in REST API: `backend/auth.py` verify_token()
- WebSocket token from query params: `backend/auth.py` verify_ws_token()
- Schema validation via Pydantic models: ChatRequest, ChatResponse in `backend/api/chat_routes.py`

**Authentication:**
- Method: Bearer token (static string from .env)
- Implementation: `backend/auth.py` with HTTPBearer and custom WebSocket handler
- Token source: `settings.bearer_token` from environment

**Session Lifecycle:**
- Creation: SessionStore.create() on first chat or explicit "init"
- Access: SessionStore.resolve(session_id) to retrieve
- Update: SessionStore.touch(session_id) updates last_active timestamp
- Cleanup: In-memory; no explicit garbage collection (relies on process lifetime)

---

*Architecture analysis: 2026-05-12*
