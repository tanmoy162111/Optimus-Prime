# Codebase Structure

**Analysis Date:** 2026-05-12

## Directory Layout

```
Optimus Prime/
├── backend/                        # Python FastAPI backend (NEW active system)
│   ├── app.py                      # FastAPI app definition, lifespan, health check
│   ├── main.py                     # Old 846-line monolithic entry point (DEPRECATED)
│   ├── config.py                   # Settings (bearer_token, API keys, model names, Kali SSH config)
│   ├── auth.py                     # Token verification (REST Bearer, WebSocket query param)
│   ├── __init__.py
│   ├── requirements.txt
│   ├── Dockerfile
│   │
│   ├── api/                        # NEW: REST/WebSocket endpoints
│   │   ├── __init__.py
│   │   ├── chat_routes.py          # POST /api/chat, GET /api/session/{session_id}
│   │   └── ws_handler.py           # WS /ws/chat with ConnectionManager and WebSocket lifecycle
│   │
│   ├── agent/                      # NEW: Orchestration system (active)
│   │   ├── __init__.py
│   │   ├── orchestrator.py         # Main Orchestrator class, process_stream(), OrchestratorDecision
│   │   ├── llm_router.py           # Route to Claude (primary) or Ollama (fallback)
│   │   ├── engine_router.py        # Dispatch to MLAIEngine, ICSEngine, InfrastructureEngine
│   │   ├── instruction_parser.py   # Parse user intent from messages
│   │   ├── tool_selector.py        # Select appropriate tools for agent
│   │   ├── response_composer.py    # Format LLM response for client
│   │   ├── conversation.py         # Conversation utilities
│   │   ├── conversation_summariser.py  # Summarize long conversation histories
│   │   ├── credential_vault.py     # Store/retrieve credentials
│   │   ├── token_budget_manager.py # Track token usage across LLM calls
│   │   │
│   │   └── sub_agents/             # Domain-specific agent implementations
│   │       ├── __init__.py
│   │       ├── base.py             # BaseAgent abstract class
│   │       ├── cloud_agent.py      # AWS, Azure, GCP security
│   │       ├── iam_agent.py        # IAM/access control testing
│   │       ├── endpoint_agent.py   # Endpoint hardening, antivirus evasion
│   │       ├── exploit_agent.py    # Exploit selection and execution
│   │       ├── scan_agent.py       # Network scanning (nmap, etc.)
│   │       ├── recon_agent.py      # Reconnaissance (OSINT)
│   │       ├── intel_agent.py      # Threat intelligence gathering
│   │       ├── data_sec_agent.py   # Data security, encryption, DLP
│   │       ├── genai_agent.py      # GenAI/LLM security (prompt injection, etc.)
│   │       ├── model_sec_agent.py  # ML model security
│   │       └── ics_agent.py        # ICS/SCADA/OT security
│   │
│   ├── agents/                     # OLD: Legacy agent implementations (DEPRECATED)
│   │   ├── base_agent.py
│   │   ├── cloud_agent.py
│   │   ├── datasec_agent.py
│   │   ├── endpoint_agent.py
│   │   ├── exploit_agent.py
│   │   ├── iam_agent.py
│   │   └── ... (other legacy agents)
│   │
│   ├── core/                       # OLD: 6-layer monolith architecture (DEPRECATED)
│   │   ├── base_agent.py           # Old AgentAction, ToolResult, BaseAgent
│   │   ├── chat_handler.py         # Old conversation and orchestration
│   │   ├── credential_vault.py     # Old credential storage
│   │   ├── event_bus.py            # DurableEventLog, EventBus (event sourcing)
│   │   ├── hook_runner.py          # Pre/post execution hooks
│   │   ├── llm_router.py           # Old LLMRouter with ClaudeProvider, OllamaProvider
│   │   ├── models.py               # Old ScopeConfig, AgentTask, Finding, etc.
│   │   ├── omo.py                  # Old "Optimized Multi-Agent Orchestrator"
│   │   ├── omx.py                  # Old "Orchestration Multi-eXecution" engine
│   │   ├── permission.py           # PermissionEnforcer, PermissionPipeline
│   │   ├── scope_enforcer.py       # Scope validation
│   │   ├── stealth_enforcer.py     # Stealth level enforcement
│   │   ├── namespace_enforcer.py   # Namespace isolation
│   │   ├── session.py              # Old session model
│   │   ├── task_registry.py        # Task dispatch registry
│   │   ├── tool_executor.py        # Tool execution with result classification
│   │   ├── tool_fallback.py        # Tool fallback logic
│   │   ├── terminal_broadcaster.py # WebSocket event broadcasting
│   │   ├── xai_logger.py           # Explainable AI logging
│   │   └── exceptions.py
│   │
│   ├── session/                    # NEW: Session state management
│   │   ├── __init__.py
│   │   ├── engagement_session.py   # EngagementSession, ConversationHistory, EngagementState, ScopeConfig
│   │   └── session_store.py        # SessionStore (in-memory Dict[session_id, EngagementSession])
│   │
│   ├── execution/                  # Tool execution backends
│   │   ├── __init__.py
│   │   ├── ssh_client.py           # Paramiko SSH client for Kali Linux
│   │   └── shell_manager.py        # Local subprocess execution
│   │
│   ├── tools/                      # Tool registry and management
│   │   ├── __init__.py
│   │   ├── tool_registry.py        # Registry of available tools
│   │   ├── tool_spec.py            # Tool specification dataclass
│   │   ├── sandbox_manager.py      # Sandbox environment management
│   │   │
│   │   └── backends/               # Execution backends for different tool types
│   │       ├── __init__.py
│   │       ├── kali_ssh.py         # KaliConnectionManager for Kali SSH
│   │       ├── local_subprocess.py # Local command execution
│   │       ├── sandbox.py          # Sandbox execution
│   │       ├── ipc_backend.py      # Inter-process communication
│   │       ├── ics_runtime_ipc.py  # ICS/OT runtime IPC
│   │       ├── ml_runtime_ipc.py   # ML model runtime IPC
│   │       └── tor_socks5.py       # Tor proxy support
│   │
│   ├── inference/                  # LLM providers
│   │   ├── __init__.py
│   │   ├── ollama_client.py        # Ollama client (Mistral, embeddings)
│   │   └── self_learning_parser.py # Self-learning output parser
│   │
│   ├── memory/                     # Persistence layer
│   │   ├── __init__.py
│   │   ├── smart_memory.py         # SmartMemory (semantic memory with embeddings)
│   │   └── client_profile.py       # ClientProfileDB (client preferences, history)
│   │
│   ├── knowledge/                  # Knowledge bases
│   │   └── vulnerability_kb.py     # Vulnerability database
│   │
│   ├── intelligence/               # Intelligence and reporting layer
│   │   ├── __init__.py
│   │   ├── intelligent_reporter.py # Multi-format reporting (executive, technical, remediation, compliance)
│   │   ├── compliance_mapping.py   # Map findings to NIST-CSF, PCI-DSS, GDPR, ISO27001, SOC2
│   │   ├── research_kb.py          # Research knowledge base
│   │   ├── research_daemon.py      # Background threat intel collection
│   │   ├── strategy_evolution.py   # Adaptive testing strategy
│   │   ├── custom_tool_generator.py # Generate custom tools (three-gate pipeline)
│   │   ├── intel_bus.py            # Intelligence event bus
│   │   ├── web_intelligence.py     # Web-based intelligence gathering
│   │   ├── surface_web_intel.py    # Surface web intel
│   │   ├── dark_web_intel.py       # Dark web intel
│   │   └── source_adapters.py      # NVD, CISA KEV, GitHub PoCs, MITRE ATT&CK, blogs, ExploitDB, dark web
│   │
│   ├── reporting/                  # Legacy reporting (mostly in intelligence/)
│   │   ├── __init__.py
│   │   ├── explainable_ai.py       # XAI logging
│   │   └── intelligent_reporter.py # May duplicate intelligence/intelligent_reporter.py
│   │
│   ├── verification/               # Verification and validation
│   │   └── (empty or internal modules)
│   │
│   ├── exploitation/               # Exploitation framework
│   │   └── (empty or internal modules)
│   │
│   ├── engines/                    # Execution engines (not yet documented in detail)
│   │   ├── engine_infra.py         # Engine infrastructure
│   │   └── engine_interface.py     # Engine interface
│   │
│   └── tests/                      # Test suite
│       └── (test files)
│
├── frontend/                       # React Vite frontend (monolithic, no component separation)
│   ├── src/
│   │   ├── main.jsx                # Entry point: ReactDOM.render(App)
│   │   ├── App.jsx                 # Monolithic app (2000+ lines): chat UI, event log, terminal, settings
│   │   ├── index.css               # Tailwind + custom styles
│   │   ├── App.test.jsx            # React Testing Library tests
│   │   └── test-setup.js           # Test configuration (globals, mocks)
│   │
│   ├── components/                 # Component directory (possibly empty or for future refactor)
│   │
│   ├── pages/                      # Page templates (possibly empty)
│   │
│   ├── index.html                  # HTML entry point
│   ├── vite.config.js              # Vite build config (proxy to backend:8000)
│   ├── tailwind.config.js          # Tailwind CSS config
│   ├── postcss.config.js           # PostCSS config
│   ├── package.json                # React, Lucide icons, Tailwind, Vite, Vitest deps
│   ├── package-lock.json
│   └── Dockerfile
│
└── .planning/
    └── codebase/                   # (This directory: generated analysis docs)
        ├── ARCHITECTURE.md
        ├── STRUCTURE.md
        ├── CONVENTIONS.md           (to be written by quality focus)
        ├── TESTING.md               (to be written by quality focus)
        ├── STACK.md                 (to be written by tech focus)
        ├── INTEGRATIONS.md          (to be written by tech focus)
        └── CONCERNS.md              (to be written by concerns focus)
```

## Directory Purposes

**backend/app.py:**
- Purpose: FastAPI application factory and startup point
- Contains: FastAPI instance, CORS middleware, route registration, lifespan hooks
- Key features: Health check endpoint, CORS allowing all origins (security note), module imports

**backend/api/:**
- Purpose: HTTP and WebSocket endpoints
- Contains: REST routes (chat, session retrieval) and WebSocket handler
- Key features: Token verification, ConnectionManager for WebSocket session multiplexing

**backend/agent/:**
- Purpose: NEW active orchestration system
- Contains: Orchestrator (main), LLMRouter (Claude/Ollama), routing components, sub-agents
- Key features: Streaming responses, multi-agent dispatch, LLM-driven decisions

**backend/agent/sub_agents/:**
- Purpose: Specialized security agents by domain
- Contains: 12 agent types (cloud, IAM, endpoint, exploit, scan, recon, intel, data_sec, genai, model_sec, ics, base)
- Key features: Each agent has allowed tools, execution engine, and domain-specific logic

**backend/agents/:**
- Purpose: OLD deprecated agent implementations
- Contains: Legacy versions of cloud, datasec, endpoint, exploit, IAM, intel agents
- Status: Dead code — retained for reference only

**backend/core/:**
- Purpose: OLD 6-layer monolith architecture
- Contains: EventBus, OmX/OmO orchestrators, ChatHandler, permissions, hooks, task registry
- Status: Deprecated — new `backend/agent/` system is active

**backend/session/:**
- Purpose: Session state container and registry
- Contains: EngagementSession (scope, history, state), ConversationHistory (sliding window), SessionStore (in-memory registry)
- Key features: Per-engagement context, 40-message context window, scope enforcement

**backend/execution/:**
- Purpose: Tool execution backend abstraction
- Contains: SSHClient (Paramiko), ShellManager (subprocess)
- Key features: SSH to Kali Linux, local command execution

**backend/tools/:**
- Purpose: Tool definitions, registry, and executor
- Contains: ToolRegistry (available tools), ToolSpec (tool metadata), ToolExecutor, sandbox manager
- Key features: Permission checking, multiple backends (SSH, subprocess, IPC, sandbox, Tor)

**backend/inference/:**
- Purpose: LLM provider clients
- Contains: OllamaClient (Mistral, embeddings), self-learning parser
- Key features: Ollama connection pooling, token counting

**backend/memory/:**
- Purpose: Persistence and semantic memory
- Contains: SmartMemory (embeddings-based), ClientProfileDB (client preferences)
- Key features: Tier 2 and Tier 3 memory systems for long-term context

**backend/knowledge/:**
- Purpose: Knowledge base management
- Contains: VulnerabilityKB (CVE/CWE data)
- Key features: Integration with vulnerability databases

**backend/intelligence/:**
- Purpose: Intelligence gathering, reporting, compliance
- Contains: IntelligentReporter (6 report formats), ComplianceMappingDB (5 frameworks), ResearchKB, CustomToolGenerator
- Key features: OSINT adapters (NVD, CISA, GitHub, MITRE, blogs, ExploitDB, dark web)

**frontend/src/:**
- Purpose: React frontend application
- Contains: Single monolithic App.jsx component with full chat/event/terminal UI
- Key features: WebSocket client, real-time event log, terminal emulator, settings panel

**frontend/components/:**
- Purpose: Reusable React components (currently empty or for future refactor)
- Status: Directory exists but no component files present

## Key File Locations

**Entry Points:**

- `backend/app.py` — FastAPI app definition, runs with `uvicorn backend.app:app --host 0.0.0.0 --port 8000`
- `backend/main.py` — OLD entry point, 846 lines, deprecated (do not use)
- `frontend/src/main.jsx` — React root render
- `frontend/index.html` — HTML entry point

**Configuration:**

- `backend/config.py` — Pydantic Settings: bearer_token, anthropic_api_key, ollama_host, claude_model, kali_host/port/user/password
- `backend/auth.py` — Token verification for REST and WebSocket
- `frontend/vite.config.js` — Vite server proxy to backend:8000

**Core Logic:**

- `backend/agent/orchestrator.py` — Main orchestration: LLMRouter + EngineRouter + ToolSelector
- `backend/agent/llm_router.py` — Claude/Ollama provider abstraction
- `backend/agent/engine_router.py` — Intent-based engine dispatch (MLAIEngine, ICSEngine, InfrastructureEngine)
- `backend/api/ws_handler.py` — WebSocket lifecycle, ConnectionManager
- `backend/session/engagement_session.py` — Session state dataclass and factory

**Testing:**

- `frontend/src/App.test.jsx` — React Testing Library tests
- `frontend/src/test-setup.js` — Vitest configuration
- `backend/tests/` — Backend test suite (directory exists, specific tests not detailed)

## Naming Conventions

**Files:**

- **Backend Python files:** `snake_case.py` (e.g., `llm_router.py`, `engagement_session.py`)
- **Agent files:** `{domain}_agent.py` (e.g., `cloud_agent.py`, `endpoint_agent.py`)
- **Config/utility files:** `snake_case.py` (e.g., `config.py`, `auth.py`, `tool_executor.py`)
- **Frontend files:** `CamelCase.jsx` for components, `lowercase.js` for utilities (e.g., `App.jsx`, `main.jsx`, `test-setup.js`)

**Directories:**

- **Functional subsystems:** `lowercase_with_underscores` (e.g., `backend/tools/`, `backend/memory/`, `backend/intelligence/`)
- **Layer groupings:** `lowercase` (e.g., `api/`, `core/`, `agent/`, `sub_agents/`)
- **Frontend:** `src/`, `components/`, `pages/` (standard React layout)

**Classes/Functions:**

- **Classes:** `PascalCase` (e.g., Orchestrator, LLMRouter, EngagementSession, ConnectionManager)
- **Functions:** `snake_case` (e.g., `process_stream()`, `verify_token()`, `dispatch()`)
- **Dataclasses:** `PascalCase` (e.g., @dataclass OrchestratorDecision, LLMResponse)
- **Constants:** `SCREAMING_SNAKE_CASE` (e.g., `_SYSTEM_PROMPT`, `REPORT_FORMATS_UI`)

**Variables:**

- **Session IDs:** `session_id` (string UUID)
- **Engagement IDs:** `engagement_id` (string UUID)
- **Messages:** `message`, `messages` (strings, lists of Dict[role, content])
- **Config/settings:** `settings` (Pydantic BaseSettings instance)

## Where to Add New Code

**New Chat Feature (e.g., custom response formatting):**
- Primary code: `backend/agent/response_composer.py` (add method to ResponseComposer)
- Orchestrator integration: `backend/agent/orchestrator.py` (call from process_stream)
- Frontend: `frontend/src/App.jsx` (add UI for new feature in message rendering section)

**New Security Domain Agent (e.g., "container_agent" for Docker/K8s security):**
- Implementation: Create `backend/agent/sub_agents/container_agent.py`
  - Inherit from BaseAgent
  - Define allowed_tools list
  - Implement async execute(target, **kwargs)
- Registration: Update EngineRouter in `backend/agent/engine_router.py` to dispatch container intents
- Tool binding: Add tools to ToolRegistry in `backend/tools/tool_registry.py`

**New Tool (e.g., "container_scan" using trivy):**
- Tool spec: Add entry to `backend/tools/tool_spec.py`
- Registry: Add to ToolRegistry.tools in `backend/tools/tool_registry.py`
- Executor: Add handler in `backend/tools/tool_executor.py` or new backend
- Backend: Create new file in `backend/tools/backends/trivy_backend.py` if different execution model
- Sub-agent: Update one or more sub-agents' allowed_tools list

**New Report Format (e.g., "pci_dss_detail"):**
- Implementation: Add method to IntelligentReporter in `backend/intelligence/intelligent_reporter.py`
- Compliance DB: Update ComplianceMappingDB if new compliance framework
- Frontend: Add format to REPORT_FORMATS_UI constant in `frontend/src/App.jsx`

**New Session Feature (e.g., persistent sessions to database):**
- Session layer: Modify SessionStore in `backend/session/session_store.py`
  - Change `_sessions: Dict` to use database backend
  - Update create(), resolve(), touch() methods
- No changes to EngagementSession contract (backward compatible)

**New Utility/Helper:**
- Shared utilities: Create in a new file in `backend/` root or subsystem (e.g., `backend/utils.py`, `backend/agent/utils.py`)
- Use clear module names following snake_case pattern
- Export from `__init__.py` if needed for easy imports

## Special Directories

**backend/tests/:**
- Purpose: Automated test suite
- Generated: No (manually written)
- Committed: Yes

**frontend/node_modules/:**
- Purpose: npm dependency packages (React, Vite, Tailwind, Lucide, Vitest, etc.)
- Generated: Yes (by `npm install`)
- Committed: No (in .gitignore)

**backend/__pycache__/:**
- Purpose: Python bytecode cache
- Generated: Yes (by Python runtime)
- Committed: No (in .gitignore)

**.planning/codebase/:**
- Purpose: Generated architecture and analysis documents (this directory)
- Generated: Yes (by GSD analysis tools)
- Committed: Yes (for documentation purposes)

## Current Active System

The NEW system is active:
- **Entry point:** `backend/app.py`
- **Request handler:** `backend/api/ws_handler.py` for WebSocket, `backend/api/chat_routes.py` for REST
- **Orchestration:** `backend/agent/orchestrator.py`
- **Configuration:** `backend/config.py`, `backend/auth.py`

The OLD system remains in codebase but is NOT used:
- **Old entry point:** `backend/main.py` (deprecated, 846 lines)
- **Old orchestration:** `backend/core/omo.py`, `backend/core/omx.py`, `backend/core/chat_handler.py`
- **Old agents:** `backend/agents/` (dead code)

---

*Structure analysis: 2026-05-12*
