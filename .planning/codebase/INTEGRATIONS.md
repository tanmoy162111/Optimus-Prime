# External Integrations

**Analysis Date:** 2026-05-12

## APIs & External Services

**LLM Providers:**
- Claude (Anthropic) - Primary orchestration LLM
  - SDK/Client: `anthropic` 0.38.0
  - Auth: `ANTHROPIC_API_KEY` (environment variable)
  - Integration: `backend/core/llm_router.py` (ClaudeProvider class)
  - Usage: Orchestration mode chat responses, tool planning, compliance mapping

- Ollama (Local) - Secondary inference and embeddings
  - Client: `backend/inference/ollama_client.py` (OllamaClient class)
  - Host: `OLLAMA_HOST` (default: http://ollama:11434)
  - Models:
    - Chat/Generation: `MISTRAL_MODEL` (default: mistral:7b-instruct-v0.2-q4_K_M)
    - Embeddings: `EMBED_MODEL` (default: nomic-embed-text)
  - Container: `ollama/ollama:latest` in `docker-compose.yml`
  - Methods: `generate()`, `embed()`, `chat()`

**Network & Proxy:**
- Tor SOCKS5 Proxy - Anonymization for intelligence gathering
  - Service: `dperson/torproxy:latest`
  - Host: `TOR_SOCKS_HOST` (default: tor)
  - Port: `TOR_SOCKS_PORT` (default: 9050)
  - Container: `optimus_tor` service in `docker-compose.yml`

**Execution & Command Control:**
- Kali Linux SSH Server - Remote command execution
  - SSH Host: `KALI_HOST` (default: kali)
  - SSH Port: `KALI_PORT` (default: 22)
  - Username: `KALI_USER` (default: kali)
  - Password: `KALI_PASSWORD` (default: kali)
  - Client: `backend/execution/ssh_client.py` (SSHClient class)
  - SSH Library: `paramiko` 3.5.0
  - Methods: `connect()`, `execute()`, `close()`
  - Container: `optimus_kali` service in `docker-compose.yml`
  - Dockerfile: `kali/Dockerfile` (kalilinux/kali-rolling base + headless tools)

## Data Storage

**Databases:**
- SQLite - Local file-based relational database
  - Location: `MEMORY_DB_PATH` (default: /app/data/optimus_memory.db)
  - Purpose: Client profiles, engagement history, memory persistence
  - Client: `sqlite3` (Python standard library)
  - Schemas:
    - `backend/memory/client_profile.py` - Client profile schema (ClientProfileDB)
      - Tables: `client_profiles` with indexed name lookup
      - Operations: CRUD for client engagement tracking

**File Storage:**
- Local filesystem mounts via Docker volumes
  - `./data:/app/data` - Persistent data directory (memory DB, cache, reports)
  - `./config:/app/config` - Configuration files (scope.yaml)
  - `models_input:/models` - Model input directory (shared with ML runtime)
  - `ml_results:/results` - ML runtime output directory
  - `kali_workspace:/home/kali/workspace` - Kali home directory
  - `ollama_models:/root/.ollama` - Ollama model cache

**Caching:**
- File-based cache - Intelligence cache
  - Location: `INTEL_CACHE_PATH` (default: /app/data/intel_cache)
  - Usage: Research daemon caching of CVE/vulnerability data

## Authentication & Identity

**Auth Provider:**
- Custom Bearer Token - Simple bearer token authentication
  - Implementation: `backend/auth.py` (verify_token, verify_ws_token functions)
  - Token Source: `OPTIMUS_API_KEY` environment variable
  - Token Validation: HTTP header `Authorization: Bearer <token>`
  - Scope: API routes, WebSocket connections

**Session Management:**
- In-memory session store - User session tracking
  - Implementation: `backend/session/session_store.py` (session_store object)
  - Lifespan: Per-engagement session with timestamp tracking
  - Data: Session ID, engagement ID, conversation history, token usage

## Monitoring & Observability

**Error Tracking:**
- Application logging - Error and event logging
  - Framework: Python `logging` module
  - Configuration: `backend/main.py` (logging.basicConfig)
  - Level: INFO default with WARNING suppression for third-party libs (paramiko, httpx, uvicorn)
  - Format: ISO timestamp, logger name, level, message

**Logs:**
- Structured logging - JSON-formatted logs
  - Library: `python-json-logger` 2.0.7
  - Usage: Structured event logging for compliance and audit trails
  - Broadcasted to frontend: `backend/core/terminal_broadcaster.py` (TerminalBroadcaster, TerminalLogHandler)

**Real-time Event Broadcasting:**
- WebSocket events - Terminal output streaming
  - Implementation: `backend/core/terminal_broadcaster.py` (TerminalBroadcaster class)
  - Frontend: `backend/api/ws_handler.py` (WebSocket /chat endpoint)
  - Protocol: JSON messages with event metadata

## CI/CD & Deployment

**Hosting:**
- Docker Compose (local/on-premise deployment)
  - Orchestration file: `docker-compose.yml` (version 3.8)
  - Services: backend, frontend, ollama, kali, ml-runtime, tor
  - Network: `optimus_internal` bridge (internal only, no external access)
  - Memory limits: Backend 4GB, Frontend 1GB, Ollama 8GB, ML-Runtime 8GB, Kali 4GB
  - CPU limits: 2–4 cores per service

**Build & Deployment:**
- Docker Compose build - Multi-container orchestration
  - Backend Dockerfile: `backend/Dockerfile` (Python 3.12-slim base)
  - Frontend Dockerfile: `frontend/Dockerfile` (Node.js 20-alpine base)
  - Kali Dockerfile: `kali/Dockerfile` (kalilinux/kali-rolling base)
  - ML-Runtime Dockerfile: `ml-runtime/Dockerfile` (Python 3.12-slim + mluser)
  - ICS-Runtime: Minimal Python 3.12 container (not in main compose)

**CI Pipeline:**
- Not detected - No GitHub Actions, GitLab CI, or similar configured

## Environment Configuration

**Required env vars:**
- `ANTHROPIC_API_KEY` - Claude API key (critical for orchestration)
- `OPTIMUS_API_KEY` - Bearer token for API authentication

**Secrets location:**
- Environment file: `.env` (local, not committed)
- Template: `.env.example` (git-committed reference)
- Optional cloud paths (commented in .env.example):
  - `CLOUD_SECRETS_PATH` - Cloud credential storage
  - `AWS_CREDS_FILE` - AWS credentials YAML
  - `AZURE_CREDS_FILE` - Azure credentials YAML
  - `GCP_CREDS_FILE` - GCP credentials YAML

## Webhooks & Callbacks

**Incoming:**
- Not detected - No webhook endpoints for external services

**Outgoing:**
- WebSocket streaming - Real-time event streaming to frontend
  - Endpoint: `ws://backend:8000/ws/chat`
  - Protocol: JSON events (chunk, done, error, session, pong)

## Intelligence & Research APIs

**Public Vulnerability Data Sources:**
- NVD (NIST National Vulnerability Database) - CVE data
  - Endpoint: `https://services.nvd.nist.gov/rest/json/cves/2.0`
  - Adapter: `backend/intelligence/source_adapters.py` (NVDAdapter class)
  - Auth: None (public API, subject to rate limits)
  - Method: Incremental fetch with `lastModStartDate` parameter

- CISA KEV Catalog - Known Exploited Vulnerabilities
  - Endpoint: `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json`
  - Adapter: `backend/intelligence/source_adapters.py` (CISAKEVAdapter class)
  - Auth: None (public JSON feed)

- GitHub PoC Repository - Proof-of-concept exploits
  - Adapter: `backend/intelligence/source_adapters.py` (GitHubPoCAdapter class)
  - Method: GitHub API queries for security-related repositories

- MITRE ATT&CK Framework - Adversarial tactics and techniques
  - Adapter: `backend/intelligence/source_adapters.py` (MITREAttackAdapter class)
  - Source: MITRE ATT&CK public data

- Blog/Security News - Vulnerability blogs and writeups
  - Adapter: `backend/intelligence/source_adapters.py` (BlogsAdapter class)
  - Method: RSS feed aggregation and web scraping

- ExploitDB - Exploit database
  - Adapter: `backend/intelligence/source_adapters.py` (ExploitDBAdapter class)
  - Endpoint: ExploitDB public API/feed

- Dark Web Intel - Dark web mentions and threats
  - Adapter: `backend/intelligence/source_adapters.py` (DarkWebAdapter class)
  - Method: Dark web forum scraping (via Tor proxy)

**Research Integration:**
- ResearchDaemon - Autonomous research bot
  - Location: `backend/intelligence/research_daemon.py`
  - Method: Periodically fetches from adapters, stores in ResearchKB
  - Caching: 1-hour TTL (configurable via `INTEL_TTL_SECONDS`)

- ResearchKB - Knowledge base storage
  - Location: `backend/intelligence/research_kb.py`
  - Purpose: Stores CVE, PoC, ATT&CK, and blog data for agent queries

## External SDK Integrations

**HTTP Clients:**
- `aiohttp` 3.10.10 - Async HTTP for Ollama, intelligence sources
- `httpx` 0.27.2 - Sync/async HTTP for research adapters
- Headers: User-Agent: `Optimus-Intel-Daemon/2.0 (security research)`

**Token Management:**
- `tiktoken` 0.7.0 - Token counting for Claude API
  - Usage: `TokenBudgetManager` in `backend/core/llm_router.py`
  - Purpose: Track session token budget and enforce limits

---

*Integration audit: 2026-05-12*
