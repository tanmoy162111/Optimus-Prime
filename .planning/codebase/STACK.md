# Technology Stack

**Analysis Date:** 2026-05-12

## Languages

**Primary:**
- Python 3.12 - Backend (FastAPI), ML runtimes, agents, intelligence modules
- TypeScript 5.4.0 - Frontend development (type definitions)
- JavaScript (Node.js 20) - Frontend runtime, React build system

**Secondary:**
- Bash - Docker entrypoints and container initialization (`backend/entrypoint.sh`, `kali/entrypoint.sh`)
- SQL - SQLite database schema and queries

## Runtime

**Environment:**
- Python 3.12 (backend services via Docker)
- Node.js 20-alpine (frontend via Docker)
- Docker 3.8+ (containerization)

**Package Managers:**
- pip (Python dependencies) - Lockfile: `backend/requirements.txt`
- npm (JavaScript dependencies) - Lockfile: `frontend/package-lock.json`

## Frameworks

**Core Backend:**
- FastAPI 0.115.0 - REST API and WebSocket server (`backend/app.py`, `backend/main.py`)
- Uvicorn 0.32.0 - ASGI server for FastAPI
- Pydantic 2.9.2 - Data validation and settings management (`backend/config.py`)
- Pydantic-settings 2.6.1 - Environment variable configuration

**Frontend:**
- Next.js 14.2.0 - React metaframework (`frontend/pages/`, `frontend/src/`)
- React 18.3.0 - UI library
- React DOM 18.3.0 - React rendering target

**Testing:**
- pytest 8.3.3 - Python test runner (`backend/tests/`)
- pytest-asyncio 0.24.0 - Async test support (`pyproject.toml` config: asyncio_mode="auto")
- Vitest - JavaScript test framework (configured in `frontend/vite.config.js`)

**Build/Dev:**
- Vite - Frontend development server and bundler (`frontend/vite.config.js`)
- npm scripts - Frontend build automation (`frontend/package.json`)

## Key Dependencies

**Critical Backend:**
- anthropic 0.38.0 - Claude API client for LLM orchestration (`backend/agent/llm_router.py`)
- paramiko 3.5.0 - SSH client for Kali Linux execution (`backend/execution/ssh_client.py`)
- aiohttp 3.10.10 - Async HTTP client for Ollama and external APIs (`backend/inference/ollama_client.py`, `backend/intelligence/source_adapters.py`)
- httpx 0.27.2 - Sync/async HTTP client for research sources (`backend/intelligence/source_adapters.py`)
- python-socketio[client] 5.12.0 - WebSocket client for real-time communication

**Infrastructure:**
- tiktoken 0.7.0 - Token counting for Claude API usage tracking
- python-json-logger 2.0.7 - Structured logging

**Frontend:**
- socket.io-client 4.7.0 - WebSocket client for real-time backend communication
- zustand 4.5.0 - State management

**ML & Security Tools:**
- adversarial-robustness-toolbox[pytorch,tensorflow] 1.20.1 - Adversarial robustness testing (`ml-runtime/requirements.txt`)
- foolbox - Adversarial examples generation
- torch - PyTorch ML framework
- tensorflow - TensorFlow ML framework
- scikit-learn - Machine learning utilities
- promptfoo - Prompt injection testing

**Report Generation:**
- weasyprint 62.3 - HTML to PDF conversion for reports (`backend/requirements.txt`)

## Configuration

**Environment Variables:**
- Location: `.env` (template: `.env.example`)
- LLM Configuration:
  - `ANTHROPIC_API_KEY` - Claude API key
  - `CLAUDE_MODEL` - Model selection (default: claude-sonnet-4-6)
  - `MISTRAL_MODEL` - Ollama Mistral model (default: mistral:7b-instruct-v0.2-q4_K_M)
  - `EMBED_MODEL` - Ollama embedding model (default: nomic-embed-text)
- Execution Configuration:
  - `KALI_HOST` - SSH host (default: kali in Docker)
  - `KALI_PORT` - SSH port (default: 22)
  - `KALI_USER` - SSH username (default: kali)
  - `KALI_PASSWORD` - SSH password (default: kali)
- Tor Proxy:
  - `TOR_SOCKS_HOST` - SOCKS5 proxy host (default: tor)
  - `TOR_SOCKS_PORT` - SOCKS5 port (default: 9050)
- Budget Management:
  - `SESSION_TOKEN_BUDGET` - Token limit per session (default: 500000)
  - `SUMMARISER_THRESHOLD` - Token threshold for summarization (default: 60000)
- Storage:
  - `MEMORY_DB_PATH` - SQLite database location (default: /app/data/optimus_memory.db)
  - `INTEL_CACHE_PATH` - Intelligence cache directory (default: /app/data/intel_cache)
  - `REPORTS_PATH` - Report output directory (default: /app/data/reports)
  - `SCOPE_FILE_PATH` - Engagement scope YAML (default: /app/config/scope.yaml)

**Backend Config:**
- `backend/config.py` - Pydantic BaseSettings class loads environment variables

**Frontend Config:**
- `frontend/vite.config.js` - Vite server with proxy to backend
- `frontend/package.json` - npm scripts (dev, build, start)
- `tailwind.config.js` - Tailwind CSS configuration
- `postcss.config.js` - PostCSS configuration

**Build Config:**
- `pyproject.toml` - pytest configuration and project metadata
- `Dockerfile` (backend) - Python 3.12-slim base, pip install
- `Dockerfile` (frontend) - Node.js 20-alpine base, npm install
- `.env.example` - Configuration template

## Platform Requirements

**Development:**
- Python >= 3.12
- Node.js >= 20
- Docker and Docker Compose 3.8+
- Bash shell

**Production / Docker Environment:**
- Docker with Docker Compose
- Memory allocation: Backend 4GB, Frontend 1GB, Ollama 8GB, ML-Runtime 8GB, Kali 4GB
- CPU allocation: Backend 2 cores, Frontend 1 core, Ollama 4 cores, ML-Runtime 4 cores, Kali 2 cores

**Deployment Targets:**
- Docker Compose (local/on-premise) via `docker-compose.yml`
- Container orchestration ready (FastAPI/Uvicorn stateless, config-driven)

---

*Stack analysis: 2026-05-12*
