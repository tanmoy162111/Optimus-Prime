# Optimus - Universal AI Security Platform

A conversational, agentic co-pilot for professional-grade security assessments across all major cybersecurity domains.

## Architecture

- **Engine 1 (Optimus Infra)**: Network, Application, Endpoint, Cloud, IAM, Data Security
- **Engine 2 (Optimus ICS)**: IoT/OT/ICS (stub)
- **Engine 3 (Optimus AI)**: Adversarial ML, GenAI Security

## Quick Start

```bash
# Copy environment template
cp .env.example .env
# Add your ANTHROPIC_API_KEY and OPTIMUS_API_KEY

# Start all services
docker compose up -d

# Access UI
open http://localhost:3000
```

## Services

| Service | Port | Description |
|---------|-----|-------------|
| frontend | 3000 | Next.js 14 chat UI |
| backend | 8000 | FastAPI agent core |
| ollama | 11434 | Mistral + embeddings |
| kali | 22 | Security tools |
| ml-runtime | - | ART, Promptfoo |
| tor | 9050 | Dark web intel |

## API

```bash
# Chat endpoint
curl -X POST http://localhost:8000/api/chat \
  -H "Authorization: Bearer YOUR_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"message": "Scan example.com"}'
```

## Development

```bash
# Backend
cd backend && pip install -r requirements.txt
python -m uvicorn backend.app:app --reload

# Frontend
cd frontend && npm install
npm run dev
```

## License

CONFIDENTIAL - AI DevCo