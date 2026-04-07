# Web Intelligence Integration Design

**Date:** 2026-04-07
**Status:** Approved

## Problem

The web intelligence module (`ResearchDaemon`, `TorSOCKS5Backend`, `IntelAgent`, `StrategyEvolutionEngine`) is architecturally complete but entirely unconnected from real data sources:

- `ResearchDaemon` initialized in `main.py` with no `source_adapters` — all 7 sources skip with `"no adapter"`
- `TorSOCKS5Backend` is a stub returning `{"status": "stub"}`
- `cve_search` and `exploit_db` have no command builders in `kali_ssh.py` — fall to broken generic command
- `StrategyEvolutionEngine` is initialized but never called during engagements
- `OmX` planner never queries `ResearchKB` before building plans
- Frontend shows BACKEND OFFLINE because `vite.config.js` proxies to `http://localhost:8000` (fails inside Docker) and App.jsx bypasses the proxy with full URLs that break on non-localhost deployments

## Approach

**B — Python source adapters + TorSOCKS5 implementation.**

Source adapters run as async `httpx` calls in the backend (independent of Kali). Dark web queries route through the dedicated Tor container via SOCKS5. Intel feeds both the pre-engagement planner and the live IntelAgent, with StrategyEvolutionEngine enriching exploit chains at the end.

## Architecture

```
ResearchDaemon (nightly/weekly)
  ├── NVDAdapter           → NVD REST API v2 (free, no key)
  ├── CISAKEVAdapter       → CISA KEV JSON feed
  ├── ExploitDBAdapter     → searchsploit on Kali (JSON output)
  ├── GitHubPoCAdapter     → GitHub Search API (unauthenticated)
  ├── MITREAttackAdapter   → MITRE CTI STIX JSON (GitHub raw)
  ├── BlogsAdapter         → RSS: Krebs, BleepingComputer, Rapid7, SANS ISC
  └── DarkWebAdapter       → TorSOCKS5 → Ahmia .onion search
           ↓
      ResearchKB (SQLite)
           ↓
  ┌────────────────────────────┐
  │   OmX pre-engagement       │  ResearchKB.query() → injected into plan prompt
  └────────────────────────────┘
           ↓ (during engagement)
  ┌───────────────────────────────────────────┐
  │  IntelAgent (parallel with ReconAgent)     │
  │  - shodan        (Kali: internetdb curl)   │
  │  - cve_search    (Kali: CIRCL CVE API)     │
  │  - exploit_db    (Kali: searchsploit)      │
  │  - dark_web_query (TorSOCKS5Backend)       │
  └───────────────────────────────────────────┘
           ↓ findings
  StrategyEvolutionEngine.enrich_chain()
  → attaches poc_urls, attack_technique_id, historical_success_rate
  → enriched findings available to ExploitAgent via EventBus replay
```

## Components

### 1. `backend/intelligence/source_adapters.py` (new file)

Seven adapter classes, each implementing `async def fetch(last_run: str | None) -> list[ResearchKBEntry]`.

| Class | Endpoint | Incremental strategy |
|---|---|---|
| `NVDAdapter` | `services.nvd.nist.gov/rest/json/cves/2.0` | `lastModStartDate` from `last_run` |
| `CISAKEVAdapter` | `cisa.gov/.../known_exploited_vulnerabilities.json` | Full fetch, KB deduplicates by CVE ID |
| `ExploitDBAdapter` | ExploitDB CSV dump from GitLab (raw HTTP, no key) | Full fetch, KB deduplicates by EDB-ID |
| `GitHubPoCAdapter` | `api.github.com/search/repositories?q=CVE-*+poc` | Page through, 1s sleep between pages |
| `MITREAttackAdapter` | MITRE CTI STIX JSON (GitHub raw, `enterprise-attack`) | Weekly full replace |
| `BlogsAdapter` | RSS: Krebs, BleepingComputer, Rapid7, SANS ISC | `If-Modified-Since` header |
| `DarkWebAdapter` | Ahmia `.onion` via `TorSOCKS5Backend` | Weekly, 3 queries max |

Each adapter:
- Wraps its call in `try/except`; on failure returns `[]` and logs
- Returns `list[ResearchKBEntry]` — daemon handles dedup and KB ingestion
- NVD: if 429 received, sleep 6s + retry once, then give up

### 2. `backend/tools/backends/tor_socks5.py` (replace stub)

Full implementation using `httpx.AsyncClient` with `socks5://tor:9050` proxy.

**Security hardening (dark web isolation):**
- `proxies={"all://": "socks5h://tor:9050"}` — `socks5h` forces DNS resolution through Tor (no local DNS leak)
- `verify=False` for .onion (no TLS CA for onion addresses)
- Strict 60s timeout, no redirects (`follow_redirects=False`)
- Response body capped at 512KB before parsing
- All HTML stripped to plain text (regex, no lxml dependency)
- No cookies (`cookies=None`), no stored state between requests
- Clearnet redirect guard: if response URL is not `.onion` or Ahmia clearnet, reject
- `TorUnavailableError` raised when Tor SOCKS5 connection fails — callers return `[]`

**Tool execution** (`execute()` method):
- `dark_web_query` tool: routes target/flags through Ahmia search, returns sanitized text result
- Result truncated to 2000 chars before returning to agent

### 3. `backend/tools/backends/kali_ssh.py` — two new command builders

Added to the `builders` dict in `_build_command()`:

```python
"cve_search": lambda: (
    f"timeout 20 curl -sk 'https://cve.circl.lu/api/cve/{tool_input.get(\"target\", target)}'"
    f" 2>/dev/null || echo '{{}}'"
),
"exploit_db": lambda: (
    f"timeout 30 searchsploit --json {target} 2>/dev/null"
    f" || timeout 30 searchsploit {target} 2>/dev/null"
    f" || echo '{{\"RESULTS_EXPLOIT\": []}}'"
),
```

CIRCL CVE Search is a free public API requiring no authentication.
`searchsploit` is pre-installed on Kali and queries the offline ExploitDB copy.

### 4. `backend/core/omx.py` — pre-engagement KB enrichment

Before `_build_plan_prompt()` assembles the planning prompt, query `ResearchKB` for CVEs and PoCs matching the target's services. Inject top-5 results as a `"Known CVEs/PoCs:"` block so ExploitAgent sees actionable intel before its first iteration.

`OmX` receives `research_kb: ResearchKB | None = None` as an optional constructor parameter; `main.py` passes it in. If KB is unavailable or returns no results, planning proceeds unchanged.

### 5. `backend/agents/intel_agent.py` — post-run StrategyEvolution hook

After `run_loop()` completes, `execute()` calls `_post_run_enrich()`:
- Builds an `AttackChain` from findings that have CVE IDs or technique names
- Calls `StrategyEvolutionEngine.enrich_chain(chain)`
- Attaches `poc_urls`, `attack_technique_id`, `historical_success_rate` back to findings
- Publishes enriched findings to EventBus `"intel"` channel

`IntelAgent` receives `strategy_engine: StrategyEvolutionEngine | None = None`; `main.py` passes it in.

### 6. `backend/main.py` — adapter registration

After `ResearchDaemon` is constructed, register all 7 adapters:

```python
from backend.intelligence.source_adapters import (
    NVDAdapter, CISAKEVAdapter, GitHubPoCAdapter,
    MITREAttackAdapter, BlogsAdapter, DarkWebAdapter,
)
tor_backend = _get("tor_backend")  # registered alongside other backends
research_daemon.register_source("nvd",        NVDAdapter().fetch)
research_daemon.register_source("cisa_kev",   CISAKEVAdapter().fetch)
research_daemon.register_source("github_poc", GitHubPoCAdapter().fetch)
research_daemon.register_source("attack",     MITREAttackAdapter().fetch)
research_daemon.register_source("blogs",      BlogsAdapter().fetch)
research_daemon.register_source("dark_web",   DarkWebAdapter(tor_backend).fetch)
```

`ExploitDBAdapter` fetches the ExploitDB CSV dump from GitLab via HTTP (no Kali dependency — daemon runs independently of Kali availability), parses each row into a `ResearchKBEntry`, and is registered as the `"exploitdb"` source.

Pass `research_kb` to `OmX`, pass `strategy_engine` to `IntelAgent` instances inside `EngineInfra`.

### 7. Frontend fix

**`frontend/vite.config.js`:**
- All proxy targets changed from `http://localhost:8000` to `http://backend:8000`
- Add missing proxy entries: `/report`, `/terminal`

**`frontend/src/App.jsx`:**
- REST calls (`fetch`) use relative paths: `/health`, `/scope`, `/gate`, `/report`, `/terminal/exec`, `/directives`
- `API_BASE` retained only for deriving WebSocket base: `const WS_BASE = \`ws://\${window.location.host}\``
- This makes the app work on any deployment (Docker, remote server, localhost) without env vars

## Data Flow

### Nightly research ingestion
```
02:00 cron → ResearchDaemon.run_nightly()
  for source in [nvd, cisa_kev, exploitdb, github_poc, attack, blogs]:
    adapter.fetch(last_run) → list[ResearchKBEntry]
    for entry in entries:
      ResearchKB.ingest(entry)  # dedup by cve_id
    ResearchKB.set_last_run(source, now)
    EventBus.publish("research", source_event_type, {ingested, deduplicated})

03:00 Sunday → ResearchDaemon.run_weekly()
  DarkWebAdapter.fetch(last_run) → Tor → Ahmia → sanitized entries
  same ingest + event flow
```

### Pre-engagement planning
```
OmX.plan(prompt) →
  ResearchKB.query(keyword=scope_target_string, limit=5) →  # raw target from ScopeConfig.targets[0]
  if results:
    prepend "Known CVEs/PoCs:\n{entries}" to plan prompt
  → LLM builds plan with exploit context already injected
```

### Live engagement intel
```
IntelAgent.execute(task) →
  run_loop() → [shodan, cve_search, exploit_db, dark_web_query] tools
  _post_run_enrich(findings) →
    AttackChain from findings with CVE/technique fields
    StrategyEvolutionEngine.enrich_chain(chain) →
      ResearchKB.query(cve_id=...) → poc_urls, attack_technique_id
      SmartMemory.get_best_tools() → historical_success_rate
    EventBus.publish("intel", "CVE_CORRELATED", enriched_payload)
    EventBus.publish("intel", "ATTACK_MAPPED", technique_payload)
```

## Error Handling

| Failure | Behavior |
|---|---|
| Source adapter HTTP error | Returns `[]`, logs warning, daemon continues to next source |
| Tor container unreachable | `TorUnavailableError` → `DarkWebAdapter` returns `[]` |
| NVD 429 rate limit | Sleep 6s, retry once, then return partial results |
| `dark_web_query` tool fails | Returns `{"error": "tor_unavailable"}` JSON — agent logs and continues |
| Clearnet redirect from .onion | Request rejected, returns empty result |
| Response > 512KB | Truncated before parsing |
| ResearchKB query in OmX fails | Log warning, planning proceeds without KB context |
| StrategyEvolution enrichment fails | Log warning, findings returned without enrichment |

## Security (Dark Web)

- **No DNS leak:** `socks5h://` forces all DNS through Tor
- **No clearnet fallback:** if Tor is down, dark web queries fail closed (never fall back to direct HTTP)
- **Content isolation:** HTML stripped, result truncated to 2000 chars, no executable content stored in KB
- **No persistent state:** no cookies, no sessions, no stored Tor circuit info
- **Redirect guard:** any redirect target that is not `.onion` or Ahmia's known clearnet domain is rejected
- **Timeout:** 60s hard limit; slow .onion nodes are abandoned

## Testing

| Test | File | What it covers |
|---|---|---|
| Each adapter unit test | `test_source_adapters.py` | Happy path + 404 + timeout, mock via `respx` |
| TorSOCKS5 unit test | `test_tor_socks5.py` | Mock SOCKS5, DNS-leak guard, 512KB cap, redirect guard |
| DarkWebAdapter unit test | `test_source_adapters.py` | Ahmia response parsing, sanitization |
| ResearchDaemon integration | `test_research_daemon.py` (extend) | All 7 adapters registered, incremental ingestion |
| OmX KB enrichment | `test_omx_enrichment.py` | KB returns CVE → appears in plan prompt |
| IntelAgent enrichment | `test_intel_agent_enrich.py` | enrich_chain called, CVE_CORRELATED event published |
| E2E smoke | `test_pentest_e2e.py` (extend) | Mock KB CVE → visible in OmX plan |
