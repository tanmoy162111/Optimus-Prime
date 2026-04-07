# Web Intelligence Integration Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Wire the existing ResearchDaemon/KB/StrategyEvolution stack to real data sources (NVD, CISA KEV, ExploitDB, GitHub PoC, MITRE ATT&CK, RSS blogs, dark web via Tor/Ahmia), fix the TorSOCKS5 stub, add missing KaliSSH command builders, hook KB intel into OmX planning and IntelAgent enrichment, and fix the frontend proxy/URL disconnect.

**Architecture:** Source adapters live in `backend/intelligence/source_adapters.py` as plain async classes with a `fetch(last_run)` interface — registered with the existing `ResearchDaemon` in `main.py`. TorSOCKS5Backend replaces its stub using `httpx` + `socksio` (SOCKS5H for DNS-over-Tor). OmX gains an optional `research_kb` param that injects KB context into `plan.metadata`; OmO prepends it to agent prompts. IntelAgent gains a `strategy_engine` param and calls `enrich_chain()` after `run_loop()`. Frontend REST calls switch to relative paths so they proxy through Vite to `http://backend:8000`.

**Tech Stack:** Python 3.12, httpx 0.28, socksio (new dep), stdlib xml.etree.ElementTree (RSS), FastAPI, SQLite (ResearchKB), Tor SOCKS5H proxy, React/Vite

---

## File Map

| Action | Path | Responsibility |
|---|---|---|
| Create | `backend/intelligence/source_adapters.py` | All 7 source adapter classes |
| Modify | `backend/tools/backends/tor_socks5.py` | Replace stub with real httpx+SOCKS5H impl |
| Modify | `backend/tools/backends/kali_ssh.py` | Add `cve_search` + `exploit_db` builders |
| Modify | `backend/core/omx.py` | Add `research_kb` param + KB enrichment in `plan()` |
| Modify | `backend/core/omo.py` | Inject `research_context` from plan.metadata into prompts |
| Modify | `backend/agents/intel_agent.py` | Add `strategy_engine` param + `_post_run_enrich()` |
| Modify | `backend/engines/engine_infra.py` | Pass `strategy_engine` to IntelAgent on dispatch |
| Modify | `backend/main.py` | Register adapters, pass research_kb to OmX, strategy_engine to EngineInfra |
| Modify | `backend/requirements.txt` | Add `socksio>=0.2.3` |
| Create | `backend/tests/test_source_adapters.py` | Unit tests for all 7 adapters |
| Create | `backend/tests/test_tor_socks5.py` | TorSOCKS5Backend unit tests |
| Create | `backend/tests/test_omx_enrichment.py` | OmX KB enrichment tests |
| Create | `backend/tests/test_intel_agent_enrich.py` | IntelAgent strategy enrichment tests |
| Modify | `frontend/vite.config.js` | Proxy targets → `http://backend:8000`, add missing routes |
| Modify | `frontend/src/App.jsx` | REST → relative paths, WS → `window.location.host` |

---

### Task 1: Add socksio dependency

**Files:**
- Modify: `backend/requirements.txt`

- [ ] **Step 1: Add socksio to requirements.txt**

Open `backend/requirements.txt` and add after the `httpx` line:
```
socksio>=0.2.3
```

Full resulting requirements.txt:
```
fastapi>=0.115.0
uvicorn[standard]>=0.32.0
pydantic>=2.9.0
aiosqlite>=0.20.0
paramiko>=3.5.0
python-jose[cryptography]>=3.3.0
httpx>=0.27.0
socksio>=0.2.3
pyyaml>=6.0.2
aiofiles>=24.1.0
python-multipart>=0.0.12

# Testing
pytest>=8.3.0
pytest-asyncio>=0.24.0
pytest-cov>=5.0.0

# PDF generation (reports)
weasyprint>=62.0
```

- [ ] **Step 2: Install it locally**

```bash
pip install "socksio>=0.2.3"
```

Expected: `Successfully installed socksio-0.2.3` (or newer)

- [ ] **Step 3: Verify httpx SOCKS5 works**

```bash
python -c "import httpx; import socksio; print('SOCKS5 OK')"
```

Expected: `SOCKS5 OK`

- [ ] **Step 4: Commit**

```bash
git add backend/requirements.txt
git commit -m "feat: add socksio for httpx SOCKS5 Tor proxy support"
```

---

### Task 2: TorSOCKS5Backend — replace stub

**Files:**
- Modify: `backend/tools/backends/tor_socks5.py`
- Create: `backend/tests/test_tor_socks5.py`

- [ ] **Step 1: Write failing tests**

Create `backend/tests/test_tor_socks5.py`:

```python
"""Tests for TorSOCKS5Backend."""
from __future__ import annotations

import pytest
from unittest.mock import AsyncMock, MagicMock, patch


class TestTorSOCKS5Backend:
    """TorSOCKS5Backend unit tests."""

    def test_import(self):
        """Backend imports without error."""
        from backend.tools.backends.tor_socks5 import TorSOCKS5Backend
        assert TorSOCKS5Backend is not None

    def test_not_stub(self):
        """Backend is no longer a stub."""
        from backend.tools.backends.tor_socks5 import TorSOCKS5Backend
        b = TorSOCKS5Backend()
        # Stub returned {"status": "stub"} — real impl should not
        import inspect
        src = inspect.getsource(b.execute)
        assert "stub" not in src

    @pytest.mark.asyncio
    async def test_dark_web_query_returns_dict(self):
        """dark_web_query returns a dict with 'output' key on success."""
        from backend.tools.backends.tor_socks5 import TorSOCKS5Backend
        backend = TorSOCKS5Backend(tor_host="tor", tor_port=9050)

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "<html><body><p>CVE-2024-1234 exploit found</p></body></html>"
        mock_response.url = MagicMock()
        mock_response.url.host = "ahmia.fi"

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = mock_response
            result = await backend.execute(
                "dark_web_query",
                {"target": "CVE-2024-1234"},
                None,
            )

        assert isinstance(result, dict)
        assert "output" in result or "error" in result

    @pytest.mark.asyncio
    async def test_tor_unavailable_returns_error(self):
        """When Tor is down, returns error dict instead of raising."""
        from backend.tools.backends.tor_socks5 import TorSOCKS5Backend
        import httpx
        backend = TorSOCKS5Backend(tor_host="tor", tor_port=9050)

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_get.side_effect = httpx.ProxyError("connection refused")
            result = await backend.execute(
                "dark_web_query",
                {"target": "exploit CVE-2024"},
                None,
            )

        assert "error" in result

    @pytest.mark.asyncio
    async def test_clearnet_redirect_rejected(self):
        """Redirects to non-.onion non-Ahmia hosts are rejected."""
        from backend.tools.backends.tor_socks5 import TorSOCKS5Backend
        backend = TorSOCKS5Backend(tor_host="tor", tor_port=9050)

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "<html>evil</html>"
        mock_response.url = MagicMock()
        mock_response.url.host = "evil.com"  # clearnet redirect

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = mock_response
            result = await backend.execute(
                "dark_web_query",
                {"target": "exploit"},
                None,
            )

        assert "error" in result

    @pytest.mark.asyncio
    async def test_response_truncated_at_2000_chars(self):
        """Long responses are truncated to 2000 chars."""
        from backend.tools.backends.tor_socks5 import TorSOCKS5Backend
        backend = TorSOCKS5Backend(tor_host="tor", tor_port=9050)

        long_text = "A" * 5000
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = f"<html><body><p>{long_text}</p></body></html>"
        mock_response.url = MagicMock()
        mock_response.url.host = "ahmia.fi"

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = mock_response
            result = await backend.execute(
                "dark_web_query",
                {"target": "exploit"},
                None,
            )

        if "output" in result:
            assert len(result["output"]) <= 2000
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd C:/Projects/Optimus && python -m pytest backend/tests/test_tor_socks5.py -v
```

Expected: FAIL on most tests (stub returns `{"status": "stub"}`)

- [ ] **Step 3: Implement TorSOCKS5Backend**

Replace entire `backend/tools/backends/tor_socks5.py`:

```python
"""TorSOCKS5Backend — proxied HTTP via Tor SOCKS5H (Section 6.2).

Security hardening:
- socks5h:// forces DNS resolution through Tor (no local DNS leak)
- No cookies, no stored state, no clearnet redirects
- Response body capped at 512KB, HTML stripped to text
- Result truncated to 2000 chars before returning to agent
- Any redirect to non-.onion / non-Ahmia host is rejected
"""
from __future__ import annotations

import logging
import re
from typing import Any

import httpx

logger = logging.getLogger(__name__)

# Ahmia clearnet domain (also allowed as proxy target)
_ALLOWED_CLEARNET_HOSTS = {"ahmia.fi"}

# Ahmia .onion address (primary dark web search engine)
_AHMIA_ONION = "juhanurmihxlp77nkq76byazcldy2hlmovfu2epvl5ankdibsot4csyd.onion"
_AHMIA_CLEARNET = "https://ahmia.fi/search/"

_MAX_BODY_BYTES = 512 * 1024   # 512 KB
_MAX_OUTPUT_CHARS = 2_000
_TIMEOUT_SECONDS = 60.0


def _strip_html(html: str) -> str:
    """Strip HTML tags, collapse whitespace."""
    text = re.sub(r"<[^>]+>", " ", html)
    text = re.sub(r"&[a-z]+;", " ", text)
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def _is_allowed_host(url: httpx.URL) -> bool:
    """Return True if the response URL is an allowed host."""
    host = url.host
    if host.endswith(".onion"):
        return True
    if host in _ALLOWED_CLEARNET_HOSTS:
        return True
    return False


class TorUnavailableError(Exception):
    """Raised when the Tor proxy is unreachable."""


class TorSOCKS5Backend:
    """Tor SOCKS5H proxy backend for dark web research.

    Uses httpx with socks5h:// proxy so DNS is resolved inside Tor.
    """

    def __init__(
        self,
        tor_host: str = "tor",
        tor_port: int = 9050,
    ) -> None:
        self._proxy_url = f"socks5h://{tor_host}:{tor_port}"

    def _make_client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            proxies={"all://": self._proxy_url},
            timeout=_TIMEOUT_SECONDS,
            follow_redirects=False,
            verify=False,           # .onion has no public CA
            headers={
                "User-Agent": "Mozilla/5.0 (compatible; research-bot/1.0)",
            },
        )

    async def query(self, query_str: str) -> str:
        """Run a search query via Ahmia and return sanitized plain text."""
        params = {"q": query_str}

        try:
            async with self._make_client() as client:
                # Try .onion first, fall back to clearnet Ahmia
                try:
                    onion_url = f"http://{_AHMIA_ONION}/search/"
                    resp = await client.get(onion_url, params=params)
                except (httpx.ConnectError, httpx.ConnectTimeout):
                    resp = await client.get(_AHMIA_CLEARNET, params=params)

        except httpx.ProxyError as exc:
            raise TorUnavailableError(f"Tor proxy unreachable: {exc}") from exc
        except httpx.TimeoutException as exc:
            raise TorUnavailableError(f"Tor query timed out: {exc}") from exc

        # Redirect guard
        if not _is_allowed_host(resp.url):
            logger.warning("TorSOCKS5: redirect to disallowed host %s — rejecting", resp.url.host)
            return ""

        # Body cap
        raw = resp.text[:_MAX_BODY_BYTES]

        # Strip HTML, truncate
        text = _strip_html(raw)
        return text[:_MAX_OUTPUT_CHARS]

    async def execute(self, tool_name: str, tool_input: dict[str, Any], tool_spec: Any) -> dict[str, Any]:
        """Execute a tool via Tor proxy.

        Supported tools:
          dark_web_query — search Ahmia for target/flags
        """
        if tool_name != "dark_web_query":
            return {"error": f"TorSOCKS5Backend: unsupported tool {tool_name}"}

        target = tool_input.get("target", "")
        flags = tool_input.get("flags", "")
        query_str = f"{target} {flags}".strip() or "exploit CVE"

        try:
            text = await self.query(query_str)
            if not text:
                return {"error": "tor_empty_response", "output": ""}
            return {"output": text, "source": "ahmia_dark_web"}
        except TorUnavailableError as exc:
            logger.warning("TorSOCKS5Backend: %s", exc)
            return {"error": "tor_unavailable", "details": str(exc)}
        except Exception as exc:
            logger.error("TorSOCKS5Backend unexpected error: %s", exc)
            return {"error": str(exc)}
```

- [ ] **Step 4: Run tests**

```bash
cd C:/Projects/Optimus && python -m pytest backend/tests/test_tor_socks5.py -v
```

Expected: All 5 tests PASS

- [ ] **Step 5: Commit**

```bash
git add backend/tools/backends/tor_socks5.py backend/tests/test_tor_socks5.py
git commit -m "feat: implement TorSOCKS5Backend with SOCKS5H DNS-over-Tor and security hardening"
```

---

### Task 3: Source adapters — NVDAdapter + CISAKEVAdapter

**Files:**
- Create: `backend/intelligence/source_adapters.py`
- Create: `backend/tests/test_source_adapters.py`

- [ ] **Step 1: Write failing tests for NVD + CISA**

Create `backend/tests/test_source_adapters.py`:

```python
"""Tests for web intelligence source adapters."""
from __future__ import annotations

import pytest
from unittest.mock import AsyncMock, MagicMock, patch


# ─── NVDAdapter ───────────────────────────────────────────────────────────────

class TestNVDAdapter:

    @pytest.mark.asyncio
    async def test_fetch_returns_entries(self):
        """NVDAdapter.fetch() returns ResearchKBEntry list."""
        from backend.intelligence.source_adapters import NVDAdapter
        from backend.intelligence.research_kb import ResearchKBEntry

        nvd_payload = {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": "CVE-2024-1234",
                        "descriptions": [{"lang": "en", "value": "Remote code execution in Apache"}],
                        "metrics": {
                            "cvssMetricV31": [{"cvssData": {"baseScore": 9.8}}]
                        },
                        "references": [{"url": "https://example.com/advisory"}],
                    }
                }
            ]
        }

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = nvd_payload

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = mock_resp
            adapter = NVDAdapter()
            entries = await adapter.fetch(None)

        assert len(entries) == 1
        assert entries[0].cve_id == "CVE-2024-1234"
        assert entries[0].source == "nvd"
        assert entries[0].cvss_score == 9.8
        assert "Remote code execution" in entries[0].description

    @pytest.mark.asyncio
    async def test_fetch_incremental_uses_last_run(self):
        """NVDAdapter includes lastModStartDate when last_run provided."""
        from backend.intelligence.source_adapters import NVDAdapter

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {"vulnerabilities": []}

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = mock_resp
            adapter = NVDAdapter()
            await adapter.fetch("2024-01-01T00:00:00")

        call_kwargs = mock_get.call_args
        url_or_params = str(call_kwargs)
        assert "lastModStartDate" in url_or_params or "2024-01-01" in url_or_params

    @pytest.mark.asyncio
    async def test_fetch_handles_429_retry(self):
        """NVDAdapter retries once on 429."""
        from backend.intelligence.source_adapters import NVDAdapter

        resp_429 = MagicMock()
        resp_429.status_code = 429

        resp_200 = MagicMock()
        resp_200.status_code = 200
        resp_200.json.return_value = {"vulnerabilities": []}

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_get.side_effect = [resp_429, resp_200]
            with patch("asyncio.sleep", new_callable=AsyncMock):
                adapter = NVDAdapter()
                entries = await adapter.fetch(None)

        assert mock_get.call_count == 2
        assert entries == []

    @pytest.mark.asyncio
    async def test_fetch_error_returns_empty(self):
        """NVDAdapter returns [] on connection error."""
        from backend.intelligence.source_adapters import NVDAdapter
        import httpx

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_get.side_effect = httpx.ConnectError("refused")
            adapter = NVDAdapter()
            entries = await adapter.fetch(None)

        assert entries == []


# ─── CISAKEVAdapter ───────────────────────────────────────────────────────────

class TestCISAKEVAdapter:

    @pytest.mark.asyncio
    async def test_fetch_returns_entries(self):
        """CISAKEVAdapter.fetch() returns ResearchKBEntry list."""
        from backend.intelligence.source_adapters import CISAKEVAdapter

        cisa_payload = {
            "vulnerabilities": [
                {
                    "cveID": "CVE-2024-5678",
                    "vendorProject": "Microsoft",
                    "product": "Windows",
                    "vulnerabilityName": "Windows SMB RCE",
                    "shortDescription": "Remote code execution via SMB",
                    "knownRansomwareCampaignUse": "Known",
                }
            ]
        }

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = cisa_payload

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = mock_resp
            adapter = CISAKEVAdapter()
            entries = await adapter.fetch(None)

        assert len(entries) == 1
        assert entries[0].cve_id == "CVE-2024-5678"
        assert entries[0].source == "cisa_kev"
        assert "Microsoft" in entries[0].description or "Windows" in entries[0].description

    @pytest.mark.asyncio
    async def test_fetch_error_returns_empty(self):
        """CISAKEVAdapter returns [] on error."""
        from backend.intelligence.source_adapters import CISAKEVAdapter
        import httpx

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_get.side_effect = httpx.ConnectError("refused")
            adapter = CISAKEVAdapter()
            entries = await adapter.fetch(None)

        assert entries == []


# ─── GitHubPoCAdapter ─────────────────────────────────────────────────────────

class TestGitHubPoCAdapter:

    @pytest.mark.asyncio
    async def test_fetch_returns_entries(self):
        """GitHubPoCAdapter.fetch() returns ResearchKBEntry list."""
        from backend.intelligence.source_adapters import GitHubPoCAdapter

        gh_payload = {
            "items": [
                {
                    "full_name": "user/CVE-2024-1234-poc",
                    "description": "PoC exploit for CVE-2024-1234",
                    "html_url": "https://github.com/user/CVE-2024-1234-poc",
                    "updated_at": "2024-01-15T00:00:00Z",
                }
            ]
        }

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = gh_payload

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = mock_resp
            adapter = GitHubPoCAdapter()
            entries = await adapter.fetch(None)

        assert len(entries) == 1
        assert entries[0].source == "github_poc"
        assert entries[0].poc_url is not None
        assert "CVE-2024-1234" in (entries[0].cve_id or "") or "CVE-2024-1234" in entries[0].description

    @pytest.mark.asyncio
    async def test_fetch_error_returns_empty(self):
        """GitHubPoCAdapter returns [] on error."""
        from backend.intelligence.source_adapters import GitHubPoCAdapter
        import httpx

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_get.side_effect = httpx.ConnectError("refused")
            adapter = GitHubPoCAdapter()
            entries = await adapter.fetch(None)

        assert entries == []


# ─── MITREAttackAdapter ───────────────────────────────────────────────────────

class TestMITREAttackAdapter:

    @pytest.mark.asyncio
    async def test_fetch_returns_entries(self):
        """MITREAttackAdapter.fetch() returns ResearchKBEntry list."""
        from backend.intelligence.source_adapters import MITREAttackAdapter

        stix_payload = {
            "objects": [
                {
                    "type": "attack-pattern",
                    "id": "attack-pattern--12345",
                    "name": "Spearphishing Attachment",
                    "description": "Adversaries may send spearphishing emails",
                    "external_references": [
                        {
                            "source_name": "mitre-attack",
                            "external_id": "T1566.001",
                            "url": "https://attack.mitre.org/techniques/T1566/001",
                        }
                    ],
                },
                {
                    "type": "malware",  # should be ignored
                    "id": "malware--abc",
                    "name": "Some Malware",
                }
            ]
        }

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = stix_payload

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = mock_resp
            adapter = MITREAttackAdapter()
            entries = await adapter.fetch(None)

        assert len(entries) == 1
        assert entries[0].source == "attack"
        assert entries[0].technique_id == "T1566.001"
        assert "Spearphishing" in entries[0].description

    @pytest.mark.asyncio
    async def test_fetch_error_returns_empty(self):
        from backend.intelligence.source_adapters import MITREAttackAdapter
        import httpx

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_get.side_effect = httpx.ConnectError("refused")
            adapter = MITREAttackAdapter()
            entries = await adapter.fetch(None)

        assert entries == []


# ─── BlogsAdapter ─────────────────────────────────────────────────────────────

class TestBlogsAdapter:

    @pytest.mark.asyncio
    async def test_fetch_parses_rss(self):
        """BlogsAdapter.fetch() parses RSS and returns entries."""
        from backend.intelligence.source_adapters import BlogsAdapter

        rss_xml = """<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0">
  <channel>
    <title>Security Blog</title>
    <item>
      <title>CVE-2024-9999 Critical Flaw</title>
      <link>https://blog.example.com/cve-2024-9999</link>
      <description>A critical vulnerability CVE-2024-9999 was discovered in OpenSSL</description>
      <pubDate>Mon, 01 Jan 2024 12:00:00 GMT</pubDate>
    </item>
  </channel>
</rss>"""

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = rss_xml

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = mock_resp
            adapter = BlogsAdapter()
            entries = await adapter.fetch(None)

        assert len(entries) >= 1
        assert entries[0].source == "blogs"
        assert "CVE-2024-9999" in entries[0].description or "CVE-2024-9999" in (entries[0].cve_id or "")

    @pytest.mark.asyncio
    async def test_fetch_error_returns_empty(self):
        from backend.intelligence.source_adapters import BlogsAdapter
        import httpx

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_get.side_effect = httpx.ConnectError("refused")
            adapter = BlogsAdapter()
            entries = await adapter.fetch(None)

        assert entries == []


# ─── ExploitDBAdapter ─────────────────────────────────────────────────────────

class TestExploitDBAdapter:

    @pytest.mark.asyncio
    async def test_fetch_parses_csv(self):
        """ExploitDBAdapter.fetch() parses CSV and returns CVE-tagged entries."""
        from backend.intelligence.source_adapters import ExploitDBAdapter

        csv_content = (
            "id,file,description,date_published,author,type,platform,port,"
            "date_added,date_updated,verified,codes,tags,aliases,screenshot_url,"
            "application_url,source_url\n"
            "50383,exploits/linux/remote/50383.py,"
            "Apache 2.4.49 - Path Traversal and Remote Code Execution,"
            "2021-10-07,John Doe,remote,linux,,"
            "2021-10-07,2021-10-11,1,CVE-2021-41773,,,,,"
            "https://www.exploit-db.com/exploits/50383\n"
            "99999,exploits/windows/local/99999.py,"
            "Some exploit with no CVE,"
            "2024-01-01,Jane Doe,local,windows,,"
            "2024-01-01,2024-01-02,0,,,,,,"
            "https://www.exploit-db.com/exploits/99999\n"
        )

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = csv_content

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = mock_resp
            adapter = ExploitDBAdapter()
            entries = await adapter.fetch(None)

        # Only CVE-tagged entries should be returned
        assert len(entries) == 1
        assert entries[0].cve_id == "CVE-2021-41773"
        assert entries[0].source == "exploitdb"
        assert entries[0].poc_url is not None

    @pytest.mark.asyncio
    async def test_fetch_error_returns_empty(self):
        from backend.intelligence.source_adapters import ExploitDBAdapter
        import httpx

        with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_get.side_effect = httpx.ConnectError("refused")
            adapter = ExploitDBAdapter()
            entries = await adapter.fetch(None)

        assert entries == []


# ─── DarkWebAdapter ───────────────────────────────────────────────────────────

class TestDarkWebAdapter:

    @pytest.mark.asyncio
    async def test_fetch_returns_entries_from_tor(self):
        """DarkWebAdapter.fetch() returns entries when Tor is available."""
        from backend.intelligence.source_adapters import DarkWebAdapter
        from backend.tools.backends.tor_socks5 import TorSOCKS5Backend

        mock_tor = MagicMock(spec=TorSOCKS5Backend)
        mock_tor.query = AsyncMock(return_value=(
            "CVE-2024-1234 critical exploit available on darknet forum. "
            "Remote code execution vulnerability in Apache servers."
        ))

        adapter = DarkWebAdapter(tor_backend=mock_tor)
        entries = await adapter.fetch(None)

        assert isinstance(entries, list)
        assert mock_tor.query.called

    @pytest.mark.asyncio
    async def test_fetch_tor_unavailable_returns_empty(self):
        """DarkWebAdapter returns [] when Tor is unavailable."""
        from backend.intelligence.source_adapters import DarkWebAdapter
        from backend.tools.backends.tor_socks5 import TorSOCKS5Backend, TorUnavailableError

        mock_tor = MagicMock(spec=TorSOCKS5Backend)
        mock_tor.query = AsyncMock(side_effect=TorUnavailableError("tor down"))

        adapter = DarkWebAdapter(tor_backend=mock_tor)
        entries = await adapter.fetch(None)

        assert entries == []
```

- [ ] **Step 2: Run tests to verify they fail**

```bash
cd C:/Projects/Optimus && python -m pytest backend/tests/test_source_adapters.py -v
```

Expected: ImportError / AttributeError — `source_adapters` doesn't exist yet.

- [ ] **Step 3: Create source_adapters.py with all 7 adapters**

Create `backend/intelligence/source_adapters.py`:

```python
"""Web intelligence source adapters for ResearchDaemon (Section 15.1).

Each adapter implements:
    async def fetch(last_run: str | None) -> list[ResearchKBEntry]

Adapters use only public free APIs — no API keys required.
"""
from __future__ import annotations

import asyncio
import csv
import io
import logging
import re
import uuid
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import Any

import httpx

from backend.intelligence.research_kb import ResearchKBEntry

logger = logging.getLogger(__name__)

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)

_DEFAULT_TIMEOUT = 30.0
_HEADERS = {"User-Agent": "Optimus-Intel-Daemon/2.0 (security research)"}


def _make_client(timeout: float = _DEFAULT_TIMEOUT) -> httpx.AsyncClient:
    return httpx.AsyncClient(timeout=timeout, headers=_HEADERS, follow_redirects=True)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# NVDAdapter — NIST National Vulnerability Database
# ---------------------------------------------------------------------------

class NVDAdapter:
    """Fetches CVE data from NVD REST API v2.

    Uses incremental ingestion via lastModStartDate when last_run is provided.
    Retries once on 429 (rate limit) with a 6-second sleep.
    """

    _URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    async def fetch(self, last_run: str | None) -> list[ResearchKBEntry]:
        params: dict[str, Any] = {"resultsPerPage": 100}
        if last_run:
            # NVD wants ISO 8601 with milliseconds: 2024-01-01T00:00:00.000
            ts = last_run[:19] + ".000"
            params["lastModStartDate"] = ts
            params["lastModEndDate"] = _now_iso()[:19] + ".000"

        try:
            async with _make_client(timeout=60.0) as client:
                resp = await client.get(self._URL, params=params)

                if resp.status_code == 429:
                    logger.warning("NVDAdapter: rate limited, sleeping 6s then retrying")
                    await asyncio.sleep(6)
                    resp = await client.get(self._URL, params=params)

                if resp.status_code != 200:
                    logger.warning("NVDAdapter: HTTP %d", resp.status_code)
                    return []

                data = resp.json()
        except Exception as exc:
            logger.warning("NVDAdapter: fetch failed: %s", exc)
            return []

        entries: list[ResearchKBEntry] = []
        for vuln in data.get("vulnerabilities", []):
            cve = vuln.get("cve", {})
            cve_id = cve.get("id")
            if not cve_id:
                continue

            # Description (English)
            desc = ""
            for d in cve.get("descriptions", []):
                if d.get("lang") == "en":
                    desc = d.get("value", "")
                    break

            # CVSS score (v3.1 preferred)
            cvss = None
            metrics = cve.get("metrics", {})
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                if key in metrics and metrics[key]:
                    cvss = metrics[key][0].get("cvssData", {}).get("baseScore")
                    break

            # PoC URL from references
            poc_url = None
            for ref in cve.get("references", []):
                poc_url = ref.get("url")
                break

            entries.append(ResearchKBEntry(
                entry_id=f"nvd-{cve_id}",
                source="nvd",
                cve_id=cve_id,
                description=desc,
                cvss_score=cvss,
                poc_url=poc_url,
                raw_data={"nvd_id": cve_id},
            ))

        logger.info("NVDAdapter: fetched %d CVEs", len(entries))
        return entries


# ---------------------------------------------------------------------------
# CISAKEVAdapter — CISA Known Exploited Vulnerabilities catalog
# ---------------------------------------------------------------------------

class CISAKEVAdapter:
    """Fetches the CISA KEV catalog (full JSON, dedup by CVE ID in KB)."""

    _URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

    async def fetch(self, last_run: str | None) -> list[ResearchKBEntry]:
        try:
            async with _make_client() as client:
                resp = await client.get(self._URL)
                if resp.status_code != 200:
                    logger.warning("CISAKEVAdapter: HTTP %d", resp.status_code)
                    return []
                data = resp.json()
        except Exception as exc:
            logger.warning("CISAKEVAdapter: fetch failed: %s", exc)
            return []

        entries: list[ResearchKBEntry] = []
        for vuln in data.get("vulnerabilities", []):
            cve_id = vuln.get("cveID")
            if not cve_id:
                continue

            desc_parts = [
                vuln.get("vendorProject", ""),
                vuln.get("product", ""),
                vuln.get("vulnerabilityName", ""),
                vuln.get("shortDescription", ""),
            ]
            desc = " — ".join(p for p in desc_parts if p)

            entries.append(ResearchKBEntry(
                entry_id=f"cisa-{cve_id}",
                source="cisa_kev",
                cve_id=cve_id,
                description=desc,
                raw_data={
                    "ransomware": vuln.get("knownRansomwareCampaignUse", ""),
                    "due_date": vuln.get("dueDate", ""),
                },
            ))

        logger.info("CISAKEVAdapter: fetched %d KEV entries", len(entries))
        return entries


# ---------------------------------------------------------------------------
# GitHubPoCAdapter — GitHub repository search for CVE PoCs
# ---------------------------------------------------------------------------

class GitHubPoCAdapter:
    """Searches GitHub for repositories tagged as CVE proof-of-concept exploits."""

    _URL = "https://api.github.com/search/repositories"

    async def fetch(self, last_run: str | None) -> list[ResearchKBEntry]:
        params = {
            "q": "CVE poc exploit in:name,description",
            "sort": "updated",
            "order": "desc",
            "per_page": 30,
        }

        try:
            async with _make_client() as client:
                resp = await client.get(self._URL, params=params)
                if resp.status_code == 403:
                    logger.warning("GitHubPoCAdapter: rate limited (unauthenticated)")
                    return []
                if resp.status_code != 200:
                    logger.warning("GitHubPoCAdapter: HTTP %d", resp.status_code)
                    return []
                data = resp.json()
        except Exception as exc:
            logger.warning("GitHubPoCAdapter: fetch failed: %s", exc)
            return []

        entries: list[ResearchKBEntry] = []
        for repo in data.get("items", []):
            name = repo.get("full_name", "")
            desc = repo.get("description") or name
            html_url = repo.get("html_url", "")

            # Extract CVE ID from repo name or description
            combined = f"{name} {desc}"
            cve_match = _CVE_RE.search(combined)
            cve_id = cve_match.group(0).upper() if cve_match else None

            entries.append(ResearchKBEntry(
                entry_id=f"ghpoc-{uuid.uuid4().hex[:12]}",
                source="github_poc",
                cve_id=cve_id,
                description=f"GitHub PoC: {desc}",
                poc_url=html_url,
                raw_data={"repo": name, "stars": repo.get("stargazers_count", 0)},
            ))

            await asyncio.sleep(0.1)  # gentle rate limiting

        logger.info("GitHubPoCAdapter: fetched %d PoC repos", len(entries))
        return entries


# ---------------------------------------------------------------------------
# MITREAttackAdapter — MITRE ATT&CK STIX enterprise bundle
# ---------------------------------------------------------------------------

class MITREAttackAdapter:
    """Fetches MITRE ATT&CK enterprise STIX bundle from GitHub.

    Parses attack-pattern objects only. Runs weekly (large file).
    """

    _URL = (
        "https://raw.githubusercontent.com/mitre/cti/master/"
        "enterprise-attack/enterprise-attack.json"
    )

    async def fetch(self, last_run: str | None) -> list[ResearchKBEntry]:
        try:
            async with _make_client(timeout=120.0) as client:
                resp = await client.get(self._URL)
                if resp.status_code != 200:
                    logger.warning("MITREAttackAdapter: HTTP %d", resp.status_code)
                    return []
                data = resp.json()
        except Exception as exc:
            logger.warning("MITREAttackAdapter: fetch failed: %s", exc)
            return []

        entries: list[ResearchKBEntry] = []
        for obj in data.get("objects", []):
            if obj.get("type") != "attack-pattern":
                continue
            if obj.get("revoked"):
                continue

            name = obj.get("name", "")
            desc = obj.get("description", "")[:500]

            # Find MITRE ATT&CK technique ID
            technique_id = None
            for ref in obj.get("external_references", []):
                if ref.get("source_name") == "mitre-attack":
                    technique_id = ref.get("external_id")
                    break

            if not technique_id:
                continue

            entries.append(ResearchKBEntry(
                entry_id=f"attack-{technique_id}",
                source="attack",
                technique_id=technique_id,
                description=f"{name}: {desc}",
                raw_data={"technique": technique_id, "name": name},
            ))

        logger.info("MITREAttackAdapter: fetched %d ATT&CK techniques", len(entries))
        return entries


# ---------------------------------------------------------------------------
# BlogsAdapter — RSS feeds from security blogs
# ---------------------------------------------------------------------------

_RSS_FEEDS = [
    "https://krebsonsecurity.com/feed/",
    "https://www.bleepingcomputer.com/feed/",
    "https://www.rapid7.com/blog/rss.xml",
    "https://isc.sans.edu/rssfeed.xml",
]

_NS = {
    "atom": "http://www.w3.org/2005/Atom",
    "content": "http://purl.org/rss/1.0/modules/content/",
}


class BlogsAdapter:
    """Fetches security blog RSS feeds and extracts CVE-mentioning posts."""

    async def fetch(self, last_run: str | None) -> list[ResearchKBEntry]:
        entries: list[ResearchKBEntry] = []
        headers = dict(_HEADERS)
        if last_run:
            headers["If-Modified-Since"] = last_run

        async with _make_client() as client:
            for feed_url in _RSS_FEEDS:
                try:
                    resp = await client.get(feed_url, headers=headers)
                    if resp.status_code == 304:
                        continue
                    if resp.status_code != 200:
                        logger.warning("BlogsAdapter: %s returned %d", feed_url, resp.status_code)
                        continue

                    feed_entries = self._parse_rss(resp.text, feed_url)
                    entries.extend(feed_entries)

                except Exception as exc:
                    logger.warning("BlogsAdapter: failed to fetch %s: %s", feed_url, exc)

        logger.info("BlogsAdapter: fetched %d blog entries", len(entries))
        return entries

    def _parse_rss(self, xml_text: str, feed_url: str) -> list[ResearchKBEntry]:
        """Parse RSS XML and return entries that mention CVEs."""
        results: list[ResearchKBEntry] = []
        try:
            root = ET.fromstring(xml_text)
        except ET.ParseError as exc:
            logger.warning("BlogsAdapter: XML parse error for %s: %s", feed_url, exc)
            return []

        # Handle both RSS <item> and Atom <entry>
        items = root.findall(".//item") or root.findall(".//entry")
        for item in items:
            title_el = item.find("title")
            link_el = item.find("link")
            desc_el = item.find("description") or item.find("summary")

            title = title_el.text or "" if title_el is not None else ""
            link = link_el.text or (link_el.get("href", "") if link_el is not None else "")
            desc = desc_el.text or "" if desc_el is not None else ""

            combined = f"{title} {desc}"
            # Only include posts that mention a CVE
            cve_matches = _CVE_RE.findall(combined)
            if not cve_matches:
                continue

            cve_id = cve_matches[0].upper()
            results.append(ResearchKBEntry(
                entry_id=f"blog-{uuid.uuid4().hex[:12]}",
                source="blogs",
                cve_id=cve_id,
                description=f"{title}: {desc[:300]}",
                poc_url=link or None,
                raw_data={"feed": feed_url, "all_cves": list(set(m.upper() for m in cve_matches))},
            ))

        return results


# ---------------------------------------------------------------------------
# ExploitDBAdapter — ExploitDB CSV dump (GitLab)
# ---------------------------------------------------------------------------

class ExploitDBAdapter:
    """Fetches ExploitDB files_exploits.csv from GitLab.

    Only imports entries that have CVE codes (codes column).
    No Kali SSH dependency — runs independently of Kali availability.
    """

    _URL = (
        "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"
    )
    _EDB_BASE = "https://www.exploit-db.com/exploits/"

    async def fetch(self, last_run: str | None) -> list[ResearchKBEntry]:
        try:
            async with _make_client(timeout=60.0) as client:
                resp = await client.get(self._URL)
                if resp.status_code != 200:
                    logger.warning("ExploitDBAdapter: HTTP %d", resp.status_code)
                    return []
                csv_text = resp.text
        except Exception as exc:
            logger.warning("ExploitDBAdapter: fetch failed: %s", exc)
            return []

        return self._parse_csv(csv_text)

    def _parse_csv(self, csv_text: str) -> list[ResearchKBEntry]:
        """Parse ExploitDB CSV, return only CVE-tagged entries."""
        entries: list[ResearchKBEntry] = []
        reader = csv.DictReader(io.StringIO(csv_text))

        for row in reader:
            codes = row.get("codes", "").strip()
            if not codes:
                continue

            # codes field: "CVE-2021-41773" or "CVE-2021-41773;CVE-2021-42013"
            cve_ids = [c.strip() for c in codes.split(";") if c.strip().upper().startswith("CVE-")]
            if not cve_ids:
                continue

            edb_id = row.get("id", "").strip()
            desc = row.get("description", "").strip()
            platform = row.get("platform", "").strip()
            poc_url = f"{self._EDB_BASE}{edb_id}" if edb_id else None

            # Use first CVE for primary key (KB deduplicates by cve_id)
            primary_cve = cve_ids[0].upper()

            entries.append(ResearchKBEntry(
                entry_id=f"edb-{edb_id or uuid.uuid4().hex[:8]}",
                source="exploitdb",
                cve_id=primary_cve,
                description=f"ExploitDB {edb_id}: {desc}",
                poc_url=poc_url,
                affected_products=[platform] if platform else [],
                raw_data={"edb_id": edb_id, "all_cves": cve_ids, "platform": platform},
            ))

        logger.info("ExploitDBAdapter: parsed %d CVE-tagged exploits", len(entries))
        return entries


# ---------------------------------------------------------------------------
# DarkWebAdapter — Tor/Ahmia dark web search
# ---------------------------------------------------------------------------

_DARK_WEB_QUERIES = [
    "CVE exploit 2024 0day vulnerability",
    "critical exploit remote code execution",
    "zero day vulnerability database leak",
]


class DarkWebAdapter:
    """Queries Ahmia via Tor for dark web threat intel.

    Runs weekly (slow, unreliable). Returns [] if Tor is unavailable.
    At most 3 queries per run to stay within budget.
    """

    def __init__(self, tor_backend: Any) -> None:
        self._tor = tor_backend

    async def fetch(self, last_run: str | None) -> list[ResearchKBEntry]:
        from backend.tools.backends.tor_socks5 import TorUnavailableError
        entries: list[ResearchKBEntry] = []

        for query in _DARK_WEB_QUERIES:
            try:
                text = await self._tor.query(query)
                if not text:
                    continue

                # Extract any CVE IDs mentioned in the result
                cve_ids = list(set(m.upper() for m in _CVE_RE.findall(text)))

                if cve_ids:
                    for cve_id in cve_ids[:5]:  # cap at 5 CVEs per query result
                        entries.append(ResearchKBEntry(
                            entry_id=f"darkweb-{uuid.uuid4().hex[:12]}",
                            source="dark_web",
                            cve_id=cve_id,
                            description=f"Dark web reference: {text[:200]}",
                            raw_data={"query": query, "all_cves": cve_ids},
                        ))
                else:
                    # Store as general dark web intel without CVE
                    entries.append(ResearchKBEntry(
                        entry_id=f"darkweb-{uuid.uuid4().hex[:12]}",
                        source="dark_web",
                        description=f"Dark web intel [{query}]: {text[:300]}",
                        raw_data={"query": query},
                    ))

            except TorUnavailableError as exc:
                logger.warning("DarkWebAdapter: Tor unavailable: %s", exc)
                return []  # Stop immediately — Tor is down
            except Exception as exc:
                logger.warning("DarkWebAdapter: query '%s' failed: %s", query, exc)

        logger.info("DarkWebAdapter: fetched %d dark web entries", len(entries))
        return entries
```

- [ ] **Step 4: Run all source adapter tests**

```bash
cd C:/Projects/Optimus && python -m pytest backend/tests/test_source_adapters.py -v
```

Expected: All tests PASS

- [ ] **Step 5: Commit**

```bash
git add backend/intelligence/source_adapters.py backend/tests/test_source_adapters.py
git commit -m "feat: implement 7 web intelligence source adapters (NVD, CISA KEV, GitHub PoC, MITRE ATT&CK, Blogs, ExploitDB, DarkWeb)"
```

---

### Task 4: KaliSSH — cve_search and exploit_db command builders

**Files:**
- Modify: `backend/tools/backends/kali_ssh.py`

- [ ] **Step 1: Find the builders dict insertion point**

Open `backend/tools/backends/kali_ssh.py`. Find the `builders` dict in `_build_command()`. It currently ends with the `_web_query` entry. The two new entries go before `_web_query` (or after `shodan`).

Find this line (around line 382):
```python
"shodan": lambda: (
    f"timeout 15 curl -sk 'https://internetdb.shodan.io/{target}' 2>/dev/null "
    f"|| timeout 15 shodan host {target} 2>/dev/null "
    f"|| echo '{{\"error\": \"shodan unavailable for {target}\"}}'"
).strip(),
```

Add immediately after the `shodan` entry (before the `# --- Vulnerability scanning ---` comment):

```python
"cve_search": lambda: (
    f"timeout 20 curl -sk "
    f"'https://cve.circl.lu/api/cve/{tool_input.get(\"target\", target)}' "
    f"2>/dev/null || echo '{{}}'"
).strip(),
"exploit_db": lambda: (
    f"timeout 30 searchsploit --json {target} 2>/dev/null "
    f"|| timeout 30 searchsploit {target} 2>/dev/null "
    f"|| echo '{{\"RESULTS_EXPLOIT\": []}}'"
).strip(),
```

- [ ] **Step 2: Verify the edit is syntactically correct**

```bash
cd C:/Projects/Optimus && python -c "from backend.tools.backends.kali_ssh import KaliConnectionManager; print('OK')"
```

Expected: `OK`

- [ ] **Step 3: Write a quick test to verify the builders exist**

Add to `backend/tests/test_kali_ssh_timeouts.py` (existing file — append the new test class at the bottom):

```python
class TestNewIntelBuilders:
    """Verify cve_search and exploit_db command builders are present."""

    def test_cve_search_builder_exists(self):
        """cve_search tool generates a curl command."""
        from backend.tools.backends.kali_ssh import KaliConnectionManager
        # We test _build_command indirectly via the builders dict
        # by constructing a minimal mock connection
        import inspect
        src = inspect.getsource(KaliConnectionManager._build_command)
        assert "cve_search" in src
        assert "cve.circl.lu" in src

    def test_exploit_db_builder_exists(self):
        """exploit_db tool generates a searchsploit command."""
        from backend.tools.backends.kali_ssh import KaliConnectionManager
        import inspect
        src = inspect.getsource(KaliConnectionManager._build_command)
        assert "exploit_db" in src
        assert "searchsploit" in src
```

- [ ] **Step 4: Run the test**

```bash
cd C:/Projects/Optimus && python -m pytest backend/tests/test_kali_ssh_timeouts.py::TestNewIntelBuilders -v
```

Expected: Both tests PASS

- [ ] **Step 5: Commit**

```bash
git add backend/tools/backends/kali_ssh.py backend/tests/test_kali_ssh_timeouts.py
git commit -m "feat: add cve_search (CIRCL API) and exploit_db (searchsploit) KaliSSH builders"
```

---

### Task 5: OmX — pre-engagement ResearchKB enrichment

**Files:**
- Modify: `backend/core/omx.py`
- Create: `backend/tests/test_omx_enrichment.py`

- [ ] **Step 1: Write failing tests**

Create `backend/tests/test_omx_enrichment.py`:

```python
"""Tests for OmX ResearchKB pre-engagement enrichment."""
from __future__ import annotations

import pytest
from unittest.mock import AsyncMock, MagicMock


class TestOmXResearchEnrichment:

    @pytest.mark.asyncio
    async def test_plan_includes_research_context_when_kb_has_results(self):
        """When KB returns CVEs for target, plan.metadata includes research_context."""
        from backend.core.omx import OmX
        from backend.intelligence.research_kb import ResearchKBEntry

        mock_kb = MagicMock()
        mock_kb.query = AsyncMock(return_value=[
            ResearchKBEntry(
                entry_id="nvd-CVE-2024-1234",
                source="nvd",
                cve_id="CVE-2024-1234",
                description="Apache RCE",
                cvss_score=9.8,
                poc_url="https://github.com/user/poc",
            )
        ])

        from backend.core.models import ScopeConfig
        omx = OmX(research_kb=mock_kb)
        scope = ScopeConfig(targets=["10.0.0.1"])
        plan = await omx.plan("$pentest 10.0.0.1", scope=scope)

        assert "research_context" in plan.metadata
        assert "CVE-2024-1234" in plan.metadata["research_context"]

    @pytest.mark.asyncio
    async def test_plan_proceeds_when_kb_is_none(self):
        """OmX.plan() works normally when research_kb=None."""
        from backend.core.omx import OmX
        from backend.core.models import ScopeConfig

        omx = OmX(research_kb=None)
        scope = ScopeConfig(targets=["10.0.0.1"])
        plan = await omx.plan("$pentest 10.0.0.1", scope=scope)

        assert plan is not None
        assert plan.metadata.get("research_context") is None

    @pytest.mark.asyncio
    async def test_plan_proceeds_when_kb_query_fails(self):
        """OmX.plan() proceeds gracefully if KB.query() raises."""
        from backend.core.omx import OmX
        from backend.core.models import ScopeConfig

        mock_kb = MagicMock()
        mock_kb.query = AsyncMock(side_effect=Exception("DB error"))

        omx = OmX(research_kb=mock_kb)
        scope = ScopeConfig(targets=["10.0.0.1"])
        plan = await omx.plan("$pentest 10.0.0.1", scope=scope)

        assert plan is not None  # planning should not crash

    @pytest.mark.asyncio
    async def test_plan_no_context_when_kb_empty(self):
        """No research_context key when KB returns no results."""
        from backend.core.omx import OmX
        from backend.core.models import ScopeConfig

        mock_kb = MagicMock()
        mock_kb.query = AsyncMock(return_value=[])

        omx = OmX(research_kb=mock_kb)
        scope = ScopeConfig(targets=["10.0.0.1"])
        plan = await omx.plan("$pentest 10.0.0.1", scope=scope)

        assert plan.metadata.get("research_context") is None
```

- [ ] **Step 2: Run failing tests**

```bash
cd C:/Projects/Optimus && python -m pytest backend/tests/test_omx_enrichment.py -v
```

Expected: FAIL — `OmX.__init__` doesn't accept `research_kb` yet.

- [ ] **Step 3: Modify OmX.__init__ and plan()**

In `backend/core/omx.py`, find `class OmX:` at line ~331.

Change `__init__`:
```python
def __init__(
    self,
    llm_router: LLMRouter | None = None,
    research_kb: Any = None,
) -> None:
    self._llm = llm_router
    self._research_kb = research_kb
```

Add this import at the top of the file (after existing imports):
```python
from typing import Any
```
(Note: `Any` is already imported via `from typing import Any` if it's there — check first. If not present, add it.)

Change `plan()` method — add KB enrichment call after plan is built. Find the `plan()` method. It currently ends with:
```python
        if directive:
            return self._plan_from_directive(directive, message, scope)

        # No directive found — use LLM for decomposition
        return await self._plan_from_natural_language(message, scope)
```

Replace with:
```python
        if directive:
            plan = self._plan_from_directive(directive, message, scope)
        else:
            plan = await self._plan_from_natural_language(message, scope)

        await self._enrich_plan_with_kb(plan, scope)
        return plan
```

Add this new method to the `OmX` class (after `get_available_directives`):
```python
    async def _enrich_plan_with_kb(
        self,
        plan: "EngagementPlan",
        scope: "ScopeConfig | None",
    ) -> None:
        """Query ResearchKB and inject matching CVEs into plan.metadata."""
        if self._research_kb is None:
            return

        target = ""
        if scope and scope.targets:
            target = scope.targets[0]
        if not target:
            return

        try:
            entries = await self._research_kb.query(keyword=target, limit=5)
            if not entries:
                return

            lines = ["Known CVEs/PoCs from ResearchKB:"]
            for e in entries:
                parts = []
                if e.cve_id:
                    parts.append(e.cve_id)
                if e.cvss_score is not None:
                    parts.append(f"CVSS:{e.cvss_score}")
                if e.description:
                    parts.append(e.description[:120])
                if e.poc_url:
                    parts.append(f"PoC:{e.poc_url}")
                lines.append("  - " + " | ".join(parts))

            plan.metadata["research_context"] = "\n".join(lines)
            logger.info("OmX: injected %d KB entries into plan %s", len(entries), plan.plan_id)

        except Exception as exc:
            logger.warning("OmX: KB enrichment failed, proceeding without context: %s", exc)
```

- [ ] **Step 4: Run tests**

```bash
cd C:/Projects/Optimus && python -m pytest backend/tests/test_omx_enrichment.py -v
```

Expected: All 4 tests PASS

- [ ] **Step 5: Commit**

```bash
git add backend/core/omx.py backend/tests/test_omx_enrichment.py
git commit -m "feat: inject ResearchKB CVE context into OmX engagement plans"
```

---

### Task 6: OmO — inject research_context into agent prompts

**Files:**
- Modify: `backend/core/omo.py`

- [ ] **Step 1: Find prompt construction in OmO**

Open `backend/core/omo.py`. Find `_dispatch_phase()` (around line 250). The prompt is built here:

```python
prompt = f"Execute {phase_name} phase against {targets_str}".strip() if targets_str else f"Execute {phase_name} phase"

# Inject phase metadata flags into the prompt so agents can read them.
if phase_metadata.get("exploit_mode"):
    prompt += f" exploit_mode={phase_metadata['exploit_mode']}"
```

- [ ] **Step 2: Add research_context injection**

The `_dispatch_phase` signature is:
```python
async def _dispatch_phase(
    self,
    agent_type: AgentType,
    phase_name: str,
    scope: ScopeConfig,
    plan_id: str,
    phase_metadata: dict | None = None,
) -> AgentResult:
```

The method doesn't currently receive the full `plan`. The `plan` is available in `execute_plan()`. The cleanest minimal change: pass `research_context` as part of `phase_metadata` from `execute_plan()`.

In `execute_plan()`, find where `_dispatch_phase` is called. It looks like:
```python
result = await self._dispatch_phase(
    agent_type=agent_type,
    phase_name=phase.name,
    scope=scope,
    plan_id=plan.plan_id,
    phase_metadata=phase.metadata,
)
```

Change this call to merge research_context into phase_metadata:
```python
phase_meta = dict(phase.metadata or {})
if plan.metadata.get("research_context"):
    phase_meta["research_context"] = plan.metadata["research_context"]

result = await self._dispatch_phase(
    agent_type=agent_type,
    phase_name=phase.name,
    scope=scope,
    plan_id=plan.plan_id,
    phase_metadata=phase_meta,
)
```

Then in `_dispatch_phase()`, after the `exploit_mode` injection block, add:
```python
        if phase_metadata.get("research_context"):
            prompt += f"\n\nKnown Intel:\n{phase_metadata['research_context']}"
```

- [ ] **Step 3: Verify import compiles cleanly**

```bash
cd C:/Projects/Optimus && python -c "from backend.core.omo import OmO; print('OmO OK')"
```

Expected: `OmO OK`

- [ ] **Step 4: Run existing OmO tests to confirm no regression**

```bash
cd C:/Projects/Optimus && python -m pytest backend/tests/test_pentest_e2e.py -v
```

Expected: All pass (or same pass/fail as before)

- [ ] **Step 5: Commit**

```bash
git add backend/core/omo.py
git commit -m "feat: prepend ResearchKB intel context into OmO agent prompts"
```

---

### Task 7: IntelAgent — StrategyEvolution enrichment hook

**Files:**
- Modify: `backend/agents/intel_agent.py`
- Create: `backend/tests/test_intel_agent_enrich.py`

- [ ] **Step 1: Write failing tests**

Create `backend/tests/test_intel_agent_enrich.py`:

```python
"""Tests for IntelAgent StrategyEvolutionEngine enrichment hook."""
from __future__ import annotations

import pytest
from dataclasses import dataclass, field
from unittest.mock import AsyncMock, MagicMock, patch


@dataclass
class _FakeAgentResult:
    status: str = "completed"
    findings: list = field(default_factory=list)
    error: str | None = None
    output: str = ""
    tool_calls: list = field(default_factory=list)


class TestIntelAgentEnrichment:

    @pytest.mark.asyncio
    async def test_execute_calls_strategy_engine_when_present(self):
        """IntelAgent.execute() calls strategy_engine.enrich_chain() when provided."""
        from backend.agents.intel_agent import IntelAgent
        from backend.core.models import AgentTask, AgentType, EngineType, ScopeConfig

        mock_engine = MagicMock()
        mock_engine.enrich_chain = AsyncMock(return_value=MagicMock(enrichment_count=1, research_sources=["nvd"]))

        mock_run_loop = AsyncMock(return_value=_FakeAgentResult(
            status="completed",
            findings=[{
                "cve_id": "CVE-2024-1234",
                "severity": "critical",
                "title": "Apache RCE",
            }],
        ))

        agent = IntelAgent(
            agent_id="test-intel",
            agent_type=AgentType.INTEL,
            engine=EngineType.INFRASTRUCTURE,
            scope=ScopeConfig(targets=["10.0.0.1"]),
            strategy_engine=mock_engine,
        )

        with patch.object(agent, "run_loop", mock_run_loop):
            await agent.execute(AgentTask(
                task_id="t1",
                agent_class="intel",
                prompt="Execute Intel phase against 10.0.0.1",
            ))

        mock_engine.enrich_chain.assert_called_once()

    @pytest.mark.asyncio
    async def test_execute_works_without_strategy_engine(self):
        """IntelAgent.execute() works normally when strategy_engine=None."""
        from backend.agents.intel_agent import IntelAgent
        from backend.core.models import AgentTask, AgentType, EngineType, ScopeConfig

        mock_run_loop = AsyncMock(return_value=_FakeAgentResult(status="completed"))

        agent = IntelAgent(
            agent_id="test-intel",
            agent_type=AgentType.INTEL,
            engine=EngineType.INFRASTRUCTURE,
            scope=ScopeConfig(targets=["10.0.0.1"]),
            strategy_engine=None,
        )

        with patch.object(agent, "run_loop", mock_run_loop):
            result = await agent.execute(AgentTask(
                task_id="t2",
                agent_class="intel",
                prompt="Execute Intel phase against 10.0.0.1",
            ))

        assert result is not None
        assert result.status == "completed"

    @pytest.mark.asyncio
    async def test_enrich_does_not_crash_on_engine_error(self):
        """Enrichment failure does not crash IntelAgent.execute()."""
        from backend.agents.intel_agent import IntelAgent
        from backend.core.models import AgentTask, AgentType, EngineType, ScopeConfig

        mock_engine = MagicMock()
        mock_engine.enrich_chain = AsyncMock(side_effect=Exception("KB down"))

        mock_run_loop = AsyncMock(return_value=_FakeAgentResult(
            status="completed",
            findings=[{"cve_id": "CVE-2024-9999", "severity": "high"}],
        ))

        agent = IntelAgent(
            agent_id="test-intel",
            agent_type=AgentType.INTEL,
            engine=EngineType.INFRASTRUCTURE,
            scope=ScopeConfig(targets=["10.0.0.1"]),
            strategy_engine=mock_engine,
        )

        with patch.object(agent, "run_loop", mock_run_loop):
            result = await agent.execute(AgentTask(
                task_id="t3",
                agent_class="intel",
                prompt="Execute Intel phase against 10.0.0.1",
            ))

        assert result.status == "completed"  # should not fail
```

- [ ] **Step 2: Run failing tests**

```bash
cd C:/Projects/Optimus && python -m pytest backend/tests/test_intel_agent_enrich.py -v
```

Expected: FAIL — `IntelAgent` doesn't accept `strategy_engine` yet.

- [ ] **Step 3: Modify IntelAgent**

Replace entire `backend/agents/intel_agent.py`:

```python
"""IntelAgent — Threat intelligence sub-agent (Section 5.2).

Tools: shodan, cve_search, exploit_db, dark_web_query
Runs in parallel with other agents — enriches findings with CVE/ATT&CK/threat intel.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from backend.core.base_agent import AgentAction, BaseAgent
from backend.core.llm_router import LLMRouter
from backend.core.models import AgentResult, AgentTask, AgentType, EngineType
from backend.agents.scan_agent import _extract_target, _plan_with_llm

logger = logging.getLogger(__name__)

INTEL_SYSTEM_PROMPT = """You are a threat intelligence agent. Enrich findings with CVE, ATT&CK, and threat intel.

Available tools: shodan, cve_search, exploit_db, dark_web_query

Respond with JSON: {"tool": "name", "input": {"target": "...", "flags": "..."}, "reasoning": "...", "is_terminal": false}
When done: {"tool": null, "input": {}, "reasoning": "Intel gathering complete", "is_terminal": true}"""


@dataclass
class IntelAgent(BaseAgent):
    """Threat intelligence enrichment agent."""

    agent_type: AgentType = AgentType.INTEL
    engine: EngineType = EngineType.INFRASTRUCTURE
    allowed_tools: frozenset[str] = field(
        default_factory=lambda: frozenset({"shodan", "cve_search", "exploit_db", "dark_web_query"})
    )
    max_iterations: int = 15
    llm_router: LLMRouter | None = None
    strategy_engine: Any = None
    _action_history: list[dict[str, Any]] = field(default_factory=list)

    async def execute(self, task: AgentTask) -> AgentResult:
        self._action_history = []
        result = await self.run_loop(task)
        await self._post_run_enrich(result)
        return result

    async def _post_run_enrich(self, result: AgentResult) -> None:
        """Enrich findings with StrategyEvolutionEngine after run_loop completes."""
        if self.strategy_engine is None:
            return

        findings = getattr(result, "findings", []) or []
        if not findings:
            return

        # Build AttackChain from findings that have CVE IDs or technique names
        try:
            from backend.intelligence.strategy_evolution import AttackChain, ChainNode

            nodes = []
            for i, finding in enumerate(findings):
                cve_id = finding.get("cve_id") if isinstance(finding, dict) else None
                title = (
                    finding.get("title", "") if isinstance(finding, dict)
                    else getattr(finding, "title", "")
                )
                tool = (
                    finding.get("tool_used", "") if isinstance(finding, dict)
                    else getattr(finding, "tool_used", "")
                )
                nodes.append(ChainNode(
                    step_id=f"intel-{i}",
                    technique=title or "unknown",
                    cve_id=cve_id,
                    tool=tool or None,
                ))

            chain = AttackChain(
                chain_id=f"intel-chain-{id(result)}",
                nodes=nodes,
                target=str(self.scope.targets[0]) if self.scope and self.scope.targets else "",
            )

            enriched = await self.strategy_engine.enrich_chain(chain)
            logger.info(
                "IntelAgent: enriched %d/%d nodes with KB intel",
                enriched.enrichment_count,
                len(nodes),
            )

        except Exception as exc:
            logger.warning("IntelAgent: post-run enrichment failed (non-fatal): %s", exc)

    async def _plan_next_action(self, task: AgentTask) -> AgentAction | None:
        target = _extract_target(task.prompt, scope=self.scope)
        if self.llm_router:
            return await _plan_with_llm(self, task, target, INTEL_SYSTEM_PROMPT)
        return self._plan_fallback(target)

    def _plan_fallback(self, target: str) -> AgentAction | None:
        step = len(self._action_history)
        steps = [
            AgentAction("shodan", {"target": target}, "Shodan host intelligence lookup"),
            AgentAction("cve_search", {"target": target}, "CVE database correlation"),
            AgentAction("exploit_db", {"target": target}, "Exploit database lookup"),
        ]
        if step >= len(steps):
            return None
        action = steps[step]
        self._action_history.append({"tool": action.tool_name, "input": action.tool_input, "reasoning": action.reasoning})
        return action
```

- [ ] **Step 4: Run tests**

```bash
cd C:/Projects/Optimus && python -m pytest backend/tests/test_intel_agent_enrich.py -v
```

Expected: All 3 tests PASS

- [ ] **Step 5: Commit**

```bash
git add backend/agents/intel_agent.py backend/tests/test_intel_agent_enrich.py
git commit -m "feat: add StrategyEvolutionEngine hook to IntelAgent post-run enrichment"
```

---

### Task 8: EngineInfra — pass strategy_engine to IntelAgent

**Files:**
- Modify: `backend/engines/engine_infra.py`

- [ ] **Step 1: Add strategy_engine field to EngineInfra.__init__**

In `backend/engines/engine_infra.py`, find `class EngineInfra` (line ~128).

Change `__init__`:
```python
def __init__(
    self,
    tool_executor: Any = None,
    event_bus: Any = None,
    xai_logger: Any = None,
    kali_mgr: Any = None,
    llm_router: Any = None,
    strategy_engine: Any = None,
) -> None:
    self._tool_executor = tool_executor
    self._event_bus = event_bus
    self._xai_logger = xai_logger
    self._kali_mgr = kali_mgr
    self._llm_router = llm_router
    self._strategy_engine = strategy_engine
```

- [ ] **Step 2: Inject strategy_engine into IntelAgent in dispatch()**

In `dispatch()`, after the agent is created (around line 192):
```python
agent = agent_cls(
    agent_id=f"{agent_class_name}-{task.task_id[:8]}",
    agent_type=_agent_type,
    engine=task.engine_type,
    scope=task.scope,
    tool_executor=self._tool_executor,
    event_bus=self._event_bus,
    kali_mgr=self._kali_mgr,
    llm_router=self._llm_router,
)
```

Add after this block (before `if self._xai_logger:`):
```python
            # Inject strategy_engine into IntelAgent
            if agent_class_name == "intel" and self._strategy_engine:
                agent.strategy_engine = self._strategy_engine
```

- [ ] **Step 3: Verify import compiles**

```bash
cd C:/Projects/Optimus && python -c "from backend.engines.engine_infra import EngineInfra; print('EngineInfra OK')"
```

Expected: `EngineInfra OK`

- [ ] **Step 4: Run existing E2E test for regression**

```bash
cd C:/Projects/Optimus && python -m pytest backend/tests/test_pentest_e2e.py -v
```

Expected: Pass (or same results as before this change)

- [ ] **Step 5: Commit**

```bash
git add backend/engines/engine_infra.py
git commit -m "feat: pass StrategyEvolutionEngine to IntelAgent via EngineInfra dispatch"
```

---

### Task 9: main.py — wire all adapters and dependencies

**Files:**
- Modify: `backend/main.py`

- [ ] **Step 1: Add imports for source adapters**

In `backend/main.py`, find the M3 imports block (after line ~55). Add after the existing M3 imports:

```python
from backend.intelligence.source_adapters import (
    NVDAdapter,
    CISAKEVAdapter,
    GitHubPoCAdapter,
    MITREAttackAdapter,
    BlogsAdapter,
    ExploitDBAdapter,
    DarkWebAdapter,
)
```

- [ ] **Step 2: Register TorSOCKS5Backend as named backend**

In the lifespan function, find where `TorSOCKS5Backend` is registered:
```python
tool_executor.register_backend("tor_socks5", TorSOCKS5Backend())
```

Change to store a reference:
```python
tor_backend = TorSOCKS5Backend(
    tor_host=os.environ.get("TOR_SOCKS5_HOST", "tor"),
    tor_port=int(os.environ.get("TOR_SOCKS5_PORT", "9050")),
)
tool_executor.register_backend("tor_socks5", tor_backend)
_state["tor_backend"] = tor_backend
```

- [ ] **Step 3: Register all 7 source adapters with ResearchDaemon**

Find the block after `ResearchDaemon` is constructed:
```python
research_daemon = ResearchDaemon(
    research_kb=research_kb,
    event_bus=event_bus,
)
_state["research_daemon"] = research_daemon
```

Replace with:
```python
research_daemon = ResearchDaemon(
    research_kb=research_kb,
    event_bus=event_bus,
)

# Register source adapters
research_daemon.register_source("nvd",        NVDAdapter().fetch)
research_daemon.register_source("cisa_kev",   CISAKEVAdapter().fetch)
research_daemon.register_source("github_poc", GitHubPoCAdapter().fetch)
research_daemon.register_source("attack",     MITREAttackAdapter().fetch)
research_daemon.register_source("blogs",      BlogsAdapter().fetch)
research_daemon.register_source("exploitdb",  ExploitDBAdapter().fetch)
research_daemon.register_source("dark_web",   DarkWebAdapter(tor_backend=tor_backend).fetch)

_state["research_daemon"] = research_daemon
logger.info("ResearchDaemon: registered 7 source adapters")
```

- [ ] **Step 4: Pass research_kb to OmX**

Find:
```python
omx = OmX(llm_router=llm_router)
```

Change to:
```python
omx = OmX(llm_router=llm_router, research_kb=research_kb)
```

- [ ] **Step 5: Pass strategy_engine to EngineInfra**

Find:
```python
engine_infra = EngineInfra(
    tool_executor=tool_executor,
    event_bus=event_bus,
    xai_logger=xai_logger,
    kali_mgr=kali_mgr,
)
```

Change to:
```python
engine_infra = EngineInfra(
    tool_executor=tool_executor,
    event_bus=event_bus,
    xai_logger=xai_logger,
    kali_mgr=kali_mgr,
)
```

Note: `strategy_engine` is created AFTER `engine_infra` in the current startup order. After `strategy_engine` is created, add:
```python
engine_infra._strategy_engine = strategy_engine
```

Find where `strategy_engine` is built:
```python
strategy_engine = StrategyEvolutionEngine(
    research_kb=research_kb,
    smart_memory=smart_memory,
)
_state["strategy_engine"] = strategy_engine
```

Add after it:
```python
# Inject strategy_engine into EngineInfra (created before StrategyEvolutionEngine was ready)
engine_infra._strategy_engine = strategy_engine
```

- [ ] **Step 6: Verify backend starts without import errors**

```bash
cd C:/Projects/Optimus && python -c "
import asyncio
from backend.main import app
print('main.py imports OK')
"
```

Expected: `main.py imports OK`

- [ ] **Step 7: Commit**

```bash
git add backend/main.py
git commit -m "feat: wire all 7 source adapters, ResearchKB→OmX, StrategyEngine→EngineInfra in main.py"
```

---

### Task 10: Frontend fix — Vite proxy + relative REST URLs

**Files:**
- Modify: `frontend/vite.config.js`
- Modify: `frontend/src/App.jsx`

- [ ] **Step 1: Fix vite.config.js proxy targets**

Replace entire `frontend/vite.config.js`:

```javascript
import { defineConfig } from 'vite'
import react from '@vitejs/plugin-react'

export default defineConfig({
  plugins: [react()],
  server: {
    host: '0.0.0.0',
    port: 3000,
    proxy: {
      '/health': { target: 'http://backend:8000', changeOrigin: true },
      '/directives': { target: 'http://backend:8000', changeOrigin: true },
      '/scope': { target: 'http://backend:8000', changeOrigin: true },
      '/gate': { target: 'http://backend:8000', changeOrigin: true },
      '/report': { target: 'http://backend:8000', changeOrigin: true },
      '/terminal': { target: 'http://backend:8000', changeOrigin: true },
      '/ws': {
        target: 'ws://backend:8000',
        ws: true,
        changeOrigin: true,
      },
      '/chat': {
        target: 'ws://backend:8000',
        ws: true,
        changeOrigin: true,
      },
    },
  },
})
```

- [ ] **Step 2: Fix App.jsx — switch REST to relative paths, fix WebSocket URL**

In `frontend/src/App.jsx`, find lines 9-11:
```javascript
// ─── Constants ────────────────────────────────────────────────────────────────
const API_BASE = import.meta.env.VITE_API_URL || 'http://localhost:8000'
const WS_BASE  = API_BASE.replace(/^http/, 'ws')
```

Replace with:
```javascript
// ─── Constants ────────────────────────────────────────────────────────────────
// REST calls use relative paths — proxied by Vite to backend:8000
// WebSocket uses window.location.host so it works on any deployment
const WS_BASE = `ws://${window.location.host}`
```

Then find every occurrence of `${API_BASE}/` in fetch calls and replace with `/`:

Search for these patterns and replace:
- `fetch(\`${API_BASE}/health\`)` → `fetch('/health')`
- `fetch(\`${API_BASE}/directives\`)` → `fetch('/directives')`
- `fetch(\`${API_BASE}/scope\`, ` → `fetch('/scope', `
- `fetch(\`${API_BASE}/gate/` → `fetch(\`/gate/`
- `fetch(\`${API_BASE}/terminal/exec\`` → `fetch('/terminal/exec',`
- `fetch(\`${API_BASE}/report/` → `fetch(\`/report/`

And for WebSocket URLs, `WS_BASE` is already used correctly — just verify `useWebSocket` hook uses `WS_BASE` properly.

Find in App.jsx where WebSocket URLs are constructed. They should use `WS_BASE`:
- `/ws` events socket: `${WS_BASE}/ws`
- `/chat` chat socket: `${WS_BASE}/chat`
- `/ws/terminal` terminal socket: `${WS_BASE}/ws/terminal`

These should already use `WS_BASE` — just verify they aren't using `API_BASE`.

- [ ] **Step 3: Verify App.jsx has no remaining API_BASE references in fetch calls**

```bash
grep -n "API_BASE" C:/Projects/Optimus/frontend/src/App.jsx
```

Expected: No lines containing `API_BASE` (it's removed — only `WS_BASE` remains)

- [ ] **Step 4: Check for any remaining hardcoded localhost:8000**

```bash
grep -n "localhost:8000" C:/Projects/Optimus/frontend/src/App.jsx
grep -n "localhost:8000" C:/Projects/Optimus/frontend/vite.config.js
```

Expected: No matches

- [ ] **Step 5: Commit**

```bash
git add frontend/vite.config.js frontend/src/App.jsx
git commit -m "fix: switch frontend REST to relative paths, fix Vite proxy to use backend:8000 Docker service name"
```

---

### Task 11: Full regression test run

**Files:** (no changes — verification only)

- [ ] **Step 1: Run all unit tests**

```bash
cd C:/Projects/Optimus && python -m pytest backend/tests/ -v --tb=short 2>&1 | tail -40
```

Expected: All previously passing tests still pass. New tests (source adapters, tor, omx_enrichment, intel_agent_enrich, kali builders) pass.

- [ ] **Step 2: Verify import chain from main.py**

```bash
cd C:/Projects/Optimus && python -c "
from backend.intelligence.source_adapters import NVDAdapter, CISAKEVAdapter, GitHubPoCAdapter, MITREAttackAdapter, BlogsAdapter, ExploitDBAdapter, DarkWebAdapter
from backend.tools.backends.tor_socks5 import TorSOCKS5Backend, TorUnavailableError
from backend.core.omx import OmX
from backend.agents.intel_agent import IntelAgent
from backend.engines.engine_infra import EngineInfra
print('All imports OK')
"
```

Expected: `All imports OK`

- [ ] **Step 3: Commit final state if any stray changes**

```bash
cd C:/Projects/Optimus && git status
```

If clean: done. If not:
```bash
git add -A && git commit -m "fix: cleanup stray changes from integration"
```

---

## Self-Review Checklist

**Spec coverage:**
- [x] NVDAdapter — Task 3
- [x] CISAKEVAdapter — Task 3
- [x] GitHubPoCAdapter — Task 3
- [x] MITREAttackAdapter — Task 3
- [x] BlogsAdapter — Task 3
- [x] ExploitDBAdapter — Task 3
- [x] DarkWebAdapter — Task 3
- [x] TorSOCKS5Backend (socks5h, no DNS leak, body cap, redirect guard, truncate) — Task 2
- [x] cve_search KaliSSH builder — Task 4
- [x] exploit_db KaliSSH builder — Task 4
- [x] OmX pre-engagement KB enrichment — Task 5
- [x] OmO research_context → agent prompts — Task 6
- [x] IntelAgent strategy_engine hook — Task 7
- [x] EngineInfra passes strategy_engine to IntelAgent — Task 8
- [x] main.py adapter registration — Task 9
- [x] Frontend vite.config.js Docker proxy fix — Task 10
- [x] Frontend App.jsx relative REST URLs — Task 10
- [x] socksio dependency — Task 1

**Type consistency:**
- `TorSOCKS5Backend.query(query_str: str) -> str` — used in DarkWebAdapter Task 3 ✓
- `TorUnavailableError` defined in tor_socks5.py, imported in source_adapters.py ✓
- `IntelAgent.strategy_engine: Any = None` — set as dataclass field ✓
- `EngineInfra._strategy_engine` — set in __init__ and injected in dispatch ✓
- `OmX._research_kb` — set in __init__ ✓
- `ResearchKBEntry` constructor — all adapter Tasks use same field names as defined in research_kb.py ✓
