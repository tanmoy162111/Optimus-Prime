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
                    "type": "malware",
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
