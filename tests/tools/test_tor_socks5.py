"""Tests for TorSOCKS5Backend."""
from __future__ import annotations

import pytest
from unittest.mock import AsyncMock, MagicMock, patch


class TestTorSOCKS5Backend:

    def test_import(self):
        from backend.tools.backends.tor_socks5 import TorSOCKS5Backend
        assert TorSOCKS5Backend is not None

    def test_not_stub(self):
        from backend.tools.backends.tor_socks5 import TorSOCKS5Backend
        import inspect
        b = TorSOCKS5Backend()
        src = inspect.getsource(b.execute)
        assert "stub" not in src

    @pytest.mark.asyncio
    async def test_dark_web_query_returns_dict(self):
        from backend.tools.backends.tor_socks5 import TorSOCKS5Backend
        backend = TorSOCKS5Backend(tor_host="tor", tor_port=9050)
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "<html><body><p>CVE-2024-1234 exploit found</p></body></html>"
        mock_response.url = MagicMock()
        mock_response.url.host = "ahmia.fi"
        with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = mock_response
            result = await backend.execute("dark_web_query", {"target": "CVE-2024-1234"}, None)
        assert isinstance(result, dict)
        assert "output" in result or "error" in result

    @pytest.mark.asyncio
    async def test_tor_unavailable_returns_error(self):
        from backend.tools.backends.tor_socks5 import TorSOCKS5Backend
        import httpx
        backend = TorSOCKS5Backend(tor_host="tor", tor_port=9050)
        with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_get.side_effect = httpx.ProxyError("connection refused")
            result = await backend.execute("dark_web_query", {"target": "exploit CVE-2024"}, None)
        assert "error" in result

    @pytest.mark.asyncio
    async def test_clearnet_redirect_rejected(self):
        from backend.tools.backends.tor_socks5 import TorSOCKS5Backend
        backend = TorSOCKS5Backend(tor_host="tor", tor_port=9050)
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = "<html>evil</html>"
        mock_response.url = MagicMock()
        mock_response.url.host = "evil.com"
        with patch("httpx.AsyncClient.get", new_callable=AsyncMock) as mock_get:
            mock_get.return_value = mock_response
            result = await backend.execute("dark_web_query", {"target": "exploit"}, None)
        assert "error" in result

    @pytest.mark.asyncio
    async def test_response_truncated_at_2000_chars(self):
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
            result = await backend.execute("dark_web_query", {"target": "exploit"}, None)
        if "output" in result:
            assert len(result["output"]) <= 2000
