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

_ALLOWED_CLEARNET_HOSTS = {"ahmia.fi"}
_AHMIA_ONION = "juhanurmihxlp77nkq76byazcldy2hlmovfu2epvl5ankdibsot4csyd.onion"
_AHMIA_CLEARNET = "https://ahmia.fi/search/"
_MAX_BODY_BYTES = 512 * 1024
_MAX_OUTPUT_CHARS = 2_000
_TIMEOUT_SECONDS = 60.0


def _strip_html(html: str) -> str:
    text = re.sub(r"<[^>]+>", " ", html)
    text = re.sub(r"&[a-z]+;", " ", text)
    text = re.sub(r"\s+", " ", text)
    return text.strip()


def _is_allowed_host(url: httpx.URL) -> bool:
    host = url.host
    if host.endswith(".onion"):
        return True
    if host in _ALLOWED_CLEARNET_HOSTS:
        return True
    return False


class TorUnavailableError(Exception):
    """Raised when the Tor proxy is unreachable."""


class TorSOCKS5Backend:
    """Tor SOCKS5H proxy backend for dark web research."""

    def __init__(self, tor_host: str = "tor", tor_port: int = 9050) -> None:
        self._proxy_url = f"socks5h://{tor_host}:{tor_port}"

    def _make_client(self) -> httpx.AsyncClient:
        return httpx.AsyncClient(
            proxies={"all://": self._proxy_url},
            timeout=_TIMEOUT_SECONDS,
            follow_redirects=False,
            verify=False,
            headers={"User-Agent": "Mozilla/5.0 (compatible; research-bot/1.0)"},
        )

    async def query(self, query_str: str) -> str:
        """Run a search query via Ahmia and return sanitized plain text."""
        params = {"q": query_str}
        try:
            async with self._make_client() as client:
                try:
                    onion_url = f"http://{_AHMIA_ONION}/search/"
                    resp = await client.get(onion_url, params=params)
                except (httpx.ConnectError, httpx.ConnectTimeout):
                    resp = await client.get(_AHMIA_CLEARNET, params=params)
        except httpx.ProxyError as exc:
            raise TorUnavailableError(f"Tor proxy unreachable: {exc}") from exc
        except httpx.TimeoutException as exc:
            raise TorUnavailableError(f"Tor query timed out: {exc}") from exc

        if not _is_allowed_host(resp.url):
            logger.warning("TorSOCKS5: redirect to disallowed host %s — rejecting", resp.url.host)
            return ""

        raw = resp.text[:_MAX_BODY_BYTES]
        text = _strip_html(raw)
        return text[:_MAX_OUTPUT_CHARS]

    async def execute(self, tool_name: str, tool_input: dict[str, Any], tool_spec: Any) -> dict[str, Any]:
        """Execute a tool via Tor proxy. Supports: dark_web_query."""
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
