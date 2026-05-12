import aiohttp
import logging
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)


class SurfaceWebIntel:
    def __init__(self):
        self.sources = ["nvd", "exploitdb", "github", "shodan"]
        self.cache: Dict[str, Any] = {}

    async def query(self, query: str, source: Optional[str] = None) -> Dict[str, Any]:
        if query in self.cache:
            return self.cache[query]
        
        results = {}
        
        if not source or source == "nvd":
            results["nvd"] = await self._query_nvd(query)
        
        if not source or source == "exploitdb":
            results["exploitdb"] = await self._query_exploitdb(query)
        
        self.cache[query] = results
        return results

    async def _query_nvd(self, query: str) -> Dict[str, Any]:
        try:
            async with aiohttp.ClientSession() as session:
                url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?keywordSearch={query}"
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    if resp.status == 200:
                        return await resp.json()
        except Exception as e:
            logger.warning(f"NVD query failed: {e}")
        return {}

    async def _query_exploitdb(self, query: str) -> Dict[str, Any]:
        return {"query": query, "status": "not_implemented"}


class DarkWebIntel:
    def __init__(self):
        self.enabled = False
        from backend import config
        try:
            import socket
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(2)
            s.connect((config.settings.tor_socks_host, config.settings.tor_socks_port))
            s.close()
            self.enabled = True
        except Exception:
            logger.warning("Tor unavailable - dark web intel disabled")

    async def query(self, query: str) -> Dict[str, Any]:
        if not self.enabled:
            return {"status": "disabled", "reason": "Tor unavailable"}
        
        return {"status": "not_implemented", "query": query}