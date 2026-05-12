import logging

logger = logging.getLogger(__name__)


class DarkWebIntel:
    def __init__(self):
        self.enabled = False

    async def query(self, query: str):
        if not self.enabled:
            return {"status": "disabled", "reason": "Tor unavailable"}
        
        return{"query": query, "results": []}