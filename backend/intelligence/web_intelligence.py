import logging
import os
import aiohttp
from typing import Dict, Any, List, Optional

logger = logging.getLogger(__name__)

CACHE_DIR = os.getenv("INTEL_CACHE_PATH", "/app/data/intel_cache")


class WebIntelligence:
    async def scrape(self, url: str) -> Dict[str, Any]:
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=aiohttp.ClientTimeout(total=10)) as resp:
                    if resp.status == 200:
                        return {
                            "url": url,
                            "status": resp.status,
                            "content": await resp.text(),
                        }
        except Exception as e:
            logger.warning(f"Web scrape failed: {e}")
        
        return {"url": url, "status": "error", "content": None}


class AdaptiveExploitation:
    def __init__(self):
        self.strategies = ["default", "aggressive", "stealth", "test"]

    def select_strategy(self, stealth_level: str) -> str:
        if stealth_level == "high":
            return "stealth"
        elif stealth_level == "low":
            return "aggressive"
        return "default"

    def get_parameters(self, strategy: str) -> Dict[str, Any]:
        params = {
            "default": {"retries": 3, "delay": 1},
            "aggressive": {"retries": 1, "delay": 0},
            "stealth": {"retries": 5, "delay": 10},
            "test": {"retries": 1, "delay": 0},
        }
        return params.get(strategy, params["default"])


class CampaignIntelligence:
    def __init__(self):
        self.campaigns: Dict[str, List[str]] = {}

    def add_finding(self, campaign_id: str, finding: str):
        if campaign_id not in self.campaigns:
            self.campaigns[campaign_id] = []
        self.campaigns[campaign_id].append(finding)

    def get_campaign_findings(self, campaign_id: str) -> List[str]:
        return self.campaigns.get(campaign_id, [])


class ContinuousLearning:
    def __init__(self):
        self.improvements: List[Dict[str, Any]] = []

    def record_improvement(self, tool: str, technique: str, success: bool):
        self.improvements.append({
            "tool": tool,
            "technique": technique,
            "success": success,
        })

    def get_best_techniques(self, tool: str) -> List[str]:
        tool_improvements = [i for i in self.improvements if i["tool"] == tool]
        successful = [i["technique"] for i in tool_improvements if i["success"]]
        
        from collections import Counter
        return [t for t, _ in Counter(successful).most_common(5)]