import logging
import json
from typing import Dict, Any, List
from datetime import datetime

logger = logging.getLogger(__name__)


class ExplainableAI:
    def __init__(self):
        self.audit_log: List[Dict[str, Any]] = []

    def log_decision(
        self,
        decision_type: str,
        reasoning: str,
        confidence: float,
        factors: List[str],
    ):
        entry = {
            "timestamp": datetime.now().isoformat(),
            "decision_type": decision_type,
            "reasoning": reasoning,
            "confidence": confidence,
            "factors": factors,
        }
        self.audit_log.append(entry)
        logger.info(f"XAI: {decision_type} - {reasoning}")

    def get_decision(self, decision_type: str = None) -> List[Dict[str, Any]]:
        if decision_type:
            return [e for e in self.audit_log if e.get("decision_type") == decision_type]
        return self.audit_log

    def explain(self, decision_type: str) -> str:
        decisions = self.get_decision(decision_type)
        if not decisions:
            return "No decision found."
        
        latest = decisions[-1]
        return f"{latest['decision_type']}: {latest['reasoning']} (confidence: {latest['confidence']})"


class ExploitChainer:
    def __init__(self):
        self.graph: Dict[str, List[str]] = {}

    def add_finding(self, source: str, target: str):
        if source not in self.graph:
            self.graph[source] = []
        self.graph[source].append(target)

    def get_paths(self) -> List[List[str]]:
        paths = []
        for source, targets in self.graph.items():
            for target in targets:
                paths.append([source, target])
        return paths

    def highest_impact_path(self) -> List[str]:
        paths = self.get_paths()
        if not paths:
            return []
        return max(paths, key=len)