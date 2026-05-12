import os
import re
import json
import logging
from typing import Dict, Any, List, Optional

logger = logging.getLogger(__name__)


class SelfLearningParser:
    TOOL_PATTERNS = {
        "nmap": r"(?P<port>\d+)/(?P<proto>\w+)\s+(?P<state>\w+)\s+(?P<service>\w+)",
        "nikto": r"\+(?P<finding>[^\n]+)",
        "nuclei": r"\[(?P<severity>\w+)\]\[(?P<template>[^\]]+)\]",
        "sqlmap": r"Type: (?P<type>\w+), Title: (?P<title>[^\n]+)",
    }

    def __init__(self):
        self.learned_patterns: Dict[str, List[str]] = {}

    def parse(self, tool: str, output: str) -> List[Dict[str, Any]]:
        pattern = self.TOOL_PATTERNS.get(tool)
        if not pattern:
            return [{"raw": output[:200]}]
        
        matches = []
        for match in re.finditer(pattern, output, re.IGNORECASE):
            parsed = match.groupdict()
            
            if "severity" in parsed:
                parsed["severity"] = self._normalize_severity(parsed.get("severity", ""))
            
            matches.append(parsed)
        
        return matches

    def learn(self, tool: str, output: str, results: List[Dict[str, Any]]):
        if tool not in self.learned_patterns:
            self.learned_patterns[tool] = []
        
        self.learned_patterns[tool].append(output[:100])

    def _normalize_severity(self, severity: str) -> str:
        severity_upper = severity.upper()
        
        critical = ["CRITICAL", "CRT", "C"]
        high = ["HIGH", "H", "3"]
        medium = ["MEDIUM", "MED", "M", "2"]
        low = ["LOW", "L", "1", "INFO", "INFORMATIONAL", "I"]
        
        if severity_upper in critical:
            return "CRITICAL"
        elif severity_upper in high:
            return "HIGH"
        elif severity_upper in medium:
            return "MEDIUM"
        elif severity_upper in low:
            return "LOW"
        
        return "INFO"


class PhaseController:
    PHASES = ["recon", "scan", "exploit", "post_exploit", "report"]

    def __init__(self):
        self.current_phase = 0

    def next(self) -> str:
        if self.current_phase < len(self.PHASES) - 1:
            self.current_phase += 1
        return self.current_phase

    def current(self) -> str:
        return self.PHASES[self.current_phase]

    def reset(self):
        self.current_phase = 0

    def can_transition(self, from_phase: str, to_phase: str) -> bool:
        try:
            from_idx = self.PHASES.index(from_phase)
            to_idx = self.PHASES.index(to_phase)
            return to_idx <= from_idx + 1
        except ValueError:
            return False