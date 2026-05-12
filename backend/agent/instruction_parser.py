import re
import logging
from typing import Dict, Any, Optional
from dataclasses import dataclass

from backend.agent.conversation import SessionState

logger = logging.getLogger(__name__)


class EngineRouter:
    def dispatch(self, intent: str, target: Optional[str] = None) -> str:
        ml_intents = {
            "model_security",
            "genai_security",
            "adversarial_evasion",
            "prompt_injection",
            "model_extraction",
            "membership_inference",
        }
        
        if intent.lower() in ml_intents:
            return "MLAIEngine"
        
        if target and self._is_ml_target(target):
            return "MLAIEngine"
        
        ics_patterns = ["modbus", "dnp3", "scada", "ics", "ot", "industrial"]
        if target and any(p in target.lower() for p in ics_patterns):
            return "ICSEngine"
        
        return "InfrastructureEngine"

    def _is_ml_target(self, target: str) -> bool:
        ml_extensions = [".pt", ".pth", ".h5", ".keras", ".onnx", ".pkl", ".pickle"]
        return any(target.lower().endswith(ext) for ext in ml_extensions)


class InstructionParser:
    def parse(
        self,
        message: str,
        session: SessionState,
        mode: Optional[str] = None,
    ) -> Dict[str, Any]:
        intent = self._detect_intent(message)
        target = self._extract_target(message)
        constraints = self._extract_constraints(message)
        phase = self._detect_phase(message)
        confidence = self._calculate_confidence(intent, message)
        
        return {
            "intent": intent,
            "target": target,
            "constraints": constraints,
            "phase": phase,
            "confidence": confidence,
            "mode": mode or session.mode,
        }

    def _detect_intent(self, message: str) -> str:
        message_lower = message.lower()
        
        intent_patterns = {
            "reconnaissance": [r"\brecon\b", r"\bdomain枚举\b", r"\bwhois\b", r"\bdns\b"],
            "scan": [r"\bscan\b", r"\bport scan\b", r"\bcheck\b"],
            "vulnerability_scan": [r"\bvuln\b", r"\bcve\b", r"\bvulnerability\b"],
            "exploitation": [r"\bexploit\b", r"\bsqlmap\b", r"\binjection\b", r"\bpayload\b"],
            "pentest": [r"\bpentest\b", r"\bpen test\b", r"\bfull.*assess\b"],
            "cloud_assessment": [r"\baws\b", r"\bazure\b", r"\bgcp\b", r"\bcloud\b"],
            "iam_assessment": [r"\bjwt\b", r"\boauth\b", r"\bsaml\b", r"\biam\b", r"\bauthentication\b"],
            "secrets_discovery": [r"\bsecret\b", r"\bapi key\b", r"\btoken\b", r"\bhardcoded\b"],
            "tls_assessment": [r"\btls\b", r"\bssl\b", r"\bcipher\b", r"\bcertificate\b"],
            "pii_discovery": [r"\bpii\b", r"\bpersonally\b", r"\bprivacy\b", r"\bgdpr\b"],
            "endpoint_assessment": [r"\bendpoint\b", r"\bhost\b", r"\bmachine\b", r"\bprivilege\b"],
            "model_security": [r"\badversarial\b", r"\bevasion\b", r"\bart\b", r"\bfoolbox\b"],
            "genai_security": [r"\bprompt injection\b", r"\bllm\b", r"\bchatbot\b", r"\bgenai\b"],
            "intel_gathering": [r"\bcve\b", r"\bexploitdb\b", r"\bintelligence\b"],
            "status_query": [r"\bstatus\b", r"\bprogress\b", r"\bwhat.*doing\b"],
        }
        
        for intent, patterns in intent_patterns.items():
            for pattern in patterns:
                if re.search(pattern, message_lower):
                    return intent
        
        return "general"

    def _extract_target(self, message: str) -> Optional[str]:
        url_pattern = r"(?:https?://)?(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(?:/[^\s]*)?"
        ip_pattern = r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?::[0-9]+)?\b"
        
        match = re.search(url_pattern, message)
        if match:
            return match.group(0)
        
        match = re.search(ip_pattern, message)
        if match:
            return match.group(0)
        
        domain_pattern = r"\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}\b"
        match = re.search(domain_pattern, message.split()[(-1):] if message.split() else [""])
        if match:
            return match.group(0)
        
        return None

    def _extract_constraints(self, message: str) -> Dict[str, Any]:
        constraints = {}
        
        if "stealth" in message.lower():
            if "high" in message.lower():
                constraints["stealth_level"] = "high"
            elif "low" in message.lower():
                constraints["stealth_level"] = "low"
        
        if "rate limit" in message.lower():
            match = re.search(r"(\d+)\s*per\s*minute", message.lower())
            if match:
                constraints["rate_limit"] = int(match.group(1))
        
        return constraints

    def _detect_phase(self, message: str) -> str:
        message_lower = message.lower()
        
        phase_patterns = {
            "recon": [r"\brecon\b", r"\benumeration\b", r"\bdiscover\b"],
            "scan": [r"\bscan\b", r"\bdiscover\b", r"\bprobe\b"],
            "exploit": [r"\bexploit\b", r"\battack\b", r"\binject\b"],
            "post_exploit": [r"\bpost\b", r"\bescalate\b", r"\bpersist\b"],
            "report": [r"\breport\b", r"\bexport\b", r"\bsummary\b"],
        }
        
        for phase, patterns in phase_patterns.items():
            for pattern in patterns:
                if re.search(pattern, message_lower):
                    return phase
        
        return "analysis"

    def _calculate_confidence(self, intent: str, message: str) -> float:
        if intent == "general":
            return 0.5
        if len(message.split()) < 3:
            return 0.6
        return 0.85