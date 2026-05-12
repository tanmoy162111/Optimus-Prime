from typing import Dict, List, Optional


class ToolSelector:
    TOOL_MAP = {
        "reconnaissance": [
            "sublist3r", "amass", "theHarvester", "dnsenum", "whatweb"
        ],
        "scan": [
            "nmap", "masscan", "nikto", "nuclei", "wpscan"
        ],
        "exploitation": [
            "sqlmap", "dalfox", "commix", "ffuf", "msfconsole", "payload_crafter"
        ],
        "cloud_assessment": [
            "scoutsuite", "prowler", "pacu", "aws-cli", "az-cli", "gcloud"
        ],
        "iam_assessment": [
            "jwt-tool", "oauthscan", "saml-raider", "modlishka", "o365spray"
        ],
        "secrets_discovery": [
            "trufflehog", "gitleaks"
        ],
        "tls_assessment": [
            "testssl.sh"
        ],
        "pii_discovery": [
            "pii_parser"
        ],
        "endpoint_assessment": [
            "msfconsole", "sharpedrchecker", "lotl_crafter", "av_bypass"
        ],
        "model_security": [
            "art_evasion", "foolbox", "model_extraction", "membership_inference"
        ],
        "genai_security": [
            "promptfoo", "owasp_llm_probe"
        ],
    }

    def select(self, intent: str, engine: str) -> List[str]:
        if engine == "MLAIEngine":
            if intent == "model_security":
                return ["art_evasion", "foolbox"]
            return ["promptfoo"]
        
        if engine == "ICSEngine":
            return []
        
        return self.TOOL_MAP.get(intent, [])

    def get_allowed_tools(self, sub_agent: str) -> List[str]:
        return self.TOOL_MAP.get(sub_agent, [])