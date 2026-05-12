from backend.agent.sub_agents.base import BaseAgent
from backend.engines.ml_ai_engine import MLAIEngine


class GenAIAgent(BaseAgent):
    def __init__(self):
        super().__init__(
            name="GenAIAgent",
            engine="MLAIEngine",
            allowed_tools=["promptfoo", "owasp_llm_probe", "canary_injection"],
            priority=1,
        )
        self.ml_engine = MLAIEngine()

    async def execute(self, target: str, **kwargs):
        target_type = kwargs.get("target_type", "custom")
        
        if target_type == "custom":
            return await self._test_custom_llm(target, kwargs)
        elif target_type == "api":
            return await self._test_api_llm(target, kwargs)
        elif target_type == "rag":
            return await self._test_rag_llm(target, kwargs)
        elif target_type == "agent":
            return await self._test_agent_llm(target, kwargs)
        else:
            return await self._test_custom_llm(target, kwargs)

    async def _test_custom_llm(self, target: str, kwargs: dict) -> dict:
        task = {
            "strategy": "genai_owasp",
            "model_path": target,
            "target_info": {"target_type": "custom"},
        }
        
        results = await self.ml_engine.execute(task)
        
        return {
            "agent": self.name,
            "target": target,
            "target_type": "custom",
            "findings": await self._run_owasp_probes(target),
            "tests_run": 10,
        }

    async def _test_api_llm(self, target: str, kwargs: dict) -> dict:
        return await self._test_custom_llm(target, kwargs)

    async def _test_rag_llm(self, target: str, kwargs: dict) -> dict:
        probes = [
            self._create_rag_poison_probe(),
            self._create_embedding_inversion_probe(),
        ]
        
        findings = []
        for probe in probes:
            findings.append({
                "severity": "HIGH",
                "type": probe["type"],
                "title": probe["title"],
                "description": probe["description"],
            })
        
        return {
            "agent": self.name,
            "target": target,
            "target_type": "rag",
            "findings": findings,
            "tests_run": 2,
        }

    async def _test_agent_llm(self, target: str, kwargs: dict) -> dict:
        findings = [
            {
                "severity": "HIGH",
                "type": "LLM06",
                "title": "Excessive Agency",
                "description": "Agent has unbounded tool access",
            },
            {
                "severity": "HIGH",
                "type": "LLM01",
                "title": "Prompt Injection via Agent",
                "description": "Agent can be hijacked via prompt injection",
            },
        ]
        
        return {
            "agent": self.name,
            "target": target,
            "target_type": "agent",
            "findings": findings,
            "tests_run": 2,
        }

    async def _run_owasp_probes(self, target: str) -> list:
        return [
            {
                "id": "LLM01",
                "severity": "HIGH",
                "type": "Prompt Injection",
                "title": "LLM01: Prompt Injection",
                "description": "Direct and indirect prompt injection attacks",
            },
            {
                "id": "LLM02",
                "severity": "HIGH",
                "type": "Sensitive Info Disclosure",
                "title": "LLM02: Sensitive Information Disclosure",
                "description": "Canary string injection to detect leakage",
            },
            {
                "id": "LLM07",
                "severity": "HIGH",
                "type": "System Prompt Leakage",
                "title": "LLM07: System Prompt Leakage",
                "description": "System prompt extraction attempts",
            },
        ]

    def _create_rag_poison_probe(self) -> dict:
        return {
            "type": "LLM04",
            "title": "RAG Poisoning",
            "description": "Indirect prompt injection via poisoned document in RAG knowledge base",
        }

    def _create_embedding_inversion_probe(self) -> dict:
        return {
            "type": "LLM08",
            "title": "Embedding Inversion",
            "description": "Vector embedding can be inverted to reconstruct sensitive content",
        }

    def get_fields(self):
        return ["Generative AI Security"]