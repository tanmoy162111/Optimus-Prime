from backend.agent.sub_agents.base import BaseAgent
from backend.engines.ml_ai_engine import MLAIEngine


class ModelSecAgent(BaseAgent):
    def __init__(self):
        super().__init__(
            name="ModelSecAgent",
            engine="MLAIEngine",
            allowed_tools=["art_evasion", "foolbox", "model_extraction", "membership_inference", "modelaudit"],
            priority=1,
        )
        self.ml_engine = MLAIEngine()

    async def execute(self, target: str, **kwargs):
        attack_type = kwargs.get("attack_type", "evasion")
        
        if attack_type == "evasion":
            return await self._test_evasion(target, kwargs)
        elif attack_type == "extraction":
            return await self._test_extraction(target, kwargs)
        elif attack_type == "membership":
            return await self._test_membership(target, kwargs)
        elif attack_type == "poisoning":
            return await self._test_poisoning(target, kwargs)
        else:
            return await self._test_evasion(target, kwargs)

    async def _test_evasion(self, target: str, kwargs: dict) -> dict:
        task = {
            "strategy": "evasion",
            "model_path": target,
            "target_info": {
                "attack_type": kwargs.get("attack_type", "fgsm"),
            },
        }
        
        results = await self.ml_engine.execute(task)
        
        return {
            "agent": self.name,
            "target": target,
            "attack_type": "evasion",
            "findings": results.get("findings", []),
            "robustness_score": results.get("robustness_score", 0.0),
        }

    async def _test_extraction(self, target: str, kwargs: dict) -> dict:
        task = {
            "strategy": "extraction",
            "model_path": target,
            "target_info": {},
        }
        
        results = await self.ml_engine.execute(task)
        
        return {
            "agent": self.name,
            "target": target,
            "attack_type": "extraction",
            "findings": results.get("findings", []),
            "accuracy": results.get("accuracy", 0.0),
        }

    async def _test_membership(self, target: str, kwargs: dict) -> dict:
        task = {
            "strategy": "membership",
            "model_path": target,
            "target_info": {},
        }
        
        results = await self.ml_engine.execute(task)
        
        return {
            "agent": self.name,
            "target": target,
            "attack_type": "membership",
            "findings": results.get("findings", []),
            "inference_accuracy": results.get("inference_accuracy", 0.0),
        }

    async def _test_poisoning(self, target: str, kwargs: dict) -> dict:
        task = {
            "strategy": "poisoning",
            "model_path": target,
            "target_info": {},
        }
        
        results = await self.ml_engine.execute(task)
        
        return {
            "agent": self.name,
            "target": target,
            "attack_type": "poisoning",
            "findings": results.get("findings", []),
            "backdoor_detected": results.get("backdoor_detected", False),
        }

    def get_fields(self):
        return ["Adversarial ML"]