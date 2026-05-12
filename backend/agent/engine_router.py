class EngineRouter:
    def dispatch(self, intent: str, target: str = None) -> str:
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