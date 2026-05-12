import json
import logging
import os
import time
from pathlib import Path
from typing import Dict, Any

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

MODELS_INPUT = os.getenv("MODELS_INPUT", "/models")
ML_RESULTS = os.getenv("ML_RESULTS", "/results")


def load_probe_strategy(strategy_name: str):
    if strategy_name == "evasion":
        from ml_runtime.probe_strategies.evasion_strategy import EvasionStrategy
        return EvasionStrategy()
    elif strategy_name == "extraction":
        from ml_runtime.probe_strategies.extraction_strategy import ExtractionStrategy
        return ExtractionStrategy()
    elif strategy_name == "membership":
        from ml_runtime.probe_strategies.membership_strategy import MembershipStrategy
        return MembershipStrategy()
    elif strategy_name == "poisoning":
        from ml_runtime.probe_strategies.poisoning_strategy import PoisoningStrategy
        return PoisoningStrategy()
    elif strategy_name == "genai_owasp":
        from ml_runtime.probe_strategies.genai_owasp_strategy import GenAIOWASPStrategy
        return GenAIOWASPStrategy()
    else:
        raise ValueError(f"Unknown strategy: {strategy_name}")


def main():
    models_dir = Path(MODELS_INPUT)
    results_dir = Path(ML_RESULTS)
    
    results_dir.mkdir(parents=True, exist_ok=True)
    
    logger.info(f"ML Runtime started. Watching {models_dir}")
    
    while True:
        task_files = list(models_dir.glob("task_*.json"))
        
        for task_file in task_files:
            try:
                logger.info(f"Processing task: {task_file.name}")
                
                with open(task_file, "r") as f:
                    task = json.load(f)
                
                task_id = task.get("task_id", "unknown")
                strategy_name = task.get("strategy", "evasion")
                model_path = task.get("model_path")
                target_info = task.get("target_info", {})
                
                strategy = load_probe_strategy(strategy_name)
                
                results = strategy.execute(model_path, target_info)
                
                result_file = results_dir / f"findings_{task_id}.json"
                with open(result_file, "w") as f:
                    json.dump(results, f, indent=2)
                
                task_file.unlink()
                
                logger.info(f"Task {task_id} completed")
            
            except Exception as e:
                logger.error(f"Task failed: {e}")
        
        time.sleep(2)


if __name__ == "__main__":
    main()