from dataclasses import dataclass
from typing import Optional

from backend.config import settings


@dataclass
class TokenBudgetManager:
    initial: int
    used: int = 0
    warning_threshold: float = 0.8

    @property
    def remaining(self) -> int:
        return self.initial - self.used

    @property
    def fraction_used(self) -> float:
        return self.used / self.initial

    @property
    def is_mistral_only(self) -> bool:
        return self.fraction_used >= 1.0

    @property
    def is_warning(self) -> bool:
        return self.fraction_used >= self.warning_threshold

    def use(self, tokens: int):
        self.used += tokens

    def reset(self):
        self.used = 0