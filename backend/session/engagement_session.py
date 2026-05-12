from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional
from uuid import uuid4


@dataclass
class ScopeConfig:
    targets: List[str] = field(default_factory=list)
    exclusions: List[str] = field(default_factory=list)
    stealth_level: str = "medium"
    ports: List[int] = field(default_factory=list)
    protocols: List[str] = field(default_factory=list)


@dataclass
class ConversationHistory:
    messages: List[Dict[str, str]] = field(default_factory=list)
    _max_window: int = field(default=40, repr=False)

    def add_message(self, role: str, content: str) -> None:
        self.messages.append({"role": role, "content": content})

    def get_context_window(self) -> List[Dict[str, str]]:
        return self.messages[-self._max_window:]


@dataclass
class EngagementState:
    phase_status: Dict[str, str] = field(default_factory=dict)
    findings: List[Dict] = field(default_factory=list)
    gate_queue: List[str] = field(default_factory=list)

    def add_finding(self, finding: Dict) -> None:
        self.findings.append(finding)

    def set_phase_status(self, phase_id: str, status: str) -> None:
        self.phase_status[phase_id] = status


@dataclass
class EngagementSession:
    session_id: str
    engagement_id: str
    scope: ScopeConfig
    conv_history: ConversationHistory
    state: EngagementState
    created_at: datetime
    last_active: datetime

    @classmethod
    def create(cls, engagement_id: Optional[str] = None) -> "EngagementSession":
        now = datetime.utcnow()
        return cls(
            session_id=str(uuid4()),
            engagement_id=engagement_id or str(uuid4()),
            scope=ScopeConfig(),
            conv_history=ConversationHistory(),
            state=EngagementState(),
            created_at=now,
            last_active=now,
        )
