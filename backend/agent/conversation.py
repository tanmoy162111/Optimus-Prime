import uuid
from dataclasses import dataclass, field
from datetime import datetime
from typing import List, Optional
import json


@dataclass
class SessionState:
    session_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    created_at: datetime = field(default_factory=datetime.now)
    last_active: datetime = field(default_factory=datetime.now)
    mode: str = "InfrastructureEngine"
    target: Optional[str] = None
    constraints: dict = field(default_factory=dict)
    stealth_level: str = "medium"
    token_budget_initial: int = 500000
    token_budget_used: int = 0
    _frozen: bool = False

    def __post_init__(self):
        object.__setattr__(self, "_frozen", False)

    def __setattr__(self, name, value):
        if getattr(self, "_frozen", False):
            raise FrozenInstanceError(f"SessionState is frozen - cannot modify {name}")
        super().__setattr__(name, value)

    def to_dict(self):
        return {
            "session_id": self.session_id,
            "created_at": self.created_at.isoformat(),
            "last_active": self.last_active.isoformat(),
            "mode": self.mode,
            "target": self.target,
            "constraints": self.constraints,
            "stealth_level": self.stealth_level,
            "token_budget_used": self.token_budget_used,
            "token_budget_remaining": self.token_budget_initial - self.token_budget_used,
        }


@dataclass
class ChatMessage:
    role: str
    content: str
    timestamp: datetime = field(default_factory=datetime.now)


@dataclass
class Finding:
    severity: str
    title: str
    description: str
    evidence: str
    cve: Optional[str] = None
    tool: Optional[str] = None


class ConversationManager:
    def __init__(self):
        self.sessions: dict = {}

    def get_or_create_session(self, session_id: Optional[str] = None) -> SessionState:
        if session_id and session_id in self.sessions:
            session = self.sessions[session_id]
            session.last_active = datetime.now()
            return session
        
        session = SessionState(session_id=session_id)
        self.sessions[session.session_id] = session
        return session

    def get_session(self, session_id: str) -> Optional[SessionState]:
        return self.sessions.get(session_id)

    def end_session(self, session_id: str):
        self.sessions.pop(session_id, None)


class FrozenInstanceError(Exception):
    pass