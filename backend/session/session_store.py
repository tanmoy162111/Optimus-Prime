from datetime import datetime
from typing import Dict, Optional

from backend.session.engagement_session import EngagementSession


class SessionStore:
    def __init__(self) -> None:
        self._sessions: Dict[str, EngagementSession] = {}

    def create(self, engagement_id: Optional[str] = None) -> EngagementSession:
        session = EngagementSession.create(engagement_id=engagement_id)
        self._sessions[session.session_id] = session
        return session

    def resolve(self, session_id: str) -> Optional[EngagementSession]:
        return self._sessions.get(session_id)

    def touch(self, session_id: str) -> None:
        session = self._sessions.get(session_id)
        if session:
            session.last_active = datetime.utcnow()


session_store = SessionStore()
