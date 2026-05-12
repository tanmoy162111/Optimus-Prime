import logging
import os
from typing import Dict, Any, List
from dataclasses import dataclass, field
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)


@dataclass
class MemoryEntry:
    session_id: str
    query: str
    findings: str
    timestamp: datetime = field(default_factory=datetime.now)
    embedding: List[float] = field(default_factory=list)


class SmartMemory:
    def __init__(self, db_path: str):
        self.db_path = db_path
        self.entries: List[MemoryEntry] = []
        self._load()

    def _load(self):
        if os.path.exists(self.db_path):
            pass

    def store(self, session_id: str, query: str, findings: str):
        entry = MemoryEntry(session_id=session_id, query=query, findings=findings)
        self.entries.append(entry)
        self._save()

    def _save(self):
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)

    async def search(self, query: str, top_k: int = 5) -> List[MemoryEntry]:
        return self.entries[-top_k:]

    def get_session_memory(self, session_id: str) -> List[MemoryEntry]:
        return [e for e in self.entries if e.session_id == session_id]