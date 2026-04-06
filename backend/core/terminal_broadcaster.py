"""TerminalBroadcaster — fans out terminal events to all /ws/terminal clients.

Two public classes:
  TerminalBroadcaster  — WebSocket connection manager + event fan-out
  TerminalLogHandler   — logging.Handler that feeds records into the broadcaster
"""
from __future__ import annotations

import asyncio
import logging
from datetime import datetime, timezone
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from fastapi import WebSocket

logger = logging.getLogger(__name__)


class TerminalBroadcaster:
    """Singleton that fans out structured terminal events to all /ws/terminal clients."""

    def __init__(self) -> None:
        self._connections: list[WebSocket] = []

    async def connect(self, ws: WebSocket) -> None:
        """Accept and register a new WebSocket connection."""
        await ws.accept()
        self._connections.append(ws)

    def disconnect(self, ws: WebSocket) -> None:
        """Remove a WebSocket connection (no-op if not registered)."""
        if ws in self._connections:
            self._connections.remove(ws)

    async def publish(self, event: dict) -> None:
        """Fan out an event to all registered connections, silently dropping dead ones."""
        dead: list[WebSocket] = []
        for ws in list(self._connections):
            try:
                await ws.send_json(event)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self.disconnect(ws)


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


class TerminalLogHandler(logging.Handler):
    """Feeds Python log records into TerminalBroadcaster as backend_log events.

    Attach to the 'backend' logger in main.py startup:
        handler = TerminalLogHandler(broadcaster)
        handler.setLevel(logging.DEBUG)
        logging.getLogger("backend").addHandler(handler)
    """

    def __init__(self, broadcaster: TerminalBroadcaster) -> None:
        super().__init__()
        self._broadcaster = broadcaster

    def emit(self, record: logging.LogRecord) -> None:
        """Publish the log record as a backend_log event. Never raises."""
        try:
            event = {
                "type": "backend_log",
                "source": "backend",
                "level": record.levelname,
                "logger": record.name,
                "data": self.format(record) if self.formatter else record.getMessage(),
                "ts": _now_iso(),
            }
            try:
                loop = asyncio.get_running_loop()
                loop.create_task(self._broadcaster.publish(event))
            except RuntimeError:
                pass  # no running loop (e.g., during tests without async context)
        except Exception:
            self.handleError(record)
