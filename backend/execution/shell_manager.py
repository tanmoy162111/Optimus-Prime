from typing import Optional, List
import logging

from backend.execution.ssh_client import SSHClient

logger = logging.getLogger(__name__)


class ShellManager:
    def __init__(self, ssh_client: SSHClient):
        self.ssh = ssh_client
        self.active_sessions: dict = {}

    async def execute(self, command: str, timeout: int = 60) -> str:
        logger.info(f"Executing: {command}")
        output = await self.ssh.execute(command)
        return output

    async def create_session(self, session_id: str, target: str) -> str:
        session_shell = await self.ssh.execute(f"bash -c 'sleep 999999' &")
        self.active_sessions[session_id] = session_shell
        return session_id

    async def send_to_session(self, session_id: str, command: str) -> str:
        if session_id in self.active_sessions:
            return await self.ssh.execute(f'echo "{command}" | {self.active_sessions[session_id]}')
        return ""

    async def close_session(self, session_id: str):
        self.active_sessions.pop(session_id, None)