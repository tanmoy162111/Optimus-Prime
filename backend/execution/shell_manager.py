from typing import Optional, List
import logging

from backend.execution.ssh_client import SSHClient

logger = logging.getLogger(__name__)


class ShellManager:
    def __init__(self, ssh_client: SSHClient, engagement_id: str):
        self.ssh = ssh_client
        self.engagement_id = engagement_id
        self._workdir = f"/engagements/{engagement_id}"
        self.active_sessions: dict = {}

    async def execute(self, command: str, timeout: int = 60) -> str:
        # SEC-02: scope every command to this engagement's Kali working
        # directory. mkdir -p runs on every call (idempotent) since
        # SSHClient.connect() is lazy and there is no reliable one-time
        # session-start hook to create the dir once (see 02-RESEARCH.md
        # Pattern 2).
        scoped = f'mkdir -p "{self._workdir}" && cd "{self._workdir}" && {command}'
        logger.info(f"Executing: {scoped}")
        output = await self.ssh.execute(scoped)
        return output

    # NOTE (SEC-02 / T-02-07): create_session()/send_to_session() below call
    # self.ssh.execute(...) DIRECTLY, bypassing the engagement-scoped
    # execute() above. They are intentionally left UNSCOPED dead-code (no
    # live callers today) — out of scope for SEC-02. Any future caller MUST
    # route through execute() or add its own /engagements/{engagement_id}/
    # scoping before relying on these methods for isolation.
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