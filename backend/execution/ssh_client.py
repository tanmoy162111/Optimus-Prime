import asyncio
import paramiko
import logging
from typing import Optional
from backend import config

logger = logging.getLogger(__name__)


class SSHClient:
    def __init__(self, engagement_id: Optional[str] = None):
        self.client: Optional[paramiko.SSHClient] = None
        self.engagement_id = engagement_id

    async def connect(self) -> paramiko.SSHClient:
        if self.client is None:
            self.client = paramiko.SSHClient()
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            
            await asyncio.to_thread(
                self.client.connect,
                hostname=config.settings.kali_host,
                port=config.settings.kali_port,
                username=config.settings.kali_user,
                password=config.settings.kali_password,
            )

        return self.client

    async def execute(self, command: str) -> str:
        client = await self.connect()

        stdin, stdout, stderr = await asyncio.to_thread(client.exec_command, command)
        
        output = stdout.read().decode()
        error = stderr.read().decode()
        
        if error:
            logger.warning(f"SSH command error: {error}")
        
        return output

    async def close(self):
        if self.client:
            self.client.close()
            self.client = None