"""KaliConnectionManager — SSH connection pool with resilience (N5, Section 6.3).

Wraps paramiko with:
  - Connection pool (size 3) via asyncio.Semaphore
  - Health check before dispatch: transport.send_ignore()
  - Reconnect with exponential backoff (2s base, 30s max, 5 attempts)
  - KALI_UNREACHABLE event published on total failure

The KaliSSHHandler is stateless — pool is dependency-injected.
"""

from __future__ import annotations

import asyncio
import logging
import time
from typing import Any

import paramiko

logger = logging.getLogger(__name__)

# Pool configuration
POOL_SIZE = 3
MAX_RECONNECT_ATTEMPTS = 5
RECONNECT_BASE_DELAY = 2.0
RECONNECT_MAX_DELAY = 30.0
COMMAND_TIMEOUT = 300  # default per-command timeout


class KaliConnection:
    """A single SSH connection in the pool."""

    def __init__(self, host: str, port: int, username: str, password: str) -> None:
        self._host = host
        self._port = port
        self._username = username
        self._password = password
        self._client: paramiko.SSHClient | None = None
        self._connected = False

    @property
    def connected(self) -> bool:
        return self._connected

    def connect(self) -> None:
        """Establish SSH connection."""
        client = paramiko.SSHClient()
        client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        client.connect(
            hostname=self._host,
            port=self._port,
            username=self._username,
            password=self._password,
            timeout=10,
            allow_agent=False,
            look_for_keys=False,
        )
        self._client = client
        self._connected = True
        logger.info("KaliConnection: connected to %s:%d", self._host, self._port)

    def health_check(self) -> bool:
        """Send ignore packet to verify connection is alive."""
        if not self._client or not self._connected:
            return False
        try:
            transport = self._client.get_transport()
            if transport is None or not transport.is_active():
                return False
            transport.send_ignore()
            return True
        except Exception:
            self._connected = False
            return False

    def exec_command(self, command: str, timeout: int = COMMAND_TIMEOUT) -> tuple[str, str, int]:
        """Execute a command and return (stdout, stderr, exit_code)."""
        if not self._client:
            raise ConnectionError("Not connected to Kali")

        stdin, stdout, stderr = self._client.exec_command(command, timeout=timeout)
        exit_code = stdout.channel.recv_exit_status()
        out = stdout.read().decode("utf-8", errors="replace")
        err = stderr.read().decode("utf-8", errors="replace")
        return out, err, exit_code

    def close(self) -> None:
        """Close the SSH connection."""
        if self._client:
            try:
                self._client.close()
            except Exception:
                pass
        self._connected = False


class KaliConnectionManager:
    """Connection lifecycle manager for KaliSSH backend (v2.0 N5).

    Manages a pool of SSH connections to the Kali container with:
      - Pool of `pool_size` connections (default 3)
      - asyncio.Semaphore governs concurrent access
      - Health check before every dispatch
      - Exponential backoff reconnect on failure
      - KALI_UNREACHABLE event on total pool failure
    """

    def __init__(
        self,
        host: str = "kali",
        port: int = 22,
        username: str = "root",
        password: str = "optimus",
        pool_size: int = POOL_SIZE,
        event_bus: Any = None,
    ) -> None:
        self._host = host
        self._port = port
        self._username = username
        self._password = password
        self._pool_size = pool_size
        self._semaphore = asyncio.Semaphore(pool_size)
        self._pool: list[KaliConnection] = []
        self._event_bus = event_bus
        self._pool_lock = asyncio.Lock()

    async def connect(self) -> None:
        """Establish the connection pool."""
        async with self._pool_lock:
            for i in range(self._pool_size):
                conn = KaliConnection(
                    self._host, self._port, self._username, self._password,
                )
                try:
                    await asyncio.to_thread(conn.connect)
                    self._pool.append(conn)
                except Exception as exc:
                    logger.warning(
                        "KaliConnectionManager: pool slot %d failed: %s", i, exc,
                    )
                    self._pool.append(conn)  # Keep slot, will reconnect on use

        logger.info(
            "KaliConnectionManager: pool initialized (%d/%d connected)",
            sum(1 for c in self._pool if c.connected), self._pool_size,
        )

    async def _get_healthy_connection(self) -> KaliConnection:
        """Get a healthy connection from the pool, reconnecting if needed."""
        async with self._pool_lock:
            # Find a connected one first
            for conn in self._pool:
                healthy = await asyncio.to_thread(conn.health_check)
                if healthy:
                    return conn

            # No healthy connection — try reconnecting each
            for conn in self._pool:
                success = await self._reconnect_connection(conn)
                if success:
                    return conn

        # Total failure
        await self._publish_unreachable()
        raise ConnectionError(
            f"KaliConnectionManager: all {self._pool_size} connections failed — KALI_UNREACHABLE"
        )

    async def _reconnect_connection(self, conn: KaliConnection) -> bool:
        """Reconnect a single connection with exponential backoff."""
        delay = RECONNECT_BASE_DELAY
        for attempt in range(1, MAX_RECONNECT_ATTEMPTS + 1):
            try:
                await asyncio.to_thread(conn.close)
                await asyncio.to_thread(conn.connect)
                logger.info(
                    "KaliConnectionManager: reconnected on attempt %d", attempt,
                )
                return True
            except Exception as exc:
                logger.warning(
                    "KaliConnectionManager: reconnect attempt %d/%d failed: %s",
                    attempt, MAX_RECONNECT_ATTEMPTS, exc,
                )
                actual_delay = min(delay, RECONNECT_MAX_DELAY)
                await asyncio.sleep(actual_delay)
                delay *= 2

        return False

    async def execute(
        self,
        tool_name: str,
        tool_input: dict[str, Any],
        tool_spec: Any,
    ) -> dict[str, Any]:
        """Execute a tool via KaliSSH through the connection pool.

        Acquires a semaphore slot, gets a healthy connection, executes
        the command, and returns parsed output.
        """
        async with self._semaphore:
            conn = await self._get_healthy_connection()

            # Build command from tool_name and tool_input
            command = self._build_command(tool_name, tool_input)
            timeout = getattr(tool_spec, "timeout_seconds", COMMAND_TIMEOUT)

            try:
                stdout, stderr, exit_code = await asyncio.to_thread(
                    conn.exec_command, command, timeout,
                )
            except Exception as exc:
                # Connection may have died mid-execution
                logger.error(
                    "KaliConnectionManager: exec failed for %s: %s",
                    tool_name, exc,
                )
                # Try reconnect for next caller
                await self._reconnect_connection(conn)
                return {
                    "status": "error",
                    "tool": tool_name,
                    "error": str(exc),
                    "stdout": "",
                    "stderr": "",
                    "exit_code": -1,
                }

            return {
                "status": "success" if exit_code == 0 else "error",
                "tool": tool_name,
                "stdout": stdout,
                "stderr": stderr,
                "exit_code": exit_code,
            }

    def _build_command(self, tool_name: str, tool_input: dict[str, Any]) -> str:
        """Build a shell command from tool name and input parameters.

        Each tool has its own command-line syntax. This method translates
        the structured tool_input dict into the appropriate CLI invocation.
        """
        target = tool_input.get("target", "")
        port = tool_input.get("port", "")
        flags = tool_input.get("flags", "")
        raw_command = tool_input.get("command", "")

        # If a raw command is provided, use it directly
        if raw_command:
            return raw_command

        # Tool-specific command builders
        builders = {
            "nmap": lambda: f"nmap {flags} {f'-p {port}' if port else ''} {target}".strip(),
            "nmap_verify": lambda: f"nmap -sV --open -p {port} {target}".strip(),
            "whatweb": lambda: f"whatweb {flags} {target}".strip(),
            "dnsrecon": lambda: f"dnsrecon -d {target} {flags}".strip(),
            "sublist3r": lambda: f"sublist3r -d {target} {flags}".strip(),
            "amass": lambda: f"amass enum -d {target} {flags}".strip(),
            "nikto": lambda: f"nikto -h {target} {f'-p {port}' if port else ''} {flags}".strip(),
            "nuclei": lambda: f"nuclei -u {target} {flags}".strip(),
            "masscan": lambda: f"masscan {target} {f'-p{port}' if port else '-p1-65535'} {flags}".strip(),
            "wpscan": lambda: f"wpscan --url {target} {flags}".strip(),
            "sqlmap": lambda: f"sqlmap -u {target} {flags} --batch".strip(),
            "dalfox": lambda: f"dalfox url {target} {flags}".strip(),
            "ffuf": lambda: f"ffuf -u {target} {flags}".strip(),
            "testssl": lambda: f"testssl {flags} {target}".strip(),
            "testssl_readonly": lambda: f"testssl --read-only {target}".strip(),
        }

        builder = builders.get(tool_name)
        if builder:
            return builder()

        # Generic fallback
        args = " ".join(f"{v}" for k, v in tool_input.items() if k not in ("_credentials",))
        return f"{tool_name} {args}".strip()

    async def _publish_unreachable(self) -> None:
        """Publish KALI_UNREACHABLE event to EventBus."""
        if self._event_bus:
            try:
                await self._event_bus.publish(
                    channel="system",
                    event_type="KALI_UNREACHABLE",
                    payload={
                        "message": "All Kali SSH connections failed after reconnect attempts",
                        "pool_size": self._pool_size,
                        "max_attempts": MAX_RECONNECT_ATTEMPTS,
                    },
                )
            except Exception as exc:
                logger.error("Failed to publish KALI_UNREACHABLE: %s", exc)

        logger.error(
            "KaliConnectionManager: KALI_UNREACHABLE — all %d connections failed",
            self._pool_size,
        )

    async def health_check(self) -> bool:
        """Check if at least one connection in the pool is healthy."""
        for conn in self._pool:
            if await asyncio.to_thread(conn.health_check):
                return True
        return False

    async def close(self) -> None:
        """Close all connections in the pool."""
        for conn in self._pool:
            await asyncio.to_thread(conn.close)
        self._pool.clear()
        logger.info("KaliConnectionManager: pool closed")
