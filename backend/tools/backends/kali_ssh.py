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
MAX_RECONNECT_ATTEMPTS = 2       # Reduced from 5 — fail fast, let circuit breaker handle retries
RECONNECT_BASE_DELAY = 1.0       # Reduced from 2s
RECONNECT_MAX_DELAY = 5.0        # Reduced from 30s
COMMAND_TIMEOUT = 3600           # last-resort Python-side backstop only; per-tool limits via Kali timeout prefix
SSH_CONNECT_TIMEOUT = 5          # per-attempt SSH connect timeout (was 10s)
CIRCUIT_BREAKER_COOLDOWN = 60.0  # seconds before retrying after total pool failure
HEALTH_CHECK_TIMEOUT = 2.0       # max seconds for a health check — bounds lock hold time
SSH_KEEPALIVE_INTERVAL = 30      # seconds between SSH-level keepalives


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
            timeout=SSH_CONNECT_TIMEOUT,
            allow_agent=False,
            look_for_keys=False,
        )
        self._client = client
        # Enable SSH-level keepalives so dead connections are detected quickly
        # instead of appearing healthy until the next command blocks.
        transport = client.get_transport()
        if transport:
            transport.set_keepalive(SSH_KEEPALIVE_INTERVAL)
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

        # Wait for the channel to close with a timeout.  Without this,
        # recv_exit_status() blocks indefinitely if Kali goes offline
        # mid-command, causing the ToolExecutor's 300 s asyncio.wait_for
        # to fire and report a spurious timeout instead of a clean error.
        if not stdout.channel.status_event.wait(timeout=timeout):
            stdout.channel.close()
            self._connected = False
            raise TimeoutError(f"Command timed out after {timeout}s: {command[:100]}")

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
        terminal_broadcaster: Any | None = None,
    ) -> None:
        self._host = host
        self._port = port
        self._username = username
        self._password = password
        self._pool_size = pool_size
        self._semaphore = asyncio.Semaphore(pool_size)
        self._pool: list[KaliConnection] = []
        self._event_bus = event_bus
        self._terminal_broadcaster = terminal_broadcaster
        self._pool_lock = asyncio.Lock()
        self._unreachable_until: float = 0.0  # circuit breaker timestamp

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
        """Get a healthy connection — lock only held for pool reads, not reconnect sleep."""
        # Circuit breaker: fail immediately if Kali was recently unreachable
        now = time.monotonic()
        if now < self._unreachable_until:
            remaining = self._unreachable_until - now
            raise ConnectionError(
                f"Kali SSH unreachable — retrying in {remaining:.0f}s "
                f"(start the Kali container to enable scan tools)"
            )

        # Step 1: find a healthy slot under the lock (fast operation).
        # Each health check is bounded by HEALTH_CHECK_TIMEOUT so the lock
        # is never held longer than pool_size × HEALTH_CHECK_TIMEOUT even
        # if send_ignore() stalls on a half-open TCP connection.
        conn_to_reconnect = None
        async with self._pool_lock:
            for conn in self._pool:
                try:
                    healthy = await asyncio.wait_for(
                        asyncio.to_thread(conn.health_check),
                        timeout=HEALTH_CHECK_TIMEOUT,
                    )
                except asyncio.TimeoutError:
                    healthy = False
                if healthy:
                    return conn
            # No healthy connections found — pick first slot to reconnect
            if self._pool:
                conn_to_reconnect = self._pool[0]

        # Step 2: reconnect OUTSIDE the lock — sleep does not block other callers
        if conn_to_reconnect:
            success = await self._reconnect_connection(conn_to_reconnect)
            if success:
                return conn_to_reconnect

        # Step 3: try remaining pool slots outside the lock
        async with self._pool_lock:
            remaining = list(self._pool[1:])  # Already tried index 0
        for conn in remaining:
            success = await self._reconnect_connection(conn)
            if success:
                return conn

        # Total failure — open circuit breaker
        self._unreachable_until = time.monotonic() + CIRCUIT_BREAKER_COOLDOWN
        await self._publish_unreachable()
        raise ConnectionError(
            f"Kali SSH unreachable — all {self._pool_size} connections failed. "
            f"Will retry in {CIRCUIT_BREAKER_COOLDOWN:.0f}s."
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

            # Prepend a full PATH so tools installed via apt, pip3 --user, Go, or
            # manually into /opt / /snap are reachable.  paramiko's exec_command
            # launches a non-login, non-interactive shell — it does NOT source
            # ~/.bashrc or ~/.profile — so the default PATH is bare system paths
            # only.  This one-liner closes that gap without any exec overhead.
            command = (
                "export PATH=/root/.local/bin:/usr/local/go/bin:/snap/bin:"
                "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:"
                "$PATH 2>/dev/null; " + command
            )

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

            # Detect "command not found" (exit 127) — return a clear error so
            # agents can skip the tool rather than treating it as a normal failure.
            if exit_code == 127 or (
                exit_code != 0
                and stderr
                and ("command not found" in stderr.lower() or "not found" in stderr.lower())
            ):
                logger.warning(
                    "KaliConnectionManager: tool '%s' not found on Kali — exit %d: %s",
                    tool_name, exit_code, stderr[:200],
                )
                return {
                    "status": "tool_not_found",
                    "tool": tool_name,
                    "error": (
                        f"Tool '{tool_name}' is not installed or not in PATH on Kali. "
                        f"stderr: {stderr[:200]}"
                    ),
                    "stdout": stdout,
                    "stderr": stderr,
                    "exit_code": exit_code,
                }

            if self._terminal_broadcaster is not None:
                from datetime import datetime, timezone
                ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
                if stdout:
                    await self._terminal_broadcaster.publish({
                        "type": "kali_output",
                        "source": "kali",
                        "agent": tool_input.get("_agent_name"),
                        "tool": tool_name,
                        "stream": "stdout",
                        "data": stdout,
                        "ts": ts,
                    })
                if stderr:
                    await self._terminal_broadcaster.publish({
                        "type": "kali_output",
                        "source": "kali",
                        "agent": tool_input.get("_agent_name"),
                        "tool": tool_name,
                        "stream": "stderr",
                        "data": stderr,
                        "ts": ts,
                    })

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

        # Tool-specific command builders (with Kali-side timeout prefixes)
        builders = {
            # --- Reconnaissance ---
            "nmap": lambda: f"timeout 180 nmap {flags} {f'-p {port}' if port else ''} {target}".strip(),
            "nmap_verify": lambda: f"timeout 30 nmap -sV --open -p {port} {target}".strip(),
            "whatweb": lambda: f"timeout 30 whatweb {flags} {target}".strip(),
            "dnsrecon": lambda: f"timeout 60 dnsrecon -d {target} {flags}".strip(),
            "sublist3r": lambda: f"timeout 60 sublist3r -d {target} {flags}".strip(),
            "amass": lambda: f"timeout 120 amass enum -d {target} {flags}".strip(),
            # --- Scope discovery ---
            "crt_sh": lambda: (
                f"timeout 15 curl -sk 'https://crt.sh/?q={target}&output=json' "
                f"| python3 -c \""
                f"import sys,json; data=json.load(sys.stdin); "
                f"[print(e.get('name_value','')) for e in data[:100]]\""
                f" 2>/dev/null || timeout 15 curl -sk 'https://crt.sh/?q={target}'"
            ).strip(),
            "whois": lambda: f"timeout 15 whois {target} 2>/dev/null || echo 'whois: {target}'".strip(),
            "dns_enum": lambda: (
                f"(timeout 30 dig +noall +answer {target} ANY 2>/dev/null; "
                f"timeout 10 dig +noall +answer {target} MX 2>/dev/null; "
                f"timeout 10 dig +noall +answer {target} NS 2>/dev/null; "
                f"timeout 10 host {target} 2>/dev/null) | sort -u"
            ).strip(),
            "github_scan": lambda: (
                f"timeout 15 curl -sk 'https://api.github.com/search/repositories"
                f"?q={target}+in:name,description&per_page=10' 2>/dev/null"
            ).strip(),
            "shodan": lambda: (
                f"timeout 15 curl -sk 'https://internetdb.shodan.io/{target}' 2>/dev/null "
                f"|| timeout 15 shodan host {target} 2>/dev/null "
                f"|| echo '{{\"error\": \"shodan unavailable for {target}\"}}'"
            ).strip(),
            "cve_search": lambda: (
                f"timeout 20 curl -sk "
                f"'https://cve.circl.lu/api/cve/{tool_input.get('target', target)}' "
                f"2>/dev/null || echo '{{}}'"
            ).strip(),
            "exploit_db": lambda: (
                f"timeout 30 searchsploit --json {target} 2>/dev/null "
                f"|| timeout 30 searchsploit {target} 2>/dev/null "
                f"|| echo '{{\"RESULTS_EXPLOIT\": []}}'"
            ).strip(),
            # --- Vulnerability scanning ---
            "nikto": lambda: f"timeout 90 nikto -maxtime 90 -h {target} {f'-p {port}' if port else ''} {flags}".strip(),
            "nuclei": lambda: f"timeout 60 nuclei -u {target} {flags}".strip(),
            "masscan": lambda: f"timeout 120 masscan {target} {f'-p{port}' if port else '-p1-65535'} {flags}".strip(),
            "wpscan": lambda: f"timeout 90 wpscan --url {target} {flags}".strip(),
            # --- Exploitation ---
            "sqlmap": lambda: f"timeout 180 sqlmap -u {target} {flags} --batch".strip(),
            "dalfox": lambda: f"timeout 60 dalfox url {target} {flags}".strip(),
            "ffuf": lambda: f"timeout 90 ffuf -u {target} {flags}".strip(),
            "commix": lambda: f"timeout 120 commix --url={target} {flags} --batch 2>/dev/null".strip(),
            "payload_crafter": lambda: (
                f"timeout 60 msfvenom {flags} 2>/dev/null || echo 'payload_crafter: msfvenom unavailable'"
            ).strip(),
            "msfconsole": lambda: (
                f"timeout 300 msfconsole -q -x '{raw_command}' 2>/dev/null"
                if raw_command else
                "echo 'msfconsole: no command provided'"
            ).strip(),
            # --- TLS / HTTP probes ---
            # Kali installs the package as 'testssl' (no .sh suffix)
            "testssl": lambda: f"timeout 60 testssl {flags} {target}".strip(),
            "testssl_readonly": lambda: f"timeout 60 testssl --read-only {target}".strip(),
            "curl": lambda: f"timeout 15 curl -sk {flags} '{target}' 2>/dev/null".strip(),
            "httpx_probe": lambda: (
                f"timeout 15 curl -sk -o /dev/null -w '%{{http_code}} %{{url_effective}}\\n' '{target}' 2>/dev/null"
            ).strip(),
            # --- ToolFallbackResolver install/query commands (bypass registry) ---
            "_install": lambda: raw_command or "echo 'install: no command'",
            "_web_query": lambda: raw_command or "echo 'web_query: no command'",
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
