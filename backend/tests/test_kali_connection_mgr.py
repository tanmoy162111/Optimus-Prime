"""Suite 1 — KaliConnectionManager unit tests (T4).

Tests the SSH connection pool with mocked paramiko:
  - Health check failure triggers reconnect
  - Exponential backoff timing
  - Pool semaphore limits concurrent callers to 3
  - KALI_UNREACHABLE event published on total failure
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from backend.tools.backends.kali_ssh import (
    MAX_RECONNECT_ATTEMPTS,
    RECONNECT_BASE_DELAY,
    RECONNECT_MAX_DELAY,
    KaliConnection,
    KaliConnectionManager,
)


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def mock_event_bus(tmp_path):
    """Create a mock EventBus that records published events."""
    bus = AsyncMock()
    bus.published_events = []

    async def _publish(channel, event_type, payload):
        bus.published_events.append({
            "channel": channel,
            "event_type": event_type,
            "payload": payload,
        })

    bus.publish = _publish
    return bus


def _make_mock_transport(active: bool = True):
    """Create a mock paramiko Transport."""
    transport = MagicMock()
    transport.is_active.return_value = active
    transport.send_ignore.return_value = None
    return transport


def _make_mock_client(active: bool = True):
    """Create a mock paramiko SSHClient."""
    client = MagicMock()
    client.get_transport.return_value = _make_mock_transport(active)

    # Mock exec_command
    stdin_mock = MagicMock()
    stdout_mock = MagicMock()
    stderr_mock = MagicMock()
    stdout_mock.channel.recv_exit_status.return_value = 0
    stdout_mock.read.return_value = b"scan results here"
    stderr_mock.read.return_value = b""
    client.exec_command.return_value = (stdin_mock, stdout_mock, stderr_mock)

    return client


# ---------------------------------------------------------------------------
# KaliConnection tests
# ---------------------------------------------------------------------------

class TestKaliConnection:
    """Test individual connection health check and execution."""

    def test_health_check_not_connected(self):
        conn = KaliConnection("kali", 22, "root", "pass")
        assert conn.health_check() is False

    def test_health_check_active_transport(self):
        conn = KaliConnection("kali", 22, "root", "pass")
        conn._client = _make_mock_client(active=True)
        conn._connected = True
        assert conn.health_check() is True

    def test_health_check_dead_transport(self):
        conn = KaliConnection("kali", 22, "root", "pass")
        conn._client = _make_mock_client(active=False)
        conn._connected = True
        assert conn.health_check() is False

    def test_exec_command_success(self):
        conn = KaliConnection("kali", 22, "root", "pass")
        conn._client = _make_mock_client()
        conn._connected = True
        stdout, stderr, code = conn.exec_command("nmap -sV target")
        assert code == 0
        assert "scan results" in stdout

    def test_exec_command_not_connected_raises(self):
        conn = KaliConnection("kali", 22, "root", "pass")
        with pytest.raises(ConnectionError, match="Not connected"):
            conn.exec_command("nmap target")

    def test_exec_command_timeout_when_kali_offline(self):
        """exec_command raises TimeoutError when channel never closes (Kali offline)."""
        import threading

        conn = KaliConnection("kali", 22, "root", "pass")

        # Build a channel whose status_event never fires (simulates Kali dropping offline)
        channel_mock = MagicMock()
        channel_mock.status_event = threading.Event()  # never set → wait() returns False
        channel_mock.status_event.wait = MagicMock(return_value=False)

        stdout_mock = MagicMock()
        stdout_mock.channel = channel_mock
        stderr_mock = MagicMock()

        client = MagicMock()
        client.exec_command.return_value = (MagicMock(), stdout_mock, stderr_mock)
        conn._client = client
        conn._connected = True

        with pytest.raises(TimeoutError, match="timed out"):
            conn.exec_command("nmap target", timeout=1)

    def test_close(self):
        conn = KaliConnection("kali", 22, "root", "pass")
        conn._client = _make_mock_client()
        conn._connected = True
        conn.close()
        assert conn.connected is False


# ---------------------------------------------------------------------------
# KaliConnectionManager tests
# ---------------------------------------------------------------------------

class TestKaliConnectionManager:
    """Test the connection pool manager."""

    @pytest.mark.asyncio
    async def test_pool_initialization(self):
        """Pool connects the specified number of slots."""
        mgr = KaliConnectionManager(pool_size=2)

        with patch.object(KaliConnection, "connect") as mock_connect:
            await mgr.connect()
            assert len(mgr._pool) == 2
            assert mock_connect.call_count == 2

    @pytest.mark.asyncio
    async def test_health_check_returns_true_when_connected(self):
        """Health check returns True when at least one connection is alive."""
        mgr = KaliConnectionManager(pool_size=1)
        conn = KaliConnection("kali", 22, "root", "pass")
        conn._client = _make_mock_client(active=True)
        conn._connected = True
        mgr._pool = [conn]

        assert await mgr.health_check() is True

    @pytest.mark.asyncio
    async def test_health_check_returns_false_when_all_dead(self):
        """Health check returns False when all connections are dead."""
        mgr = KaliConnectionManager(pool_size=1)
        conn = KaliConnection("kali", 22, "root", "pass")
        # Not connected
        mgr._pool = [conn]

        assert await mgr.health_check() is False

    @pytest.mark.asyncio
    async def test_execute_through_healthy_pool(self):
        """Execute succeeds through a healthy connection."""
        mgr = KaliConnectionManager(pool_size=1)
        conn = KaliConnection("kali", 22, "root", "pass")
        conn._client = _make_mock_client(active=True)
        conn._connected = True
        mgr._pool = [conn]

        spec = MagicMock()
        spec.timeout_seconds = 60

        result = await mgr.execute("nmap", {"target": "10.0.0.1"}, spec)
        assert result["status"] == "success"
        assert result["tool"] == "nmap"

    @pytest.mark.asyncio
    async def test_reconnect_on_health_check_failure(self):
        """When health check fails, reconnect is triggered."""
        mgr = KaliConnectionManager(pool_size=1)
        conn = KaliConnection("kali", 22, "root", "pass")
        conn._connected = False  # Dead
        mgr._pool = [conn]

        reconnect_calls = []

        original_reconnect = mgr._reconnect_connection

        async def mock_reconnect(c):
            reconnect_calls.append(True)
            c._connected = True
            c._client = _make_mock_client(active=True)
            return True

        mgr._reconnect_connection = mock_reconnect

        spec = MagicMock()
        spec.timeout_seconds = 60

        result = await mgr.execute("nmap", {"target": "10.0.0.1"}, spec)
        assert len(reconnect_calls) == 1
        assert result["status"] == "success"

    @pytest.mark.asyncio
    async def test_kali_unreachable_on_total_failure(self, mock_event_bus):
        """KALI_UNREACHABLE published when all connections fail."""
        mgr = KaliConnectionManager(pool_size=1, event_bus=mock_event_bus)
        conn = KaliConnection("kali", 22, "root", "pass")
        conn._connected = False
        mgr._pool = [conn]

        async def mock_reconnect(c):
            return False  # All attempts fail

        mgr._reconnect_connection = mock_reconnect

        spec = MagicMock()
        spec.timeout_seconds = 60

        with pytest.raises(ConnectionError, match="unreachable"):
            await mgr.execute("nmap", {"target": "10.0.0.1"}, spec)

        # Check event was published
        assert len(mock_event_bus.published_events) == 1
        assert mock_event_bus.published_events[0]["event_type"] == "KALI_UNREACHABLE"

    @pytest.mark.asyncio
    async def test_semaphore_limits_concurrency(self):
        """Pool semaphore limits concurrent callers to pool_size."""
        pool_size = 2
        mgr = KaliConnectionManager(pool_size=pool_size)

        # Create healthy connections
        for _ in range(pool_size):
            conn = KaliConnection("kali", 22, "root", "pass")
            conn._client = _make_mock_client(active=True)
            conn._connected = True
            mgr._pool.append(conn)

        concurrent_count = 0
        max_concurrent = 0
        lock = asyncio.Lock()

        original_execute = mgr.execute

        async def tracked_execute(tool_name, tool_input, tool_spec):
            nonlocal concurrent_count, max_concurrent
            async with lock:
                concurrent_count += 1
                max_concurrent = max(max_concurrent, concurrent_count)

            await asyncio.sleep(0.05)  # Simulate work

            async with lock:
                concurrent_count -= 1

            return {"status": "success", "tool": tool_name}

        # Override execute but keep semaphore
        async def semaphore_tracked(tool_name, tool_input, tool_spec):
            async with mgr._semaphore:
                return await tracked_execute(tool_name, tool_input, tool_spec)

        spec = MagicMock()
        spec.timeout_seconds = 60

        # Launch more tasks than pool_size
        tasks = [
            asyncio.create_task(semaphore_tracked("nmap", {"target": f"10.0.0.{i}"}, spec))
            for i in range(5)
        ]
        await asyncio.gather(*tasks)

        assert max_concurrent <= pool_size

    @pytest.mark.asyncio
    async def test_close_clears_pool(self):
        """Close shuts down all connections."""
        mgr = KaliConnectionManager(pool_size=2)
        for _ in range(2):
            conn = KaliConnection("kali", 22, "root", "pass")
            conn._client = _make_mock_client()
            conn._connected = True
            mgr._pool.append(conn)

        await mgr.close()
        assert len(mgr._pool) == 0


# ---------------------------------------------------------------------------
# Command builder tests
# ---------------------------------------------------------------------------

class TestCommandBuilder:
    """Test command building from tool name and input."""

    def test_nmap_command(self):
        mgr = KaliConnectionManager()
        cmd = mgr._build_command("nmap", {"target": "10.0.0.1", "flags": "-sV", "port": "80"})
        assert "nmap" in cmd
        assert "10.0.0.1" in cmd
        assert "-sV" in cmd
        assert "-p 80" in cmd

    def test_whatweb_command(self):
        mgr = KaliConnectionManager()
        cmd = mgr._build_command("whatweb", {"target": "example.com", "flags": "-a 3"})
        assert "whatweb" in cmd
        assert "example.com" in cmd

    def test_raw_command_passthrough(self):
        mgr = KaliConnectionManager()
        cmd = mgr._build_command("custom", {"command": "curl -s http://target"})
        assert cmd == "curl -s http://target"

    def test_generic_fallback(self):
        mgr = KaliConnectionManager()
        cmd = mgr._build_command("unknown_tool", {"target": "10.0.0.1", "mode": "fast"})
        assert "unknown_tool" in cmd
        assert "10.0.0.1" in cmd


# ---------------------------------------------------------------------------
# Exponential backoff tests
# ---------------------------------------------------------------------------

class TestExponentialBackoff:
    """Verify the reconnect backoff timing constants."""

    def test_base_delay(self):
        assert RECONNECT_BASE_DELAY == 1.0

    def test_max_delay(self):
        assert RECONNECT_MAX_DELAY == 5.0

    def test_backoff_sequence(self):
        """Verify the exponential backoff sequence caps at max."""
        delay = RECONNECT_BASE_DELAY
        delays = []
        for _ in range(MAX_RECONNECT_ATTEMPTS):
            actual = min(delay, RECONNECT_MAX_DELAY)
            delays.append(actual)
            delay *= 2

        assert delays == [1.0, 2.0, 4.0, 5.0, 5.0][:MAX_RECONNECT_ATTEMPTS]


class TestKaliConnectionManagerBroadcast:
    """Verify that execute() publishes stdout/stderr to TerminalBroadcaster."""

    @pytest.mark.asyncio
    async def test_execute_broadcasts_stdout(self):
        from unittest.mock import AsyncMock, MagicMock, patch
        from backend.core.terminal_broadcaster import TerminalBroadcaster

        broadcaster = TerminalBroadcaster()
        broadcaster.publish = AsyncMock()

        mgr = KaliConnectionManager(
            host="kali", port=22, username="root", password="optimus",
            event_bus=MagicMock(),
            terminal_broadcaster=broadcaster,
        )

        mock_conn = MagicMock()
        mock_conn.exec_command.return_value = ("scan complete\n", "", 0)
        mgr._pool = [mock_conn]
        mgr._semaphore = asyncio.Semaphore(3)

        mock_spec = MagicMock()
        mock_spec.timeout_seconds = 30

        with patch.object(mgr, "_get_healthy_connection", return_value=mock_conn):
            result = await mgr.execute(
                tool_name="nmap",
                tool_input={"target": "10.0.0.1"},
                tool_spec=mock_spec,
            )

        assert result["stdout"] == "scan complete\n"

        broadcaster.publish.assert_awaited()
        call_event = broadcaster.publish.call_args_list[0][0][0]
        assert call_event["type"] == "kali_output"
        assert call_event["source"] == "kali"
        assert call_event["tool"] == "nmap"
        assert call_event["stream"] == "stdout"
        assert "scan complete" in call_event["data"]
        assert "agent" in call_event  # field must be present (value is None when _agent_name not in tool_input)

    @pytest.mark.asyncio
    async def test_execute_broadcasts_stderr_when_non_empty(self):
        from unittest.mock import AsyncMock, MagicMock, patch
        from backend.core.terminal_broadcaster import TerminalBroadcaster

        broadcaster = TerminalBroadcaster()
        broadcaster.publish = AsyncMock()

        mgr = KaliConnectionManager(
            host="kali", port=22, username="root", password="optimus",
            event_bus=MagicMock(),
            terminal_broadcaster=broadcaster,
        )

        mock_conn = MagicMock()
        mock_conn.exec_command.return_value = ("", "permission denied\n", 1)
        mgr._pool = [mock_conn]
        mgr._semaphore = asyncio.Semaphore(3)

        mock_spec = MagicMock()
        mock_spec.timeout_seconds = 30

        with patch.object(mgr, "_get_healthy_connection", return_value=mock_conn):
            await mgr.execute(
                tool_name="nmap",
                tool_input={"target": "10.0.0.1"},
                tool_spec=mock_spec,
            )

        calls = [c[0][0] for c in broadcaster.publish.call_args_list]
        stderr_calls = [c for c in calls if c.get("stream") == "stderr"]
        assert len(stderr_calls) == 1
        assert "permission denied" in stderr_calls[0]["data"]

    @pytest.mark.asyncio
    async def test_execute_without_broadcaster_does_not_raise(self):
        """broadcaster=None (default) must be backward-compatible."""
        from unittest.mock import MagicMock, patch

        mgr = KaliConnectionManager(
            host="kali", port=22, username="root", password="optimus",
            event_bus=MagicMock(),
        )

        mock_conn = MagicMock()
        mock_conn.exec_command.return_value = ("ok\n", "", 0)
        mgr._pool = [mock_conn]
        mgr._semaphore = asyncio.Semaphore(3)

        mock_spec = MagicMock()
        mock_spec.timeout_seconds = 30

        with patch.object(mgr, "_get_healthy_connection", return_value=mock_conn):
            result = await mgr.execute(
                tool_name="nmap",
                tool_input={"target": "10.0.0.1"},
                tool_spec=mock_spec,
            )

        assert result["status"] == "success"
