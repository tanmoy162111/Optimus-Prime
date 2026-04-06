"""Tests for TerminalBroadcaster and TerminalLogHandler."""
from __future__ import annotations

import asyncio
import logging
from unittest.mock import AsyncMock, MagicMock

import pytest

from backend.core.terminal_broadcaster import TerminalBroadcaster, TerminalLogHandler


class TestTerminalBroadcaster:
    async def test_publish_fans_out_to_all_connections(self):
        broadcaster = TerminalBroadcaster()
        ws1 = AsyncMock()
        ws2 = AsyncMock()
        broadcaster._connections = [ws1, ws2]

        event = {"type": "kali_output", "data": "hello"}
        await broadcaster.publish(event)

        ws1.send_json.assert_awaited_once_with(event)
        ws2.send_json.assert_awaited_once_with(event)

    async def test_publish_skips_failed_connections(self):
        broadcaster = TerminalBroadcaster()
        ws_good = AsyncMock()
        ws_bad = AsyncMock()
        ws_bad.send_json.side_effect = Exception("closed")
        broadcaster._connections = [ws_bad, ws_good]

        await broadcaster.publish({"type": "kali_output", "data": "x"})

        ws_good.send_json.assert_awaited_once()

    async def test_connect_adds_websocket(self):
        broadcaster = TerminalBroadcaster()
        ws = AsyncMock()
        await broadcaster.connect(ws)
        assert ws in broadcaster._connections
        ws.accept.assert_awaited_once()

    def test_disconnect_removes_websocket(self):
        broadcaster = TerminalBroadcaster()
        ws = MagicMock()
        broadcaster._connections = [ws]
        broadcaster.disconnect(ws)
        assert ws not in broadcaster._connections

    def test_disconnect_noop_if_not_connected(self):
        broadcaster = TerminalBroadcaster()
        ws = MagicMock()
        broadcaster.disconnect(ws)  # must not raise


class TestTerminalLogHandler:
    async def test_emit_publishes_backend_log_event(self):
        broadcaster = TerminalBroadcaster()
        broadcaster.publish = AsyncMock()

        handler = TerminalLogHandler(broadcaster)
        record = logging.LogRecord(
            name="backend.agents.recon_agent",
            level=logging.INFO,
            pathname="",
            lineno=0,
            msg="ReconAgent dispatching nmap",
            args=(),
            exc_info=None,
        )
        handler.emit(record)

        # give the event loop a tick to run the coroutine
        await asyncio.sleep(0)

        broadcaster.publish.assert_awaited_once()
        call_args = broadcaster.publish.call_args[0][0]
        assert call_args["type"] == "backend_log"
        assert call_args["source"] == "backend"
        assert call_args["level"] == "INFO"
        assert call_args["logger"] == "backend.agents.recon_agent"
        assert "ReconAgent dispatching nmap" in call_args["data"]
        assert call_args["ts"].endswith("Z")

    async def test_emit_does_not_raise_on_broadcaster_error(self):
        """emit() must never raise, even if loop.create_task raises."""
        broadcaster = TerminalBroadcaster()

        handler = TerminalLogHandler(broadcaster)
        record = logging.LogRecord(
            name="backend.test",
            level=logging.ERROR,
            pathname="",
            lineno=0,
            msg="error",
            args=(),
            exc_info=None,
        )

        # Patch create_task to raise synchronously inside emit
        import asyncio as _asyncio
        original_get_loop = _asyncio.get_running_loop

        class _FakeLoop:
            def create_task(self, coro):
                coro.close()  # prevent coroutine-never-awaited warning
                raise RuntimeError("simulated loop error")

        import unittest.mock as _mock
        with _mock.patch("asyncio.get_running_loop", return_value=_FakeLoop()):
            handler.emit(record)  # must not raise


class TestTerminalExecEndpoint:
    """Integration tests for POST /terminal/exec."""

    def test_empty_command_returns_400(self):
        from fastapi.testclient import TestClient
        from backend.main import app

        client = TestClient(app)
        resp = client.post("/terminal/exec", json={"command": "  "})
        assert resp.status_code == 400

    def test_missing_command_field_returns_422(self):
        from fastapi.testclient import TestClient
        from backend.main import app

        client = TestClient(app)
        resp = client.post("/terminal/exec", json={})
        assert resp.status_code == 422
