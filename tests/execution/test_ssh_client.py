"""CR-01 regression tests — SSHClient must not await synchronous paramiko calls.

`paramiko.SSHClient.connect()` and `.exec_command()` are blocking, synchronous
methods (they return None / a 3-tuple respectively, not awaitables). Awaiting
them directly raises `TypeError: object NoneType can't be used in 'await'
expression`. These tests mock `paramiko.SSHClient` as a plain (non-async)
Mock — matching the real library's interface — so an accidental `await` on a
synchronous return value fails loudly instead of being hidden by an
AsyncMock's auto-await behavior.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from backend.execution.ssh_client import SSHClient


@pytest.mark.asyncio
async def test_connect_does_not_await_synchronous_paramiko_connect():
    mock_client = MagicMock()
    mock_client.connect.return_value = None  # real paramiko.SSHClient.connect() returns None

    with patch("paramiko.SSHClient", return_value=mock_client):
        ssh = SSHClient()
        result = await ssh.connect()

    assert result is mock_client
    mock_client.connect.assert_called_once()


@pytest.mark.asyncio
async def test_execute_does_not_await_synchronous_exec_command():
    mock_client = MagicMock()
    mock_client.connect.return_value = None
    mock_stdout = MagicMock()
    mock_stdout.read.return_value = b"output"
    mock_stderr = MagicMock()
    mock_stderr.read.return_value = b""
    mock_client.exec_command.return_value = (MagicMock(), mock_stdout, mock_stderr)

    with patch("paramiko.SSHClient", return_value=mock_client):
        ssh = SSHClient()
        output = await ssh.execute("whoami")

    assert output == "output"
    mock_client.exec_command.assert_called_once_with("whoami")
