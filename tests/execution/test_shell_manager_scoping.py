"""SEC-02 unit tests — ShellManager per-engagement workdir scoping.

Verifies that every command passed through ShellManager.execute() is
prefixed with `mkdir -p "{workdir}" && cd "{workdir}" &&` where
`{workdir}` is `/engagements/{engagement_id}`, so that concurrent
engagements never share Kali filesystem state (D-03).
"""

from __future__ import annotations

from unittest.mock import AsyncMock

import pytest

from backend.execution.shell_manager import ShellManager


@pytest.mark.asyncio
async def test_execute_scopes_command_to_engagement_workdir():
    mock_ssh = AsyncMock()
    mock_ssh.execute.return_value = "output"

    shell = ShellManager(mock_ssh, engagement_id="eng-A")
    await shell.execute("nmap -sV target")

    mock_ssh.execute.assert_awaited_once_with(
        'mkdir -p "/engagements/eng-A" && cd "/engagements/eng-A" && nmap -sV target'
    )


@pytest.mark.asyncio
async def test_execute_scopes_distinct_engagements_to_distinct_workdirs():
    mock_ssh_a = AsyncMock()
    mock_ssh_a.execute.return_value = "output-a"
    mock_ssh_b = AsyncMock()
    mock_ssh_b.execute.return_value = "output-b"

    shell_a = ShellManager(mock_ssh_a, engagement_id="eng-A")
    shell_b = ShellManager(mock_ssh_b, engagement_id="eng-B")

    await shell_a.execute("nmap -sV target")
    await shell_b.execute("nmap -sV target")

    mock_ssh_a.execute.assert_awaited_once_with(
        'mkdir -p "/engagements/eng-A" && cd "/engagements/eng-A" && nmap -sV target'
    )
    mock_ssh_b.execute.assert_awaited_once_with(
        'mkdir -p "/engagements/eng-B" && cd "/engagements/eng-B" && nmap -sV target'
    )
    assert shell_a._workdir != shell_b._workdir
