"""sandbox_manager watchdog — monitors ml-runtime and ics-runtime (N4, Section 6.4).

Host sidecar process that monitors task_status.json for stalled tasks.
If task_status.json updated_at is not refreshed within 120 seconds while
status is 'running', sends SIGTERM -> waits 10s -> SIGKILL.

This runs as a host process (NOT in a container) for Docker socket access.
"""

from __future__ import annotations

import asyncio
import json
import logging
import signal
import subprocess
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Watchdog configuration
STALE_THRESHOLD_SECONDS = 120
SIGTERM_GRACE_PERIOD = 10
POLL_INTERVAL_SECONDS = 10


class RuntimeWatchdog:
    """Monitors a runtime container's task_status.json for stalls.

    When a task is detected as stalled (updated_at not refreshed in
    STALE_THRESHOLD_SECONDS while status='running'):
      1. Send SIGTERM to the container process
      2. Wait SIGTERM_GRACE_PERIOD seconds
      3. Send SIGKILL if still running
      4. Docker Compose restart policy revives the container

    The TOOL_TIMEOUT event is published by the calling backend (MLRuntimeIPC),
    not by this watchdog directly.
    """

    def __init__(
        self,
        container_name: str,
        ipc_dir: Path,
        stale_threshold: int = STALE_THRESHOLD_SECONDS,
    ) -> None:
        self._container_name = container_name
        self._ipc_dir = ipc_dir
        self._stale_threshold = stale_threshold
        self._running = False

    async def start(self) -> None:
        """Start the watchdog monitoring loop."""
        self._running = True
        logger.info(
            "RuntimeWatchdog: started for %s (watching %s)",
            self._container_name, self._ipc_dir,
        )
        while self._running:
            await self._check_tasks()
            await asyncio.sleep(POLL_INTERVAL_SECONDS)

    async def stop(self) -> None:
        """Stop the watchdog."""
        self._running = False

    async def _check_tasks(self) -> None:
        """Scan all task directories for stalled tasks."""
        if not self._ipc_dir.exists():
            return

        for task_dir in self._ipc_dir.iterdir():
            if not task_dir.is_dir():
                continue

            status_file = task_dir / "task_status.json"
            if not status_file.exists():
                continue

            try:
                data = json.loads(status_file.read_text())
            except (json.JSONDecodeError, OSError):
                continue

            if data.get("status") != "running":
                continue

            updated_at_str = data.get("updated_at")
            if not updated_at_str:
                continue

            try:
                updated_at = datetime.fromisoformat(updated_at_str).replace(
                    tzinfo=timezone.utc
                )
            except ValueError:
                continue

            now = datetime.now(timezone.utc)
            elapsed = (now - updated_at).total_seconds()

            if elapsed > self._stale_threshold:
                logger.error(
                    "RuntimeWatchdog: task in %s stalled (%.0fs since last update). "
                    "Killing container %s",
                    task_dir.name, elapsed, self._container_name,
                )
                await self._kill_container()

    async def _kill_container(self) -> None:
        """Send SIGTERM, wait, then SIGKILL to the container."""
        try:
            # SIGTERM
            await asyncio.to_thread(
                subprocess.run,
                ["docker", "kill", "--signal=SIGTERM", self._container_name],
                capture_output=True,
                timeout=5,
            )
            logger.info(
                "RuntimeWatchdog: sent SIGTERM to %s", self._container_name
            )

            # Grace period
            await asyncio.sleep(SIGTERM_GRACE_PERIOD)

            # Check if still running
            result = await asyncio.to_thread(
                subprocess.run,
                ["docker", "inspect", "-f", "{{.State.Running}}", self._container_name],
                capture_output=True,
                text=True,
                timeout=5,
            )

            if result.stdout.strip() == "true":
                # SIGKILL
                await asyncio.to_thread(
                    subprocess.run,
                    ["docker", "kill", "--signal=SIGKILL", self._container_name],
                    capture_output=True,
                    timeout=5,
                )
                logger.warning(
                    "RuntimeWatchdog: sent SIGKILL to %s", self._container_name
                )

        except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as exc:
            logger.error(
                "RuntimeWatchdog: failed to kill %s: %s",
                self._container_name, exc,
            )


class SandboxManager:
    """Host sidecar managing sandbox lifecycle and runtime watchdogs.

    Manages:
      - DVWA sandbox container lifecycle
      - ml-runtime watchdog (v2.0 N4)
      - ics-runtime watchdog (v2.0 extension)
    """

    def __init__(self) -> None:
        self._watchdogs: list[RuntimeWatchdog] = []
        self._tasks: list[asyncio.Task] = []

    def add_watchdog(self, watchdog: RuntimeWatchdog) -> None:
        """Register a runtime watchdog."""
        self._watchdogs.append(watchdog)

    async def start_all(self) -> None:
        """Start all registered watchdogs."""
        for wd in self._watchdogs:
            task = asyncio.create_task(wd.start())
            self._tasks.append(task)
        logger.info("SandboxManager: started %d watchdogs", len(self._watchdogs))

    async def stop_all(self) -> None:
        """Stop all watchdogs."""
        for wd in self._watchdogs:
            await wd.stop()
        for task in self._tasks:
            task.cancel()
        self._tasks.clear()


def create_default_sandbox_manager() -> SandboxManager:
    """Create SandboxManager with default watchdogs for ml-runtime and ics-runtime."""
    manager = SandboxManager()

    # ml-runtime watchdog
    manager.add_watchdog(RuntimeWatchdog(
        container_name="optimus-ml-runtime-1",
        ipc_dir=Path("/data/ml-runtime-ipc"),
    ))

    # ics-runtime watchdog
    manager.add_watchdog(RuntimeWatchdog(
        container_name="optimus-ics-runtime-1",
        ipc_dir=Path("/data/ics-runtime-ipc"),
    ))

    return manager
