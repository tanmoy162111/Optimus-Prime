"""TaskRegistry — Tracks agent tasks and their lifecycle (Section 5.4)."""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from typing import Any

from backend.core.models import AgentTask, TaskStatus

logger = logging.getLogger(__name__)


class TaskRegistry:
    """Registry for all agent tasks including research daemon tasks.

    Tracks task lifecycle: Created -> Running -> Completed/Failed/Stopped.
    """

    def __init__(self) -> None:
        self._tasks: dict[str, AgentTask] = {}

    def create_task(
        self,
        task_id: str,
        agent_class: str,
        prompt: str,
        team_id: str | None = None,
        parent_task_id: str | None = None,
    ) -> AgentTask:
        """Create and register a new task."""
        task = AgentTask(
            task_id=task_id,
            agent_class=agent_class,
            prompt=prompt,
            team_id=team_id,
            parent_task_id=parent_task_id,
        )
        self._tasks[task_id] = task
        logger.info("TaskRegistry: created task %s for %s", task_id, agent_class)
        return task

    def update_status(self, task_id: str, status: TaskStatus, output: str = "") -> None:
        """Update a task's status."""
        if task_id in self._tasks:
            task = self._tasks[task_id]
            task.status = status
            task.updated_at = datetime.now(timezone.utc)
            if output:
                task.output = output

    def get_task(self, task_id: str) -> AgentTask | None:
        """Get a task by ID."""
        return self._tasks.get(task_id)

    def get_tasks_by_team(self, team_id: str) -> list[AgentTask]:
        """Get all tasks for a team."""
        return [t for t in self._tasks.values() if t.team_id == team_id]

    def get_active_tasks(self) -> list[AgentTask]:
        """Get all currently running tasks."""
        return [
            t for t in self._tasks.values()
            if t.status in (TaskStatus.CREATED, TaskStatus.RUNNING)
        ]
