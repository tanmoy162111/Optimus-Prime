"""LocalSubprocess backend stub — direct subprocess execution."""

from __future__ import annotations

from typing import Any


class LocalSubprocessBackend:
    """Local subprocess backend for file ops, search, report generation.

    Stub — implementation in M1.
    """

    async def execute(self, tool_name: str, tool_input: dict[str, Any], tool_spec: Any) -> Any:
        return {"status": "stub", "tool": tool_name}
