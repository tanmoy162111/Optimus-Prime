"""ResearchDaemon — Nightly intelligence ingestion (Section 15.1).

Ingests 7 sources on a configurable schedule with independent token
budget tracking and incremental-only ingestion.
"""

from __future__ import annotations

import asyncio
import logging
import uuid
from datetime import datetime, timezone
from typing import Any, Callable, Awaitable

from backend.intelligence.research_kb import ResearchKB, ResearchKBEntry

logger = logging.getLogger(__name__)

# Default budget for research daemon (tokens)
DEFAULT_RESEARCH_BUDGET = 100_000

# Sources
NIGHTLY_SOURCES = ["nvd", "cisa_kev", "exploitdb", "github_poc", "attack", "blogs"]
WEEKLY_SOURCES = ["dark_web"]
ALL_SOURCES = NIGHTLY_SOURCES + WEEKLY_SOURCES


class ResearchBudgetTracker:
    """Independent token budget for the research daemon.

    Hard cap prevents runaway costs. Separate from session budget.
    """

    def __init__(self, budget: int = DEFAULT_RESEARCH_BUDGET) -> None:
        self._budget = budget
        self._used = 0

    @property
    def used(self) -> int:
        return self._used

    @property
    def remaining(self) -> int:
        return max(0, self._budget - self._used)

    @property
    def is_exhausted(self) -> bool:
        return self._used >= self._budget

    def record_usage(self, tokens: int) -> bool:
        """Record token usage. Returns False if budget exhausted."""
        if self._used + tokens > self._budget:
            logger.warning(
                "ResearchBudget: would exceed cap (%d + %d > %d)",
                self._used, tokens, self._budget,
            )
            return False
        self._used += tokens
        return True

    def reset(self) -> None:
        self._used = 0


class CronRegistry:
    """Simple cron-like scheduler for research tasks (Section 15.3)."""

    def __init__(self) -> None:
        self._entries: dict[str, dict[str, Any]] = {}

    def register(
        self,
        name: str,
        schedule: str,
        handler: Callable[..., Awaitable[Any]],
    ) -> None:
        """Register a cron entry.

        Args:
            name: Unique task name.
            schedule: Cron description (e.g., "nightly_0200", "weekly_sun_0300").
            handler: Async callable to execute.
        """
        self._entries[name] = {
            "schedule": schedule,
            "handler": handler,
            "last_run": None,
        }

    def get_entries(self) -> dict[str, dict[str, Any]]:
        return dict(self._entries)

    async def run(self, name: str) -> Any:
        """Manually trigger a registered task."""
        entry = self._entries.get(name)
        if entry is None:
            raise ValueError(f"Unknown cron entry: {name}")

        result = await entry["handler"]()
        entry["last_run"] = datetime.now(timezone.utc).isoformat()
        return result


class ResearchDaemon:
    """Nightly research intelligence daemon (Section 15.1).

    Ingests 7 sources with:
      - Independent token budget (RESEARCH_DAEMON_TOKEN_BUDGET)
      - Incremental ingestion (only new items since last run)
      - Cross-source deduplication via ResearchKB
      - EventBus notifications on research channel
    """

    def __init__(
        self,
        research_kb: ResearchKB,
        event_bus: Any = None,
        budget: ResearchBudgetTracker | None = None,
        source_adapters: dict[str, Callable[..., Awaitable[list[ResearchKBEntry]]]] | None = None,
    ) -> None:
        self._kb = research_kb
        self._event_bus = event_bus
        self._budget = budget or ResearchBudgetTracker()
        self._cron = CronRegistry()
        self._source_adapters = source_adapters or {}
        self._running = False

        # Register cron entries
        self._cron.register("nightly_research", "nightly_0200", self.run_nightly)
        self._cron.register("weekly_darkweb", "weekly_sun_0300", self.run_weekly)

    @property
    def cron(self) -> CronRegistry:
        return self._cron

    @property
    def budget(self) -> ResearchBudgetTracker:
        return self._budget

    def register_source(
        self,
        source_name: str,
        adapter: Callable[..., Awaitable[list[ResearchKBEntry]]],
    ) -> None:
        """Register a source adapter."""
        self._source_adapters[source_name] = adapter

    async def run_nightly(self) -> dict[str, Any]:
        """Execute nightly ingestion of 6 sources."""
        return await self._ingest_sources(NIGHTLY_SOURCES)

    async def run_weekly(self) -> dict[str, Any]:
        """Execute weekly dark web ingestion."""
        return await self._ingest_sources(WEEKLY_SOURCES)

    async def run_all(self) -> dict[str, Any]:
        """Run all sources (for manual trigger / testing)."""
        return await self._ingest_sources(ALL_SOURCES)

    async def _ingest_sources(self, sources: list[str]) -> dict[str, Any]:
        """Ingest entries from specified sources."""
        self._running = True
        results: dict[str, Any] = {
            "started_at": datetime.now(timezone.utc).isoformat(),
            "sources": {},
            "total_ingested": 0,
            "total_deduplicated": 0,
            "budget_used": 0,
            "budget_exhausted": False,
        }

        initial_budget = self._budget.used

        for source in sources:
            if self._budget.is_exhausted:
                logger.warning("ResearchDaemon: budget exhausted, stopping ingestion")
                results["budget_exhausted"] = True
                break

            adapter = self._source_adapters.get(source)
            if adapter is None:
                logger.debug("ResearchDaemon: no adapter for source %s, skipping", source)
                results["sources"][source] = {"status": "skipped", "reason": "no adapter"}
                continue

            try:
                # Get last run time for incremental ingestion
                last_run = await self._kb.get_last_run(source)

                # Simulate token usage for source fetch (per-source budget tracking)
                estimated_tokens = 500  # Estimation per source
                if not self._budget.record_usage(estimated_tokens):
                    results["sources"][source] = {"status": "skipped", "reason": "budget_exhausted"}
                    results["budget_exhausted"] = True
                    break

                # Fetch entries from source adapter
                entries = await adapter(last_run)

                ingested = 0
                deduplicated = 0
                for entry in entries:
                    if not entry.entry_id:
                        entry.entry_id = f"{source}-{uuid.uuid4().hex[:12]}"

                    kb_count_before = await self._kb.count()
                    await self._kb.ingest(entry)
                    kb_count_after = await self._kb.count()

                    if kb_count_after > kb_count_before:
                        ingested += 1
                    else:
                        deduplicated += 1

                # Update last run
                now = datetime.now(timezone.utc).isoformat()
                await self._kb.set_last_run(source, now)

                # Publish events
                if ingested > 0 and self._event_bus:
                    event_type = self._source_event_type(source)
                    await self._event_bus.publish(
                        channel="research",
                        event_type=event_type,
                        payload={
                            "source": source,
                            "ingested": ingested,
                            "deduplicated": deduplicated,
                        },
                    )

                results["sources"][source] = {
                    "status": "completed",
                    "ingested": ingested,
                    "deduplicated": deduplicated,
                }
                results["total_ingested"] += ingested
                results["total_deduplicated"] += deduplicated

            except Exception as exc:
                logger.error("ResearchDaemon: source %s failed: %s", source, exc)
                results["sources"][source] = {"status": "error", "error": str(exc)}

        results["completed_at"] = datetime.now(timezone.utc).isoformat()
        results["budget_used"] = self._budget.used - initial_budget
        self._running = False

        return results

    @staticmethod
    def _source_event_type(source: str) -> str:
        """Map source to EventBus event type."""
        mapping = {
            "nvd": "NEW_CVE_ALERT",
            "cisa_kev": "NEW_CVE_ALERT",
            "exploitdb": "POC_DETECTED",
            "github_poc": "POC_DETECTED",
            "attack": "TECHNIQUE_DELTA",
            "blogs": "NEW_CVE_ALERT",
            "dark_web": "DARK_WEB_ALERT",
        }
        return mapping.get(source, "NEW_CVE_ALERT")
