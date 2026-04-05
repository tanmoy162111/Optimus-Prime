"""ClientProfileDB — Tier 3 per-client profiles (Section 9.3).

SQLite-backed client profile management with auto-match by domain/IP,
confidence scoring, and engagement history tracking.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import logging
import sqlite3
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class ClientProfile:
    """Per-client persistent profile (Section 9.3)."""

    client_id: str
    name: str
    domains: list[str] = field(default_factory=list)
    ip_ranges: list[str] = field(default_factory=list)
    tech_stack: dict[str, Any] = field(default_factory=dict)
    recurring_weaknesses: list[dict[str, Any]] = field(default_factory=list)
    remediation_history: list[dict[str, Any]] = field(default_factory=list)
    report_preferences: dict[str, Any] = field(default_factory=dict)
    engagement_count: int = 0
    last_seen: str = ""


class ClientProfileDB:
    """Per-client profile database with auto-match and engagement tracking.

    Auto-match is suggestion only — operator always confirms before
    a profile is applied to an engagement.
    """

    def __init__(self, db_path: Path | None = None) -> None:
        self._db_path = db_path or Path("data/client_profiles/client_profiles.db")
        self._db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn: sqlite3.Connection | None = None
        self._lock = asyncio.Lock()

    async def initialize(self) -> None:
        """Create the client profiles table."""
        async with self._lock:
            self._conn = await asyncio.to_thread(
                sqlite3.connect, str(self._db_path), check_same_thread=False,
            )
            self._conn.row_factory = sqlite3.Row
            await asyncio.to_thread(
                self._conn.executescript,
                """
                CREATE TABLE IF NOT EXISTS client_profiles (
                    client_id   TEXT PRIMARY KEY,
                    name        TEXT NOT NULL,
                    domains     TEXT NOT NULL DEFAULT '[]',
                    ip_ranges   TEXT NOT NULL DEFAULT '[]',
                    tech_stack  TEXT NOT NULL DEFAULT '{}',
                    recurring_weaknesses TEXT NOT NULL DEFAULT '[]',
                    remediation_history  TEXT NOT NULL DEFAULT '[]',
                    report_preferences   TEXT NOT NULL DEFAULT '{}',
                    engagement_count     INTEGER NOT NULL DEFAULT 0,
                    last_seen   TEXT NOT NULL
                );
                CREATE INDEX IF NOT EXISTS idx_profiles_name
                    ON client_profiles(name);
                """,
            )
            await asyncio.to_thread(self._conn.commit)

    async def close(self) -> None:
        if self._conn:
            await asyncio.to_thread(self._conn.close)
            self._conn = None

    def _row_to_profile(self, row: sqlite3.Row) -> ClientProfile:
        return ClientProfile(
            client_id=row["client_id"],
            name=row["name"],
            domains=json.loads(row["domains"]),
            ip_ranges=json.loads(row["ip_ranges"]),
            tech_stack=json.loads(row["tech_stack"]),
            recurring_weaknesses=json.loads(row["recurring_weaknesses"]),
            remediation_history=json.loads(row["remediation_history"]),
            report_preferences=json.loads(row["report_preferences"]),
            engagement_count=row["engagement_count"],
            last_seen=row["last_seen"],
        )

    # ------------------------------------------------------------------
    # CRUD
    # ------------------------------------------------------------------

    async def save_profile(self, profile: ClientProfile) -> None:
        """Upsert a client profile."""
        if self._conn is None:
            await self.initialize()

        async with self._lock:
            await asyncio.to_thread(
                self._conn.execute,
                """
                INSERT OR REPLACE INTO client_profiles
                    (client_id, name, domains, ip_ranges, tech_stack,
                     recurring_weaknesses, remediation_history, report_preferences,
                     engagement_count, last_seen)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    profile.client_id,
                    profile.name,
                    json.dumps(profile.domains),
                    json.dumps(profile.ip_ranges),
                    json.dumps(profile.tech_stack),
                    json.dumps(profile.recurring_weaknesses),
                    json.dumps(profile.remediation_history),
                    json.dumps(profile.report_preferences),
                    profile.engagement_count,
                    profile.last_seen or datetime.now(timezone.utc).isoformat(),
                ),
            )
            await asyncio.to_thread(self._conn.commit)

    async def get_profile(self, client_id: str) -> ClientProfile | None:
        """Retrieve a client profile by ID."""
        if self._conn is None:
            await self.initialize()

        row = await asyncio.to_thread(
            lambda: self._conn.execute(
                "SELECT * FROM client_profiles WHERE client_id = ?",
                (client_id,),
            ).fetchone()
        )
        return self._row_to_profile(row) if row else None

    async def list_profiles(self) -> list[ClientProfile]:
        """List all client profiles."""
        if self._conn is None:
            await self.initialize()

        rows = await asyncio.to_thread(
            lambda: self._conn.execute("SELECT * FROM client_profiles").fetchall()
        )
        return [self._row_to_profile(row) for row in rows]

    # ------------------------------------------------------------------
    # Auto-Match
    # ------------------------------------------------------------------

    async def match_client(
        self, domain_or_ip: str,
    ) -> tuple[ClientProfile | None, float]:
        """Auto-match a domain or IP to an existing client profile.

        Returns (profile, confidence_score). Confidence:
          - 1.0: exact domain match
          - 0.9: subdomain match (query is subdomain of profile domain)
          - 0.85: IP in profile's CIDR range
          - 0.7: partial domain match (shared base domain)
          - 0.0: no match (returns None)

        This is a suggestion only — operator must confirm.
        """
        if self._conn is None:
            await self.initialize()

        profiles = await self.list_profiles()
        best_match: ClientProfile | None = None
        best_score: float = 0.0

        query_lower = domain_or_ip.strip().lower()

        for profile in profiles:
            score = self._compute_match_score(query_lower, profile)
            if score > best_score:
                best_score = score
                best_match = profile

        if best_score >= 0.7:
            return best_match, best_score
        return None, 0.0

    def _compute_match_score(self, query: str, profile: ClientProfile) -> float:
        """Compute match confidence for a query against a profile."""
        best = 0.0

        # Check domains
        for domain in profile.domains:
            domain_lower = domain.lower()
            if query == domain_lower:
                return 1.0  # Exact match
            if query.endswith("." + domain_lower):
                best = max(best, 0.9)  # Subdomain match
            elif domain_lower.endswith("." + query):
                best = max(best, 0.9)  # Reverse subdomain
            else:
                # Check shared base domain (e.g., api.acme.com vs acme.com)
                query_parts = query.split(".")
                domain_parts = domain_lower.split(".")
                if len(query_parts) >= 2 and len(domain_parts) >= 2:
                    if query_parts[-2:] == domain_parts[-2:]:
                        best = max(best, 0.7)

        # Check IP ranges
        try:
            query_ip = ipaddress.ip_address(query)
            for cidr in profile.ip_ranges:
                try:
                    network = ipaddress.ip_network(cidr, strict=False)
                    if query_ip in network:
                        best = max(best, 0.85)
                except ValueError:
                    # Try exact IP match
                    try:
                        if query_ip == ipaddress.ip_address(cidr):
                            best = max(best, 1.0)
                    except ValueError:
                        pass
        except ValueError:
            pass  # Query is not an IP

        return best

    # ------------------------------------------------------------------
    # Engagement Update
    # ------------------------------------------------------------------

    async def update_from_engagement(
        self,
        client_id: str,
        findings: list[dict[str, Any]] | None = None,
        tech_stack: dict[str, Any] | None = None,
    ) -> ClientProfile | None:
        """Update a client profile after an engagement completes."""
        profile = await self.get_profile(client_id)
        if profile is None:
            return None

        profile.engagement_count += 1
        profile.last_seen = datetime.now(timezone.utc).isoformat()

        if tech_stack:
            profile.tech_stack.update(tech_stack)

        if findings:
            # Add to recurring weaknesses (de-dup by title)
            existing_titles = {w.get("title") for w in profile.recurring_weaknesses}
            for f in findings:
                title = f.get("title", "")
                if title and title not in existing_titles:
                    profile.recurring_weaknesses.append({
                        "title": title,
                        "severity": f.get("severity", "info"),
                        "first_seen": f.get("found_at", datetime.now(timezone.utc).isoformat()),
                        "occurrences": 1,
                    })
                    existing_titles.add(title)
                elif title:
                    # Increment occurrences
                    for w in profile.recurring_weaknesses:
                        if w.get("title") == title:
                            w["occurrences"] = w.get("occurrences", 1) + 1
                            break

        await self.save_profile(profile)
        return profile
