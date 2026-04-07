"""Web intelligence source adapters for ResearchDaemon (Section 15.1).

Each adapter implements:
    async def fetch(last_run: str | None) -> list[ResearchKBEntry]

Adapters use only public free APIs — no API keys required.
"""
from __future__ import annotations

import asyncio
import csv
import io
import logging
import re
import uuid
import xml.etree.ElementTree as ET
from datetime import datetime, timezone
from typing import Any

import httpx

from backend.intelligence.research_kb import ResearchKBEntry

logger = logging.getLogger(__name__)

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)

_DEFAULT_TIMEOUT = 30.0
_HEADERS = {"User-Agent": "Optimus-Intel-Daemon/2.0 (security research)"}


def _make_client(timeout: float = _DEFAULT_TIMEOUT) -> httpx.AsyncClient:
    return httpx.AsyncClient(timeout=timeout, headers=_HEADERS, follow_redirects=True)


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# NVDAdapter — NIST National Vulnerability Database
# ---------------------------------------------------------------------------

class NVDAdapter:
    """Fetches CVE data from NVD REST API v2.

    Uses incremental ingestion via lastModStartDate when last_run is provided.
    Retries once on 429 (rate limit) with a 6-second sleep.
    """

    _URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    async def fetch(self, last_run: str | None) -> list[ResearchKBEntry]:
        params: dict[str, Any] = {"resultsPerPage": 100}
        if last_run:
            ts = last_run[:19] + ".000"
            params["lastModStartDate"] = ts
            params["lastModEndDate"] = _now_iso()[:19] + ".000"

        try:
            async with _make_client(timeout=60.0) as client:
                resp = await client.get(self._URL, params=params)

                if resp.status_code == 429:
                    logger.warning("NVDAdapter: rate limited, sleeping 6s then retrying")
                    await asyncio.sleep(6)
                    resp = await client.get(self._URL, params=params)

                if resp.status_code != 200:
                    logger.warning("NVDAdapter: HTTP %d", resp.status_code)
                    return []

                data = resp.json()
        except Exception as exc:
            logger.warning("NVDAdapter: fetch failed: %s", exc)
            return []

        entries: list[ResearchKBEntry] = []
        for vuln in data.get("vulnerabilities", []):
            cve = vuln.get("cve", {})
            cve_id = cve.get("id")
            if not cve_id:
                continue

            desc = ""
            for d in cve.get("descriptions", []):
                if d.get("lang") == "en":
                    desc = d.get("value", "")
                    break

            cvss = None
            metrics = cve.get("metrics", {})
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                if key in metrics and metrics[key]:
                    cvss = metrics[key][0].get("cvssData", {}).get("baseScore")
                    break

            poc_url = None

            entries.append(ResearchKBEntry(
                entry_id=f"nvd-{cve_id}",
                source="nvd",
                cve_id=cve_id,
                description=desc,
                cvss_score=cvss,
                poc_url=poc_url,
                raw_data={"nvd_id": cve_id},
            ))

        logger.info("NVDAdapter: fetched %d CVEs", len(entries))
        return entries


# ---------------------------------------------------------------------------
# CISAKEVAdapter — CISA Known Exploited Vulnerabilities catalog
# ---------------------------------------------------------------------------

class CISAKEVAdapter:
    """Fetches the CISA KEV catalog (full JSON, dedup by CVE ID in KB)."""

    _URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

    async def fetch(self, last_run: str | None) -> list[ResearchKBEntry]:
        try:
            async with _make_client() as client:
                resp = await client.get(self._URL)
                if resp.status_code != 200:
                    logger.warning("CISAKEVAdapter: HTTP %d", resp.status_code)
                    return []
                data = resp.json()
        except Exception as exc:
            logger.warning("CISAKEVAdapter: fetch failed: %s", exc)
            return []

        entries: list[ResearchKBEntry] = []
        for vuln in data.get("vulnerabilities", []):
            cve_id = vuln.get("cveID")
            if not cve_id:
                continue

            desc_parts = [
                vuln.get("vendorProject", ""),
                vuln.get("product", ""),
                vuln.get("vulnerabilityName", ""),
                vuln.get("shortDescription", ""),
            ]
            desc = " — ".join(p for p in desc_parts if p)

            entries.append(ResearchKBEntry(
                entry_id=f"cisa-{cve_id}",
                source="cisa_kev",
                cve_id=cve_id,
                description=desc,
                raw_data={
                    "ransomware": vuln.get("knownRansomwareCampaignUse", ""),
                    "due_date": vuln.get("dueDate", ""),
                },
            ))

        logger.info("CISAKEVAdapter: fetched %d KEV entries", len(entries))
        return entries


# ---------------------------------------------------------------------------
# GitHubPoCAdapter — GitHub repository search for CVE PoCs
# ---------------------------------------------------------------------------

class GitHubPoCAdapter:
    """Searches GitHub for repositories tagged as CVE proof-of-concept exploits."""

    _URL = "https://api.github.com/search/repositories"

    async def fetch(self, last_run: str | None) -> list[ResearchKBEntry]:
        params = {
            "q": "CVE poc exploit in:name,description",
            "sort": "updated",
            "order": "desc",
            "per_page": 30,
        }

        try:
            async with _make_client() as client:
                resp = await client.get(self._URL, params=params)
                if resp.status_code == 403:
                    logger.warning("GitHubPoCAdapter: rate limited (unauthenticated)")
                    return []
                if resp.status_code != 200:
                    logger.warning("GitHubPoCAdapter: HTTP %d", resp.status_code)
                    return []
                data = resp.json()
        except Exception as exc:
            logger.warning("GitHubPoCAdapter: fetch failed: %s", exc)
            return []

        entries: list[ResearchKBEntry] = []
        for repo in data.get("items", []):
            name = repo.get("full_name", "")
            desc = repo.get("description") or name
            html_url = repo.get("html_url", "")

            combined = f"{name} {desc}"
            cve_match = _CVE_RE.search(combined)
            cve_id = cve_match.group(0).upper() if cve_match else None

            entries.append(ResearchKBEntry(
                entry_id=f"ghpoc-{uuid.uuid4().hex[:12]}",
                source="github_poc",
                cve_id=cve_id,
                description=f"GitHub PoC: {desc}",
                poc_url=html_url,
                raw_data={"repo": name, "stars": repo.get("stargazers_count", 0)},
            ))

            await asyncio.sleep(0.1)

        logger.info("GitHubPoCAdapter: fetched %d PoC repos", len(entries))
        return entries


# ---------------------------------------------------------------------------
# MITREAttackAdapter — MITRE ATT&CK STIX enterprise bundle
# ---------------------------------------------------------------------------

class MITREAttackAdapter:
    """Fetches MITRE ATT&CK enterprise STIX bundle from GitHub.

    Parses attack-pattern objects only. Runs weekly (large file).
    """

    _URL = (
        "https://raw.githubusercontent.com/mitre/cti/master/"
        "enterprise-attack/enterprise-attack.json"
    )

    async def fetch(self, last_run: str | None) -> list[ResearchKBEntry]:
        try:
            async with _make_client(timeout=120.0) as client:
                resp = await client.get(self._URL)
                if resp.status_code != 200:
                    logger.warning("MITREAttackAdapter: HTTP %d", resp.status_code)
                    return []
                data = resp.json()
        except Exception as exc:
            logger.warning("MITREAttackAdapter: fetch failed: %s", exc)
            return []

        entries: list[ResearchKBEntry] = []
        for obj in data.get("objects", []):
            if obj.get("type") != "attack-pattern":
                continue
            if obj.get("revoked"):
                continue

            name = obj.get("name", "")
            desc = obj.get("description", "")[:500]

            technique_id = None
            for ref in obj.get("external_references", []):
                if ref.get("source_name") == "mitre-attack":
                    technique_id = ref.get("external_id")
                    break

            if not technique_id:
                continue

            entries.append(ResearchKBEntry(
                entry_id=f"attack-{technique_id}",
                source="attack",
                technique_id=technique_id,
                description=f"{name}: {desc}",
                raw_data={"technique": technique_id, "name": name},
            ))

        logger.info("MITREAttackAdapter: fetched %d ATT&CK techniques", len(entries))
        return entries


# ---------------------------------------------------------------------------
# BlogsAdapter — RSS feeds from security blogs
# ---------------------------------------------------------------------------

_RSS_FEEDS = [
    "https://krebsonsecurity.com/feed/",
    "https://www.bleepingcomputer.com/feed/",
    "https://www.rapid7.com/blog/rss.xml",
    "https://isc.sans.edu/rssfeed.xml",
]

_NS = {
    "atom": "http://www.w3.org/2005/Atom",
    "content": "http://purl.org/rss/1.0/modules/content/",
}


class BlogsAdapter:
    """Fetches security blog RSS feeds and extracts CVE-mentioning posts."""

    async def fetch(self, last_run: str | None) -> list[ResearchKBEntry]:
        entries: list[ResearchKBEntry] = []
        headers = dict(_HEADERS)
        if last_run:
            headers["If-Modified-Since"] = last_run

        try:
            async with _make_client() as client:
                for feed_url in _RSS_FEEDS:
                    try:
                        resp = await client.get(feed_url, headers=headers)
                        if resp.status_code == 304:
                            continue
                        if resp.status_code != 200:
                            logger.warning("BlogsAdapter: %s returned %d", feed_url, resp.status_code)
                            continue

                        feed_entries = self._parse_rss(resp.text, feed_url)
                        entries.extend(feed_entries)

                    except Exception as exc:
                        logger.warning("BlogsAdapter: failed to fetch %s: %s", feed_url, exc)

            logger.info("BlogsAdapter: fetched %d blog entries", len(entries))
        except Exception as exc:
            logger.warning("BlogsAdapter: client creation/initialization failed: %s", exc)
            return []

        return entries

    def _parse_rss(self, xml_text: str, feed_url: str) -> list[ResearchKBEntry]:
        """Parse RSS XML and return entries that mention CVEs."""
        results: list[ResearchKBEntry] = []
        try:
            root = ET.fromstring(xml_text)
        except ET.ParseError as exc:
            logger.warning("BlogsAdapter: XML parse error for %s: %s", feed_url, exc)
            return []

        items = root.findall(".//item") or root.findall(".//entry")
        for item in items:
            title_el = item.find("title")
            link_el = item.find("link")
            desc_el_found = item.find("description")
            desc_el = desc_el_found if desc_el_found is not None else item.find("summary")

            title = title_el.text or "" if title_el is not None else ""
            link = (link_el.text or link_el.get("href", "")) if link_el is not None else ""
            desc = desc_el.text or "" if desc_el is not None else ""

            combined = f"{title} {desc}"
            cve_matches = _CVE_RE.findall(combined)
            if not cve_matches:
                continue

            cve_id = cve_matches[0].upper()
            results.append(ResearchKBEntry(
                entry_id=f"blog-{uuid.uuid4().hex[:12]}",
                source="blogs",
                cve_id=cve_id,
                description=f"{title}: {desc[:300]}",
                poc_url=link or None,
                raw_data={"feed": feed_url, "all_cves": list(set(m.upper() for m in cve_matches))},
            ))

        return results


# ---------------------------------------------------------------------------
# ExploitDBAdapter — ExploitDB CSV dump (GitLab)
# ---------------------------------------------------------------------------

class ExploitDBAdapter:
    """Fetches ExploitDB files_exploits.csv from GitLab.

    Only imports entries that have CVE codes (codes column).
    No Kali SSH dependency — runs independently of Kali availability.
    """

    _URL = (
        "https://gitlab.com/exploit-database/exploitdb/-/raw/main/files_exploits.csv"
    )
    _EDB_BASE = "https://www.exploit-db.com/exploits/"

    async def fetch(self, last_run: str | None) -> list[ResearchKBEntry]:
        try:
            async with _make_client(timeout=60.0) as client:
                resp = await client.get(self._URL)
                if resp.status_code != 200:
                    logger.warning("ExploitDBAdapter: HTTP %d", resp.status_code)
                    return []
                csv_text = resp.text
        except Exception as exc:
            logger.warning("ExploitDBAdapter: fetch failed: %s", exc)
            return []

        return self._parse_csv(csv_text)

    def _parse_csv(self, csv_text: str) -> list[ResearchKBEntry]:
        """Parse ExploitDB CSV, return only CVE-tagged entries."""
        entries: list[ResearchKBEntry] = []
        reader = csv.DictReader(io.StringIO(csv_text))

        for row in reader:
            codes = row.get("codes", "").strip()
            if not codes:
                continue

            cve_ids = [c.strip() for c in codes.split(";") if c.strip().upper().startswith("CVE-")]
            if not cve_ids:
                continue

            edb_id = row.get("id", "").strip()
            desc = row.get("description", "").strip()
            platform = row.get("platform", "").strip()
            poc_url = f"{self._EDB_BASE}{edb_id}" if edb_id else None

            primary_cve = cve_ids[0].upper()

            entries.append(ResearchKBEntry(
                entry_id=f"edb-{edb_id or uuid.uuid4().hex[:8]}",
                source="exploitdb",
                cve_id=primary_cve,
                description=f"ExploitDB {edb_id}: {desc}",
                poc_url=poc_url,
                affected_products=[platform] if platform else [],
                raw_data={"edb_id": edb_id, "all_cves": cve_ids, "platform": platform},
            ))

        logger.info("ExploitDBAdapter: parsed %d CVE-tagged exploits", len(entries))
        return entries


# ---------------------------------------------------------------------------
# DarkWebAdapter — Tor/Ahmia dark web search
# ---------------------------------------------------------------------------

_DARK_WEB_QUERIES = [
    "CVE exploit 2024 0day vulnerability",
    "critical exploit remote code execution",
    "zero day vulnerability database leak",
]


class DarkWebAdapter:
    """Queries Ahmia via Tor for dark web threat intel.

    Runs weekly (slow, unreliable). Returns [] if Tor is unavailable.
    At most 3 queries per run to stay within budget.
    """

    def __init__(self, tor_backend: Any) -> None:
        self._tor = tor_backend

    async def fetch(self, last_run: str | None) -> list[ResearchKBEntry]:
        from backend.tools.backends.tor_socks5 import TorUnavailableError
        entries: list[ResearchKBEntry] = []

        for query in _DARK_WEB_QUERIES:
            try:
                text = await self._tor.query(query)
                if not text:
                    continue

                cve_ids = list(set(m.upper() for m in _CVE_RE.findall(text)))

                if cve_ids:
                    for cve_id in cve_ids[:5]:
                        entries.append(ResearchKBEntry(
                            entry_id=f"darkweb-{uuid.uuid4().hex[:12]}",
                            source="dark_web",
                            cve_id=cve_id,
                            description=f"Dark web reference: {text[:200]}",
                            raw_data={"query": query, "all_cves": cve_ids},
                        ))
                else:
                    entries.append(ResearchKBEntry(
                        entry_id=f"darkweb-{uuid.uuid4().hex[:12]}",
                        source="dark_web",
                        description=f"Dark web intel [{query}]: {text[:300]}",
                        raw_data={"query": query},
                    ))

            except TorUnavailableError as exc:
                logger.warning("DarkWebAdapter: Tor unavailable: %s", exc)
                return []
            except Exception as exc:
                logger.warning("DarkWebAdapter: query '%s' failed: %s", query, exc)

        logger.info("DarkWebAdapter: fetched %d dark web entries", len(entries))
        return entries
