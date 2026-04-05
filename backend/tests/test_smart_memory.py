"""Tests for SmartMemory — Tier 2 semantic memory (M3).

Verifies top-3 relevance on all 10 test queries, adaptive learning,
and campaign intelligence using mock embeddings with controlled similarity.
"""

from __future__ import annotations

import math
import pytest

from backend.memory.smart_memory import SmartMemory, _cosine_similarity


# ---------------------------------------------------------------------------
# Mock embedding function — deterministic, controllable similarity
# ---------------------------------------------------------------------------

# Category-based embedding: each category has a distinct "direction"
CATEGORY_VECTORS = {
    "sql_injection": [1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0],
    "xss":           [0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0],
    "open_port":     [0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0],
    "tls_issue":     [0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0, 0.0],
    "credential":    [0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0, 0.0],
    "cloud":         [0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0, 0.0],
    "endpoint":      [0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0, 0.0],
    "default":       [0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 0.0, 1.0],
}

# Keywords that map to categories
KEYWORD_MAP = {
    "sql": "sql_injection", "injection": "sql_injection", "sqli": "sql_injection",
    "xss": "xss", "cross-site": "xss", "script": "xss",
    "port": "open_port", "open": "open_port", "nmap": "open_port", "service": "open_port",
    "tls": "tls_issue", "ssl": "tls_issue", "certificate": "tls_issue",
    "credential": "credential", "password": "credential", "secret": "credential", "token": "credential",
    "cloud": "cloud", "aws": "cloud", "s3": "cloud", "misconfiguration": "cloud",
    "endpoint": "endpoint", "edr": "endpoint", "privilege": "endpoint",
}


def _mock_embed(text: str) -> list[float]:
    """Deterministic embedding based on keyword matching."""
    text_lower = text.lower()
    vec = [0.0] * 8

    for keyword, category in KEYWORD_MAP.items():
        if keyword in text_lower:
            cat_vec = CATEGORY_VECTORS[category]
            for i, v in enumerate(cat_vec):
                vec[i] += v

    # Add small noise based on text hash for differentiation
    import hashlib
    h = hashlib.md5(text.encode()).digest()
    for i in range(min(8, len(h))):
        vec[i] += h[i] / 2550.0  # Tiny noise

    # Normalize
    norm = math.sqrt(sum(x * x for x in vec))
    if norm > 0:
        vec = [x / norm for x in vec]
    else:
        vec = CATEGORY_VECTORS["default"][:]

    return vec


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
async def smart_memory(tmp_path):
    sm = SmartMemory(
        db_path=tmp_path / "test_memory.db",
        embedding_fn=_mock_embed,
    )
    await sm.initialize()
    yield sm
    await sm.close()


# ---------------------------------------------------------------------------
# Test data: 20 findings across categories
# ---------------------------------------------------------------------------

FINDINGS = [
    ("f01", "SQL injection in login form parameter username"),
    ("f02", "SQL injection in search API endpoint"),
    ("f03", "Blind SQL injection via order-by parameter"),
    ("f04", "Reflected XSS in search bar input"),
    ("f05", "Stored XSS in comment field"),
    ("f06", "Open port 22 SSH service detected"),
    ("f07", "Open port 3306 MySQL service detected"),
    ("f08", "TLS certificate expired on api.example.com"),
    ("f09", "Weak TLS cipher suite SSLv3 detected"),
    ("f10", "Hardcoded credential found: AWS access key"),
    ("f11", "Exposed API token in public repository"),
    ("f12", "Cloud S3 bucket publicly accessible"),
    ("f13", "AWS security group allows 0.0.0.0/0 on port 22"),
    ("f14", "Endpoint EDR bypass via DLL sideloading"),
    ("f15", "Privilege escalation via unquoted service path"),
    ("f16", "SQL injection in admin panel"),
    ("f17", "XSS via DOM manipulation"),
    ("f18", "Open port 80 HTTP service"),
    ("f19", "TLS SSL certificate chain incomplete"),
    ("f20", "Password hash stored in plaintext"),
]


# ---------------------------------------------------------------------------
# 10 test queries — each must return top-3 relevant
# ---------------------------------------------------------------------------

TEST_QUERIES = [
    {
        "query": "SQL injection vulnerabilities",
        "expected_category": "sql_injection",
        "expected_ids": {"f01", "f02", "f03", "f16"},
    },
    {
        "query": "XSS cross-site scripting findings",
        "expected_category": "xss",
        "expected_ids": {"f04", "f05", "f17"},
    },
    {
        "query": "Open port service detection nmap",
        "expected_category": "open_port",
        "expected_ids": {"f06", "f07", "f18"},
    },
    {
        "query": "TLS SSL certificate issues",
        "expected_category": "tls_issue",
        "expected_ids": {"f08", "f09", "f19"},
    },
    {
        "query": "Credential and secret exposure",
        "expected_category": "credential",
        "expected_ids": {"f10", "f11", "f20"},
    },
    {
        "query": "Cloud AWS misconfiguration",
        "expected_category": "cloud",
        "expected_ids": {"f12", "f13"},
    },
    {
        "query": "Endpoint EDR bypass and privilege escalation",
        "expected_category": "endpoint",
        "expected_ids": {"f14", "f15"},
    },
    {
        "query": "SQL injection in admin panel",
        "expected_category": "sql_injection",
        "expected_ids": {"f01", "f02", "f03", "f16"},
    },
    {
        "query": "Password and token secret leak",
        "expected_category": "credential",
        "expected_ids": {"f10", "f11", "f20"},
    },
    {
        "query": "S3 cloud bucket misconfiguration AWS",
        "expected_category": "cloud",
        "expected_ids": {"f12", "f13"},
    },
]


class TestSmartMemorySemanticSearch:
    """Validate top-3 relevance on all 10 test queries (M3 AC #1)."""

    @pytest.mark.asyncio
    async def test_store_and_search_all_findings(self, smart_memory):
        """Store 20 findings and verify basic search works."""
        for fid, text in FINDINGS:
            await smart_memory.store_finding(fid, text)

        results = await smart_memory.search("SQL injection", top_k=3)
        assert len(results) == 3
        assert results[0]["similarity"] > 0

    @pytest.mark.asyncio
    async def test_top3_relevance_all_10_queries(self, smart_memory):
        """All 10 test queries must return top-3 results from expected category."""
        # Store all findings
        for fid, text in FINDINGS:
            await smart_memory.store_finding(fid, text)

        passed = 0
        for i, tq in enumerate(TEST_QUERIES):
            results = await smart_memory.search(tq["query"], top_k=3)
            result_ids = {r["finding_id"] for r in results}

            # At least 1 result from expected IDs must be in top-3
            overlap = result_ids & tq["expected_ids"]
            if overlap:
                passed += 1
            else:
                # Log for debugging but don't fail individual query
                print(f"Query {i}: '{tq['query']}' — got {result_ids}, expected overlap with {tq['expected_ids']}")

        assert passed == 10, (
            f"Only {passed}/10 queries returned relevant top-3 results"
        )

    @pytest.mark.asyncio
    async def test_similarity_ordering(self, smart_memory):
        """Results should be ordered by descending similarity."""
        for fid, text in FINDINGS:
            await smart_memory.store_finding(fid, text)

        results = await smart_memory.search("SQL injection", top_k=5)
        sims = [r["similarity"] for r in results]
        assert sims == sorted(sims, reverse=True)

    @pytest.mark.asyncio
    async def test_empty_search(self, smart_memory):
        """Search on empty database returns empty list."""
        results = await smart_memory.search("anything")
        assert results == []

    @pytest.mark.asyncio
    async def test_store_with_metadata(self, smart_memory):
        """Findings with metadata are stored and returned correctly."""
        await smart_memory.store_finding(
            "f-meta", "SQL injection test",
            metadata={"severity": "high", "target": "10.0.0.1"},
        )
        results = await smart_memory.search("SQL injection")
        assert len(results) == 1
        assert results[0]["metadata"]["severity"] == "high"


class TestSmartMemoryAdaptiveLearning:
    """Validate tool effectiveness tracking (AdaptiveLearning)."""

    @pytest.mark.asyncio
    async def test_store_and_retrieve_tool_effectiveness(self, smart_memory):
        """Tool effectiveness records are stored and retrievable."""
        await smart_memory.store_tool_effectiveness("nuclei", "web_app", 0.85, finding_count=12)
        await smart_memory.store_tool_effectiveness("nikto", "web_app", 0.60, finding_count=5)
        await smart_memory.store_tool_effectiveness("nmap", "web_app", 0.40, finding_count=3)

        best = await smart_memory.get_best_tools("web_app", top_k=3)
        assert len(best) == 3
        assert best[0]["tool"] == "nuclei"
        assert best[0]["avg_success_rate"] > best[1]["avg_success_rate"]

    @pytest.mark.asyncio
    async def test_adaptive_learning_averages(self, smart_memory):
        """Multiple records for same tool are averaged."""
        await smart_memory.store_tool_effectiveness("nuclei", "api", 0.90)
        await smart_memory.store_tool_effectiveness("nuclei", "api", 0.70)

        best = await smart_memory.get_best_tools("api")
        assert len(best) == 1
        assert abs(best[0]["avg_success_rate"] - 0.80) < 0.01


class TestSmartMemoryCampaignIntelligence:
    """Validate cross-engagement pattern detection."""

    @pytest.mark.asyncio
    async def test_detect_systemic_weakness(self, smart_memory):
        """Weakness across 3+ engagements flagged as systemic."""
        # Same weakness across 3 engagements
        for eng in ["eng-1", "eng-2", "eng-3"]:
            await smart_memory.store_finding(
                f"sqli-{eng}", "SQL injection in login form",
                client_id="client-acme", engagement_id=eng,
            )

        systemic = await smart_memory.detect_systemic("client-acme", min_occurrences=3)
        assert len(systemic) == 1
        assert systemic[0]["engagement_count"] == 3

    @pytest.mark.asyncio
    async def test_no_systemic_below_threshold(self, smart_memory):
        """Weakness in only 2 engagements not flagged."""
        for eng in ["eng-1", "eng-2"]:
            await smart_memory.store_finding(
                f"xss-{eng}", "XSS in search bar",
                client_id="client-beta", engagement_id=eng,
            )

        systemic = await smart_memory.detect_systemic("client-beta", min_occurrences=3)
        assert len(systemic) == 0
