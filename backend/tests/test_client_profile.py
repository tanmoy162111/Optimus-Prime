"""Tests for ClientProfileDB — Tier 3 client profiles (M3).

Validates auto-match accuracy >= 90% on test dataset of 20 clients.
"""

from __future__ import annotations

import pytest

from backend.memory.client_profile import ClientProfile, ClientProfileDB


# ---------------------------------------------------------------------------
# Test dataset: 20 clients
# ---------------------------------------------------------------------------

TEST_PROFILES = [
    ClientProfile(client_id="c01", name="Acme Corp", domains=["acme.com", "api.acme.com"], ip_ranges=["10.0.1.0/24"]),
    ClientProfile(client_id="c02", name="Beta Inc", domains=["beta.io", "app.beta.io"], ip_ranges=["172.16.0.0/16"]),
    ClientProfile(client_id="c03", name="Gamma Ltd", domains=["gamma.org"], ip_ranges=["192.168.1.0/24"]),
    ClientProfile(client_id="c04", name="Delta Systems", domains=["delta.net", "mail.delta.net"], ip_ranges=["10.10.0.0/16"]),
    ClientProfile(client_id="c05", name="Epsilon Tech", domains=["epsilon.tech"], ip_ranges=["203.0.113.0/24"]),
    ClientProfile(client_id="c06", name="Zeta Group", domains=["zeta.co", "portal.zeta.co"], ip_ranges=["198.51.100.0/24"]),
    ClientProfile(client_id="c07", name="Eta Partners", domains=["eta-partners.com"], ip_ranges=["10.20.0.0/16"]),
    ClientProfile(client_id="c08", name="Theta Labs", domains=["thetalabs.ai", "api.thetalabs.ai"], ip_ranges=["172.20.0.0/16"]),
    ClientProfile(client_id="c09", name="Iota Security", domains=["iota-sec.com"], ip_ranges=["10.30.0.0/16"]),
    ClientProfile(client_id="c10", name="Kappa Finance", domains=["kappa.finance", "trade.kappa.finance"], ip_ranges=["192.168.10.0/24"]),
    ClientProfile(client_id="c11", name="Lambda Corp", domains=["lambda-corp.com"], ip_ranges=["10.40.0.0/16"]),
    ClientProfile(client_id="c12", name="Mu Digital", domains=["mu.digital", "shop.mu.digital"], ip_ranges=["172.30.0.0/16"]),
    ClientProfile(client_id="c13", name="Nu Analytics", domains=["nu-analytics.io"], ip_ranges=["10.50.0.0/16"]),
    ClientProfile(client_id="c14", name="Xi Robotics", domains=["xi-robotics.com", "api.xi-robotics.com"], ip_ranges=["192.168.20.0/24"]),
    ClientProfile(client_id="c15", name="Omicron Health", domains=["omicron.health"], ip_ranges=["10.60.0.0/16"]),
    ClientProfile(client_id="c16", name="Pi Engineering", domains=["pi-eng.net"], ip_ranges=["172.25.0.0/16"]),
    ClientProfile(client_id="c17", name="Rho Media", domains=["rho-media.com", "cdn.rho-media.com"], ip_ranges=["198.18.0.0/16"]),
    ClientProfile(client_id="c18", name="Sigma Defense", domains=["sigma-def.gov"], ip_ranges=["10.70.0.0/16"]),
    ClientProfile(client_id="c19", name="Tau Consulting", domains=["tau-consulting.biz"], ip_ranges=["192.168.30.0/24"]),
    ClientProfile(client_id="c20", name="Upsilon Games", domains=["upsilon.games", "play.upsilon.games"], ip_ranges=["10.80.0.0/16"]),
]

# 20 test queries with expected client_id matches
MATCH_QUERIES = [
    ("acme.com", "c01"),                    # Exact domain
    ("api.acme.com", "c01"),                # Exact subdomain
    ("staging.acme.com", "c01"),            # Subdomain match
    ("beta.io", "c02"),                     # Exact domain
    ("10.0.1.50", "c01"),                   # IP in range
    ("172.16.5.10", "c02"),                 # IP in range
    ("gamma.org", "c03"),                   # Exact domain
    ("mail.delta.net", "c04"),              # Exact subdomain
    ("203.0.113.100", "c05"),               # IP in range
    ("portal.zeta.co", "c06"),              # Exact subdomain
    ("eta-partners.com", "c07"),            # Exact domain
    ("api.thetalabs.ai", "c08"),            # Exact subdomain
    ("iota-sec.com", "c09"),               # Exact domain
    ("trade.kappa.finance", "c10"),         # Exact subdomain
    ("10.40.100.1", "c11"),                 # IP in range
    ("shop.mu.digital", "c12"),             # Exact subdomain
    ("xi-robotics.com", "c14"),             # Exact domain
    ("10.60.0.1", "c15"),                   # IP in range
    ("cdn.rho-media.com", "c17"),           # Exact subdomain
    ("play.upsilon.games", "c20"),          # Exact subdomain
]


@pytest.fixture
async def profile_db(tmp_path):
    db = ClientProfileDB(db_path=tmp_path / "test_profiles.db")
    await db.initialize()
    for profile in TEST_PROFILES:
        await db.save_profile(profile)
    yield db
    await db.close()


class TestClientProfileAutoMatch:
    """Validate auto-match accuracy >= 90% on 20-client test dataset (M3 AC #2)."""

    @pytest.mark.asyncio
    async def test_auto_match_accuracy_90_percent(self, profile_db):
        """At least 18/20 correct matches (>= 90% accuracy)."""
        correct = 0
        failures = []

        for query, expected_id in MATCH_QUERIES:
            profile, confidence = await profile_db.match_client(query)
            if profile and profile.client_id == expected_id:
                correct += 1
            else:
                actual_id = profile.client_id if profile else None
                failures.append((query, expected_id, actual_id, confidence))

        accuracy = correct / len(MATCH_QUERIES) * 100
        assert accuracy >= 90.0, (
            f"Auto-match accuracy {accuracy:.1f}% < 90% — "
            f"{len(failures)} failures: {failures}"
        )

    @pytest.mark.asyncio
    async def test_exact_domain_confidence_1_0(self, profile_db):
        """Exact domain match should return confidence 1.0."""
        profile, confidence = await profile_db.match_client("acme.com")
        assert profile is not None
        assert profile.client_id == "c01"
        assert confidence == 1.0

    @pytest.mark.asyncio
    async def test_subdomain_confidence_0_9(self, profile_db):
        """Subdomain match should return confidence 0.9."""
        profile, confidence = await profile_db.match_client("staging.acme.com")
        assert profile is not None
        assert profile.client_id == "c01"
        assert confidence == 0.9

    @pytest.mark.asyncio
    async def test_ip_range_confidence_0_85(self, profile_db):
        """IP in CIDR range match should return confidence 0.85."""
        profile, confidence = await profile_db.match_client("10.0.1.50")
        assert profile is not None
        assert profile.client_id == "c01"
        assert confidence == 0.85

    @pytest.mark.asyncio
    async def test_no_match_returns_none(self, profile_db):
        """Unknown domain returns (None, 0.0)."""
        profile, confidence = await profile_db.match_client("unknown-domain.xyz")
        assert profile is None
        assert confidence == 0.0

    @pytest.mark.asyncio
    async def test_no_match_random_ip(self, profile_db):
        """Random IP not in any range returns (None, 0.0)."""
        profile, confidence = await profile_db.match_client("8.8.8.8")
        assert profile is None
        assert confidence == 0.0


class TestClientProfileCRUD:
    """Basic CRUD operations on client profiles."""

    @pytest.mark.asyncio
    async def test_save_and_retrieve(self, profile_db):
        profile = await profile_db.get_profile("c01")
        assert profile is not None
        assert profile.name == "Acme Corp"
        assert "acme.com" in profile.domains

    @pytest.mark.asyncio
    async def test_list_all_profiles(self, profile_db):
        profiles = await profile_db.list_profiles()
        assert len(profiles) == 20

    @pytest.mark.asyncio
    async def test_update_from_engagement(self, profile_db):
        """Post-engagement update increments count and adds findings."""
        updated = await profile_db.update_from_engagement(
            "c01",
            findings=[
                {"title": "SQL injection in login", "severity": "high"},
                {"title": "XSS in search", "severity": "medium"},
            ],
            tech_stack={"web_server": "nginx", "framework": "Django"},
        )
        assert updated is not None
        assert updated.engagement_count == 1
        assert updated.tech_stack["web_server"] == "nginx"
        assert len(updated.recurring_weaknesses) == 2

    @pytest.mark.asyncio
    async def test_update_increments_occurrences(self, profile_db):
        """Repeated weakness increments occurrences."""
        finding = {"title": "SQL injection in login", "severity": "high"}
        await profile_db.update_from_engagement("c01", findings=[finding])
        await profile_db.update_from_engagement("c01", findings=[finding])

        profile = await profile_db.get_profile("c01")
        sqli = [w for w in profile.recurring_weaknesses if "SQL" in w.get("title", "")]
        assert len(sqli) == 1
        assert sqli[0]["occurrences"] == 2
