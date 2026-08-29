"""Tests for VerificationLoop — DATA-02 engagement-scoped budget isolation.

Validates that concurrent engagements verifying the same finding_id do not
share or exhaust each other's request budget (the prior, now-deleted
implementation keyed its counter by bare finding_id — that IS the
cross-engagement budget-bleed bug this phase fixes).
"""

from __future__ import annotations

import pytest

from backend.verification.verification_loop import VerificationLoop
from backend.verification.verification_policy import VerificationPolicy


def test_check_and_increment_enforces_default_policy_limit():
    """Default policy (max_requests_per_finding=3): 3 calls True, 4th call False."""
    loop = VerificationLoop()

    assert loop.check_and_increment("eng-A", "F1") is True
    assert loop.check_and_increment("eng-A", "F1") is True
    assert loop.check_and_increment("eng-A", "F1") is True
    assert loop.check_and_increment("eng-A", "F1") is False


def test_cross_engagement_budget_isolation_for_shared_finding_id():
    """Two engagements verifying the same finding_id keep independent budgets.

    Exhaust eng-A's budget for finding F1, then confirm eng-B (same
    finding_id, different engagement) still has a fresh budget — proving
    the counter is keyed by f"{engagement_id}:{finding_id}", not bare
    finding_id.
    """
    loop = VerificationLoop()

    # Exhaust eng-A's budget for F1
    assert loop.check_and_increment("eng-A", "F1") is True
    assert loop.check_and_increment("eng-A", "F1") is True
    assert loop.check_and_increment("eng-A", "F1") is True
    assert loop.check_and_increment("eng-A", "F1") is False

    # eng-B, same finding_id — independent budget, still within limit
    assert loop.check_and_increment("eng-B", "F1") is True
    assert loop.check_and_increment("eng-B", "F1") is True
    assert loop.check_and_increment("eng-B", "F1") is True
    assert loop.check_and_increment("eng-B", "F1") is False


def test_injected_custom_policy_is_honored():
    """A custom VerificationPolicy injected via the constructor is respected."""
    custom_policy = VerificationPolicy(max_requests_per_finding=1)
    loop = VerificationLoop(policy=custom_policy)

    assert loop.policy is custom_policy
    assert loop.check_and_increment("eng-A", "F1") is True
    assert loop.check_and_increment("eng-A", "F1") is False
