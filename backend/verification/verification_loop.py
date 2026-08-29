"""VerificationLoop — engagement-scoped verification budget stub (DATA-02).

Section 7.4 (N9): governs what the full verification loop is allowed to do
(tool allowlist, max requests per finding, no-auth-injection default). This
module is a scoping-only stub: it tracks per-(engagement, finding) request
budgets against an injected VerificationPolicy and nothing more.

Deliberately excluded this phase (v1.1 Phase 5 — Autonomous Verification
Loop — will extend this stub, not replace it):
  - CONFIRMED / FALSE_POSITIVE / MANUAL_REVIEW classification
  - OmO Reviewer role
  - Actual verification tool dispatch (curl, nmap_verify, testssl_readonly,
    httpx_probe)

The prior (deleted) implementation keyed its `_request_counts` dict by bare
`finding_id` — two concurrent engagements verifying a finding with the same
`finding_id` would share (and could exhaust) each other's request budget.
This stub fixes that by keying on `f"{engagement_id}:{finding_id}"`.
"""

from __future__ import annotations

from typing import Dict

from backend.verification.verification_policy import (
    DEFAULT_VERIFICATION_POLICY,
    VerificationPolicy,
)


class VerificationLoop:
    """Scoping-only stub (DATA-02).

    Full CONFIRMED/FALSE_POSITIVE/MANUAL_REVIEW classification logic is
    v1.1 Phase 5 scope — do not add it here.
    """

    def __init__(self, policy: VerificationPolicy | None = None) -> None:
        self._policy = policy or DEFAULT_VERIFICATION_POLICY
        self._request_counts: Dict[str, int] = {}

    @property
    def policy(self) -> VerificationPolicy:
        return self._policy

    def _key(self, engagement_id: str, finding_id: str) -> str:
        return f"{engagement_id}:{finding_id}"

    def check_and_increment(self, engagement_id: str, finding_id: str) -> bool:
        """Increment and check the per-(engagement, finding) request budget.

        Returns True if still within VerificationPolicy.max_requests_per_finding,
        False if the budget is exhausted. Deliberately returns a bool, not a
        FindingClassification enum — that enum belongs to the full loop (v1.1
        Phase 5) and does not exist in the new system yet.
        """
        key = self._key(engagement_id, finding_id)
        count = self._request_counts.get(key, 0) + 1
        self._request_counts[key] = count
        return count <= self._policy.max_requests_per_finding
