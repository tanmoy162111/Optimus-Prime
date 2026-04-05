"""StealthEnforcer — Layer 4 of the permission pipeline.

Validates that a tool is allowed at the current engagement stealth level.
Blocks tools whose StealthProfile minimum level exceeds the engagement level.
"""

from __future__ import annotations

import logging

from backend.core.exceptions import StealthViolationError
from backend.core.models import StealthLevel, StealthProfile

logger = logging.getLogger(__name__)

# Stealth level ordering: LOW < MEDIUM < HIGH
_STEALTH_ORDER = {
    StealthLevel.LOW: 0,
    StealthLevel.MEDIUM: 1,
    StealthLevel.HIGH: 2,
}

# Tools blocked at HIGH stealth (Section 6.6)
HIGH_STEALTH_BLOCKED_TOOLS: frozenset[str] = frozenset({
    "masscan",
    "shodan",
    "dark_web_query",
})

# Tools that require rate limiting at MEDIUM stealth
MEDIUM_STEALTH_RATE_LIMITED: frozenset[str] = frozenset({
    "nmap",
    "nikto",
    "nuclei",
    "wpscan",
    "ffuf",
})


class StealthEnforcer:
    """Validates tool calls against the engagement stealth level."""

    @staticmethod
    def check(
        tool_name: str,
        stealth_level: StealthLevel,
        stealth_profile: StealthProfile,
    ) -> dict[str, bool]:
        """Check tool against stealth constraints.

        Args:
            tool_name: Name of the tool being called.
            stealth_level: Current engagement stealth level.
            stealth_profile: The tool's declared stealth profile.

        Returns:
            Dict with 'rate_limited' flag for the caller to enforce.

        Raises:
            StealthViolationError: If tool is blocked at current stealth level.
        """
        result = {"rate_limited": False}

        # HIGH stealth: block aggressive tools
        if stealth_level == StealthLevel.HIGH:
            if tool_name in HIGH_STEALTH_BLOCKED_TOOLS:
                raise StealthViolationError(
                    f"Tool '{tool_name}' is blocked at stealth level HIGH"
                )
            # At HIGH stealth, check if tool is passive-only compatible
            if not stealth_profile.passive_only:
                # Allow targeted scans but rate-limit them
                result["rate_limited"] = True

        # MEDIUM stealth: rate-limit active scanning tools
        if stealth_level == StealthLevel.MEDIUM:
            if tool_name in MEDIUM_STEALTH_RATE_LIMITED:
                result["rate_limited"] = True

        # Check tool's declared minimum stealth level
        tool_min = _STEALTH_ORDER.get(stealth_profile.min_stealth_level, 0)
        engagement_level = _STEALTH_ORDER.get(stealth_level, 0)

        if tool_min > engagement_level:
            raise StealthViolationError(
                f"Tool '{tool_name}' requires stealth level "
                f"{stealth_profile.min_stealth_level.value} or lower, "
                f"but engagement is at {stealth_level.value}"
            )

        return result
