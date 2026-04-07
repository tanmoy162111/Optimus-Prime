"""ScopeEnforcer — Layer 2 of the permission pipeline.

Stateless, side-effect-free (v2.0). Validates that a tool call's target
is within the engagement scope. Safe for concurrent calls.
"""

from __future__ import annotations

import ipaddress
import logging
import re
from typing import Any

from backend.core.exceptions import ScopeViolationError
from backend.core.models import ScopeConfig

logger = logging.getLogger(__name__)


class ScopeEnforcer:
    """Validates tool calls against the engagement ScopeConfig.

    All methods are stateless and side-effect-free, enabling safe
    concurrent calls from parallel agents without locks (v2.0).
    """

    @staticmethod
    def check(scope: ScopeConfig, tool_input: dict[str, Any]) -> None:
        """Run all scope checks. Raises ScopeViolationError on failure.

        Checks performed:
          1. Target IP/domain in scope
          2. Port in scope
          3. Protocol in scope
        """
        target = tool_input.get("target") or tool_input.get("host") or tool_input.get("url", "")
        port = tool_input.get("port")
        protocol = tool_input.get("protocol")

        if target:
            ScopeEnforcer._check_target(scope, target)
        if port is not None:
            ScopeEnforcer._check_port(scope, port)
        if protocol:
            ScopeEnforcer._check_protocol(scope, protocol)

    @staticmethod
    def _check_target(scope: ScopeConfig, target: str) -> None:
        """Verify target is in scope and not excluded."""
        # Explicit empty scope check first (#10)
        if not scope.targets:
            raise ScopeViolationError(
                "No scope configured — set targets via POST /scope or scope.yaml before running tools."
            )

        # Extract hostname/IP from URL if needed
        clean_target = ScopeEnforcer._extract_host(target)

        # Check excluded first — normalize URL exclusion entries to bare host/IP so
        # that entries like 'https://admin.example.com' still match 'admin.example.com'.
        for excluded in scope.excluded_targets:
            clean_excluded = (
                ScopeEnforcer._extract_host(excluded)
                if "://" in excluded
                else excluded.strip().lower()
            )
            if ScopeEnforcer._target_matches(clean_target, clean_excluded):
                raise ScopeViolationError(
                    f"Target '{clean_target}' is in exclusion list"
                )

        # Check if target matches any scope entry.
        # Only normalize entries that are full URLs (contain ://) so that IP
        # ranges in CIDR notation (e.g. 10.0.0.0/24) are not corrupted by the
        # path-stripping in _extract_host.
        for allowed in scope.targets:
            clean_allowed = (
                ScopeEnforcer._extract_host(allowed)
                if "://" in allowed
                else allowed.strip().lower()
            )
            if ScopeEnforcer._target_matches(clean_target, clean_allowed):
                return

        # No match found
        raise ScopeViolationError(
            f"Target '{clean_target}' is not in scope"
        )

    @staticmethod
    def _check_port(scope: ScopeConfig, port: int) -> None:
        """Verify port is within scope."""
        if scope.ports == "all":
            return
        if isinstance(scope.ports, list) and port not in scope.ports:
            raise ScopeViolationError(
                f"Port {port} is not in scope (allowed: {scope.ports})"
            )

    @staticmethod
    def _check_protocol(scope: ScopeConfig, protocol: str) -> None:
        """Verify protocol is within scope."""
        if protocol.lower() not in [p.lower() for p in scope.protocols]:
            raise ScopeViolationError(
                f"Protocol '{protocol}' is not in scope (allowed: {scope.protocols})"
            )

    @staticmethod
    def _extract_host(target: str) -> str:
        """Extract hostname or IP from a target string (may be URL)."""
        # Strip protocol prefix
        if "://" in target:
            target = target.split("://", 1)[1]
        # Strip path
        target = target.split("/", 1)[0]
        # Strip port
        target = target.split(":", 1)[0]
        return target.strip().lower()

    @staticmethod
    def _target_matches(target: str, scope_entry: str) -> bool:
        """Check if a target matches a scope entry (IP, CIDR, domain, wildcard)."""
        scope_entry = scope_entry.strip().lower()
        target = target.strip().lower()

        # Exact match
        if target == scope_entry:
            return True

        # CIDR match
        try:
            network = ipaddress.ip_network(scope_entry, strict=False)
            target_ip = ipaddress.ip_address(target)
            return target_ip in network
        except ValueError:
            pass

        # Wildcard domain match (e.g., *.example.com)
        if scope_entry.startswith("*."):
            suffix = scope_entry[1:]  # .example.com
            if target.endswith(suffix) or target == scope_entry[2:]:
                return True

        # Subdomain match — target is subdomain of scope entry
        if target.endswith("." + scope_entry):
            return True

        return False
