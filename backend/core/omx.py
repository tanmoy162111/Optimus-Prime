"""OmX — Workflow Planner (Section 3.1).

Interprets operator directives ($pentest, $recon, etc.) and decomposes
them into structured engagement plans with phases, agent assignments,
and gate requirements.

For free-form natural language, delegates to LLMRouter for decomposition.
"""

from __future__ import annotations

import logging
import re
import uuid
from dataclasses import dataclass, field
from typing import Any

from backend.core.llm_router import LLMMessage, LLMRouter
from backend.core.models import AgentType, EngineType, ScopeConfig

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class PhaseGate:
    """Gate condition that must be satisfied before advancing."""
    gate_type: str  # "auto", "human", "finding_threshold"
    description: str
    threshold: int = 0  # e.g., minimum findings before proceeding


@dataclass
class EngagementPhase:
    """A single phase in an engagement plan."""
    phase_id: str
    name: str
    description: str
    agent_types: list[AgentType]
    engine: EngineType = EngineType.INFRASTRUCTURE
    gate: PhaseGate | None = None
    depends_on: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class EngagementPlan:
    """Structured engagement plan produced by OmX."""
    plan_id: str
    directive: str  # Original operator command
    description: str
    phases: list[EngagementPhase]
    scope: ScopeConfig | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def phase_count(self) -> int:
        return len(self.phases)

    def agent_types_involved(self) -> set[AgentType]:
        agents = set()
        for phase in self.phases:
            agents.update(phase.agent_types)
        return agents


# ---------------------------------------------------------------------------
# Protocol templates
# ---------------------------------------------------------------------------

def _pentest_phases(exploit_mode: str = "controlled") -> list[EngagementPhase]:
    """Full penetration test protocol with two-phase exploitation.

    Default flow:
      scope → recon → scan → exploit_controlled [human gate] →
      exploit_full [human gate] → verify → intel → report

    With --freehand:
      scope → recon → scan → exploit_full [human gate] → verify → intel → report

    Args:
        exploit_mode: ``"controlled"`` (default, two-phase) or ``"full"``
            (freehand — skips controlled phase, goes straight to full).
    """
    mode = exploit_mode.lower()

    base_phases = [
        EngagementPhase(
            phase_id="scope", name="Scope Discovery",
            description="Discover and validate engagement scope boundaries",
            agent_types=[AgentType.SCOPE_DISCOVERY],
        ),
        EngagementPhase(
            phase_id="recon", name="Reconnaissance",
            description="Active and passive reconnaissance of targets",
            agent_types=[AgentType.RECON],
            depends_on=["scope"],
        ),
        EngagementPhase(
            phase_id="scan", name="Vulnerability Scanning",
            description="Automated vulnerability scanning and service enumeration",
            agent_types=[AgentType.SCAN],
            depends_on=["recon"],
        ),
    ]

    if mode == "full":
        # Freehand: single FULL exploit phase, no CONTROLLED phase
        exploit_phases = [
            EngagementPhase(
                phase_id="exploit_full", name="Full Exploitation (Freehand)",
                description="Aggressive exploitation of all discovered services — FREEHAND mode",
                agent_types=[AgentType.EXPLOIT],
                depends_on=["scan"],
                gate=PhaseGate("human", "Operator approval required before freehand exploitation"),
                metadata={"exploit_mode": "full"},
            ),
        ]
        verify_depends = ["exploit_full"]
    else:
        # Default: CONTROLLED first, then human gate before FULL escalation
        exploit_phases = [
            EngagementPhase(
                phase_id="exploit_controlled", name="Exploitation (Controlled)",
                description="Controlled exploitation of confirmed vulnerabilities only",
                agent_types=[AgentType.EXPLOIT],
                depends_on=["scan"],
                gate=PhaseGate("human", "Operator approval required before controlled exploitation"),
                metadata={"exploit_mode": "controlled"},
            ),
            EngagementPhase(
                phase_id="exploit_full", name="Exploitation (Full Escalation)",
                description="Full freehand exploitation — operator escalation from CONTROLLED",
                agent_types=[AgentType.EXPLOIT],
                depends_on=["exploit_controlled"],
                gate=PhaseGate(
                    "human",
                    "CONTROLLED exploitation complete. Escalate to FULL freehand mode? "
                    "Type confirm-exploit_full to proceed or skip-exploit_full to skip.",
                ),
                metadata={"exploit_mode": "full"},
            ),
        ]
        verify_depends = ["exploit_full"]

    tail_phases = [
        EngagementPhase(
            phase_id="verify", name="Verification",
            description="Independent verification of all findings",
            agent_types=[AgentType.VERIFICATION_LOOP],
            depends_on=verify_depends,
        ),
        EngagementPhase(
            phase_id="intel", name="Attribution & Intelligence",
            description="CVE correlation, MITRE ATT&CK mapping, threat intel enrichment",
            agent_types=[AgentType.INTEL],
            depends_on=["verify"],
        ),
        EngagementPhase(
            phase_id="report", name="Reporting",
            description="Generate comprehensive security assessment report",
            agent_types=[],
            depends_on=["intel"],
        ),
    ]

    return base_phases + exploit_phases + tail_phases


def _recon_phases() -> list[EngagementPhase]:
    """Reconnaissance-only protocol."""
    return [
        EngagementPhase(
            phase_id="scope", name="Scope Discovery",
            description="Validate scope boundaries",
            agent_types=[AgentType.SCOPE_DISCOVERY],
        ),
        EngagementPhase(
            phase_id="recon", name="Reconnaissance",
            description="Full reconnaissance of targets",
            agent_types=[AgentType.RECON],
            depends_on=["scope"],
        ),
    ]


def _cloud_audit_phases() -> list[EngagementPhase]:
    """Cloud security audit protocol."""
    return [
        EngagementPhase(
            phase_id="scope", name="Cloud Scope Discovery",
            description="Enumerate cloud assets and services",
            agent_types=[AgentType.SCOPE_DISCOVERY, AgentType.CLOUD],
        ),
        EngagementPhase(
            phase_id="iam", name="IAM Audit",
            description="Review identity and access management configurations",
            agent_types=[AgentType.IAM],
            depends_on=["scope"],
        ),
        EngagementPhase(
            phase_id="datasec", name="Data Security",
            description="Check data exposure, encryption, and storage security",
            agent_types=[AgentType.DATASEC],
            depends_on=["scope"],
        ),
        EngagementPhase(
            phase_id="cloud", name="Cloud Infrastructure",
            description="Assess cloud infrastructure security posture",
            agent_types=[AgentType.CLOUD],
            depends_on=["iam", "datasec"],
        ),
        EngagementPhase(
            phase_id="verify", name="Verification",
            description="Verify findings",
            agent_types=[AgentType.VERIFICATION_LOOP],
            depends_on=["cloud"],
        ),
    ]


def _genai_probe_phases() -> list[EngagementPhase]:
    """GenAI/ML security probe protocol."""
    return [
        EngagementPhase(
            phase_id="model_enum", name="Model Enumeration",
            description="Discover and enumerate ML models and AI endpoints",
            agent_types=[AgentType.MODELSEC],
            engine=EngineType.MLAI,
        ),
        EngagementPhase(
            phase_id="genai", name="GenAI Security Testing",
            description="Prompt injection, jailbreak, data poisoning tests",
            agent_types=[AgentType.GENAI],
            engine=EngineType.MLAI,
            depends_on=["model_enum"],
        ),
        EngagementPhase(
            phase_id="verify", name="Verification",
            description="Verify findings",
            agent_types=[AgentType.VERIFICATION_LOOP],
            depends_on=["genai"],
        ),
    ]


def _iam_audit_phases() -> list[EngagementPhase]:
    """IAM audit protocol."""
    return [
        EngagementPhase(
            phase_id="iam", name="IAM Audit",
            description="Comprehensive IAM review",
            agent_types=[AgentType.IAM],
        ),
    ]


def _endpoint_phases() -> list[EngagementPhase]:
    """Endpoint security assessment."""
    return [
        EngagementPhase(
            phase_id="endpoint", name="Endpoint Assessment",
            description="Endpoint security posture assessment",
            agent_types=[AgentType.ENDPOINT],
        ),
    ]


def _scope_discover_phases() -> list[EngagementPhase]:
    """Scope discovery only."""
    return [
        EngagementPhase(
            phase_id="scope", name="Scope Discovery",
            description="Asset discovery and scope validation",
            agent_types=[AgentType.SCOPE_DISCOVERY],
        ),
    ]


def _ics_audit_phases() -> list[EngagementPhase]:
    """ICS security audit protocol."""
    return [
        EngagementPhase(
            phase_id="ics_enum", name="ICS Enumeration",
            description="Discover ICS/SCADA devices and protocols",
            agent_types=[AgentType.ICS],
            engine=EngineType.ICS,
            gate=PhaseGate("human", "Operator confirmation required for ICS interaction"),
        ),
        EngagementPhase(
            phase_id="verify", name="Verification",
            description="Verify ICS findings",
            agent_types=[AgentType.VERIFICATION_LOOP],
            depends_on=["ics_enum"],
        ),
    ]


# Directive -> phase builder mapping
DIRECTIVE_PROTOCOLS: dict[str, Any] = {
    "$pentest": _pentest_phases,
    "$recon": _recon_phases,
    "$cloud-audit": _cloud_audit_phases,
    "$genai-probe": _genai_probe_phases,
    "$scope-discover": _scope_discover_phases,
    "$iam-audit": _iam_audit_phases,
    "$endpoint": _endpoint_phases,
    "$ics-audit": _ics_audit_phases,
}

DIRECTIVE_DESCRIPTIONS: dict[str, str] = {
    "$pentest": "Full penetration test engagement",
    "$recon": "Reconnaissance-only engagement",
    "$cloud-audit": "Cloud security audit",
    "$genai-probe": "GenAI/ML security probe",
    "$scope-discover": "Scope discovery and asset enumeration",
    "$iam-audit": "Identity and access management audit",
    "$endpoint": "Endpoint security assessment",
    "$ics-audit": "ICS/SCADA security audit",
}

# Regex to detect directives
_DIRECTIVE_RE = re.compile(
    r"(\$(?:pentest|recon|cloud-audit|genai-probe|scope-discover|iam-audit|endpoint|ics-audit))",
    re.IGNORECASE,
)


class OmX:
    """Workflow Planner — interprets operator directives and decomposes
    them into structured engagement plans.

    For keyword commands ($pentest, $recon, etc.), uses predefined
    protocol templates. For natural language, delegates to LLMRouter.
    """

    def __init__(self, llm_router: LLMRouter | None = None) -> None:
        self._llm = llm_router

    async def plan(
        self,
        message: str,
        scope: ScopeConfig | None = None,
    ) -> EngagementPlan:
        """Parse an operator message and produce an engagement plan.

        Args:
            message: Operator command or natural language input.
            scope: Optional pre-configured scope.

        Returns:
            Structured EngagementPlan.
        """
        directive = self._detect_directive(message)

        if directive:
            return self._plan_from_directive(directive, message, scope)

        # No directive found — use LLM for decomposition
        return await self._plan_from_natural_language(message, scope)

    def _detect_directive(self, message: str) -> str | None:
        """Extract a known directive keyword from the message."""
        match = _DIRECTIVE_RE.search(message)
        if match:
            return match.group(1).lower()
        return None

    def _plan_from_directive(
        self,
        directive: str,
        message: str,
        scope: ScopeConfig | None,
    ) -> EngagementPlan:
        """Build a plan from a known directive template.

        Supported flags (appended after the directive keyword):
          --exploit=full | --exploit=controlled | --freehand
        """
        phase_builder = DIRECTIVE_PROTOCOLS.get(directive)
        if not phase_builder:
            raise ValueError(f"Unknown directive: {directive}")

        # Parse exploit mode flag
        msg_lower = message.lower()
        if "--freehand" in msg_lower or "--exploit=full" in msg_lower:
            exploit_mode = "full"
        elif "--exploit=controlled" in msg_lower:
            exploit_mode = "controlled"
        else:
            exploit_mode = "controlled"

        # Pass exploit_mode only to builders that support it ($pentest)
        import inspect
        sig = inspect.signature(phase_builder)
        if "exploit_mode" in sig.parameters:
            phases = phase_builder(exploit_mode=exploit_mode)
        else:
            phases = phase_builder()

        description = DIRECTIVE_DESCRIPTIONS.get(directive, directive)
        if directive == "$pentest" and exploit_mode == "full":
            description += " [FREEHAND exploitation mode]"

        # Auto-build scope from targets found in the message if no scope provided
        if scope is None or not scope.targets:
            targets = _extract_targets_from_message(message)
            if targets:
                scope = ScopeConfig(targets=targets)
                logger.info("OmX: auto-scope from directive message: %s", targets)

        return EngagementPlan(
            plan_id=str(uuid.uuid4()),
            directive=directive,
            description=description,
            phases=phases,
            scope=scope,
            metadata={"raw_message": message},
        )

    async def _plan_from_natural_language(
        self,
        message: str,
        scope: ScopeConfig | None,
    ) -> EngagementPlan:
        """Use LLM to decompose a natural language request into phases."""
        if self._llm is None:
            # Fallback: create a generic recon plan
            return EngagementPlan(
                plan_id=str(uuid.uuid4()),
                directive="natural_language",
                description=f"Plan from: {message[:100]}",
                phases=_recon_phases(),
                scope=scope,
                metadata={"raw_message": message, "llm_decomposed": False},
            )

        system_prompt = (
            "You are OmX, the workflow planner for Optimus Prime security platform. "
            "Given an operator request, determine which security phases and agents are needed. "
            "Respond with a JSON object: {\"phases\": [{\"name\": str, \"agents\": [str], \"description\": str}]}. "
            "Available agents: recon, scan, exploit, intel, cloud, iam, datasec, endpoint, modelsec, genai, ics, scope_discovery, verification_loop."
        )

        response = await self._llm.complete(
            messages=[LLMMessage(role="user", content=message)],
            system_prompt=system_prompt,
            max_tokens=1024,
            temperature=0.3,
        )

        # Parse LLM response into phases
        try:
            import json
            data = json.loads(response.content)
            phases = []
            for i, phase_data in enumerate(data.get("phases", [])):
                agent_types = []
                for agent_name in phase_data.get("agents", []):
                    try:
                        agent_types.append(AgentType(agent_name))
                    except ValueError:
                        logger.warning("OmX: unknown agent type from LLM: %s", agent_name)

                phases.append(EngagementPhase(
                    phase_id=f"llm_phase_{i}",
                    name=phase_data.get("name", f"Phase {i}"),
                    description=phase_data.get("description", ""),
                    agent_types=agent_types,
                    depends_on=[f"llm_phase_{i-1}"] if i > 0 else [],
                ))

            if not phases:
                phases = _recon_phases()

        except (json.JSONDecodeError, KeyError) as exc:
            logger.warning("OmX: failed to parse LLM response, falling back to recon: %s", exc)
            phases = _recon_phases()

        return EngagementPlan(
            plan_id=str(uuid.uuid4()),
            directive="natural_language",
            description=f"LLM-decomposed plan from: {message[:100]}",
            phases=phases,
            scope=scope,
            metadata={"raw_message": message, "llm_decomposed": True},
        )

    def get_available_directives(self) -> dict[str, str]:
        """Return all supported directives and their descriptions."""
        return dict(DIRECTIVE_DESCRIPTIONS)


def _extract_targets_from_message(message: str) -> list[str]:
    """Extract IP addresses, CIDR ranges, and domain names from a message.

    Strips known directive keywords before parsing so they aren't
    mistaken for targets.
    """
    # Remove directive keywords
    cleaned = _DIRECTIVE_RE.sub("", message).strip()
    targets: list[str] = []

    # IP / CIDR
    for m in re.finditer(r'\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2})?)\b', cleaned):
        targets.append(m.group(1))

    # Domain names (skip if already captured as IP)
    for m in re.finditer(r'\b((?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,})\b', cleaned):
        domain = m.group(1)
        if domain not in targets:
            targets.append(domain)

    return targets
