"""
OmX — LLM-driven engagement workflow planner (Phase 3: Orchestration Upgrade).

Decomposes an operator directive (free text, or one of the 7 fixed planning
keywords documented in OPTIMUS_PRIME_ARCHITECTURE.md Section 3.1 — $pentest,
$cloud-audit, $genai-probe, $recon, $scope-discover, $iam-audit, $endpoint)
into a Pydantic-validated EngagementPlan DAG via Claude forced tool use
(D-01 layer 1, D-06, ORCH-03).

OmX never returns a partial or default plan. A malformed/hallucinated DAG is
Critical Failure Mode #3 (03-AI-SPEC.md Section 1) — after 3 total attempts
that fail Pydantic validation (or return a truncated/max_tokens response),
plan() raises OmXPlanValidationError instead of letting a bad plan reach
OmO's dispatch loop.

OmX is fully independent of OmO (the sequential dispatch coordinator built in
a later plan): no import of omo.py, no knowledge of dispatch timing beyond
the depends_on/gate_required fields it emits per directive.
"""
import logging
from typing import List, Literal

from pydantic import BaseModel, Field, ValidationError

from backend import config

logger = logging.getLogger(__name__)


class OmXPlanValidationError(Exception):
    pass


class Directive(BaseModel):
    id: str
    phase: str
    engine: Literal["InfrastructureEngine", "MLAIEngine", "ICSEngine"]
    agent: str
    target: str
    tools: List[str] = Field(default_factory=list)
    depends_on: List[str] = Field(default_factory=list)
    gate_required: bool = False


class EngagementPlan(BaseModel):
    directives: List[Directive]
    rationale: str


# Deliberately NOT reused from orchestrator._SYSTEM_PROMPT (03-AI-SPEC.md
# Section 4b: "System vs. user separation") — that prompt is for conversational
# replies; this one is for a single structured forced-tool-use planning call.
_OMX_PLANNING_SYSTEM_PROMPT = """You are OmX, the workflow planner for Optimus Prime, a single-operator \
authorized-penetration-testing orchestration platform. Your only job is to decompose the \
operator's directive into a dependency-ordered EngagementPlan DAG by calling the \
emit_engagement_plan tool. Never respond with plain prose — always call the tool.

CLOSED ENGINE VOCABULARY — every directive.engine MUST be exactly one of:
  - InfrastructureEngine  (default for IP/domain/URL/cloud/auth targets)
  - MLAIEngine            (model file, API endpoint, LLM, RAG pipeline targets)
  - ICSEngine             (Modbus/DNP3/SCADA targets)
Never invent a fourth engine name.

REGISTERED AGENT VOCABULARY — every directive.agent MUST be exactly one of the following \
currently registered BaseAgent names:
  ReconAgent, ScanAgent, ExploitAgent, CloudAgent, IAMAgent, EndpointAgent,
  GenAIAgent, ModelSecAgent, DataSecAgent, ICSAgent, IntelAgent
Never invent an agent name that is not in this list.

SCOPE FIDELITY (hard constraint, Critical stakes — CFAA 18 U.S.C. Sec. 1030(a)(2)):
Every directive.target MUST be a member of the operator's approved scope.targets and MUST NOT \
be a member of scope.exclusions. If, while decomposing the directive, you identify an asset \
that is plausibly related but is not explicitly listed in scope.targets (a discovered subdomain, \
a linked cloud account, a third-party-hosted API, etc.) — do NOT silently include it and do NOT \
silently drop it. Emit the directive with gate_required=true so the operator must explicitly \
approve that asset before OmO ever dispatches it. Being "helpful" by expanding scope on your own \
inference is the single worst failure mode this system can produce.

STEALTH-LEVEL CONFORMANCE (High stakes, applies on every attempt including retries):
Every directive's tool/flag selection must respect scope.stealth_level on the very first response \
AND on every corrective retry after a validation failure. A validation failure is a schema \
problem — never respond to it by escalating scan aggressiveness, thread counts, or timing (e.g. \
switching to nmap -T4/-T5, removing rate limits, shortening timeouts) to "try harder." Stealth \
constraints are not relaxed by a retry prompt.

EXECUTION ORDERING: set depends_on to the ids of directives that must reach status "completed" \
first. Set gate_required=true for any directive that should not fire until the operator explicitly \
approves it (ambiguous scope, or an exploit-phase directive following recon/verification).

CANONICAL $pentest DECOMPOSITION (8 phases — use this shape as the template for any $pentest \
directive; adapt phase count/agents for other keywords such as $cloud-audit, $genai-probe, $recon, \
$scope-discover, $iam-audit, $endpoint):
  Phase 1 (scope_discovery)  ReconAgent   passive recon (crt.sh, WHOIS, DNS enum)   gate_required=true
  Phase 2 (recon)            ReconAgent   active recon (nmap rate-limited, whatweb) depends_on=[phase 1]
  Phase 3 (intel)            IntelAgent   concurrent CVE correlation                depends_on=[phase 1]
  Phase 4 (scan)             ScanAgent    application scan (nikto, nuclei, wpscan)  depends_on=[phase 2]
  Phase 5 (cloud)            CloudAgent   cloud posture (ScoutSuite, Prowler)       depends_on=[phase 1]
  Phase 6 (exploit)          ExploitAgent validated exploitation (sqlmap, dalfox,   depends_on=[phase 4, phase 5]
                                          commix, ffuf)                            gate_required=true
  Phase 7 (verify)           IntelAgent   classify findings (CONFIRMED /            depends_on=[phase 6]
                                          FALSE_POSITIVE / MANUAL_REVIEW)
  Phase 8 (report)           IntelAgent   compile final report directive           depends_on=[phase 7]

Example emit_engagement_plan input for "$pentest acme.com" (approved target: acme.com):
{
  "directives": [
    {"id": "d1", "phase": "scope_discovery", "engine": "InfrastructureEngine", "agent": "ReconAgent",
     "target": "acme.com", "tools": ["crtsh", "whois", "dns_enum"], "depends_on": [], "gate_required": true},
    {"id": "d2", "phase": "recon", "engine": "InfrastructureEngine", "agent": "ReconAgent",
     "target": "acme.com", "tools": ["nmap", "whatweb"], "depends_on": ["d1"], "gate_required": false},
    {"id": "d3", "phase": "intel", "engine": "InfrastructureEngine", "agent": "IntelAgent",
     "target": "acme.com", "tools": [], "depends_on": ["d1"], "gate_required": false},
    {"id": "d4", "phase": "scan", "engine": "InfrastructureEngine", "agent": "ScanAgent",
     "target": "acme.com", "tools": ["nikto", "nuclei", "wpscan"], "depends_on": ["d2"], "gate_required": false},
    {"id": "d5", "phase": "cloud", "engine": "InfrastructureEngine", "agent": "CloudAgent",
     "target": "acme.com", "tools": ["scoutsuite", "prowler"], "depends_on": ["d1"], "gate_required": false},
    {"id": "d6", "phase": "exploit", "engine": "InfrastructureEngine", "agent": "ExploitAgent",
     "target": "acme.com", "tools": ["sqlmap", "dalfox", "commix", "ffuf"], "depends_on": ["d4", "d5"], "gate_required": true},
    {"id": "d7", "phase": "verify", "engine": "InfrastructureEngine", "agent": "IntelAgent",
     "target": "acme.com", "tools": [], "depends_on": ["d6"], "gate_required": false},
    {"id": "d8", "phase": "report", "engine": "InfrastructureEngine", "agent": "IntelAgent",
     "target": "acme.com", "tools": [], "depends_on": ["d7"], "gate_required": false}
  ],
  "rationale": "Full pentest decomposition: scope discovery gated for approval, recon/intel/scan/cloud in parallel-eligible phases, exploit gated on verification completing recon+scan+cloud, verify before report."
}
"""


class OmX:
    """Workflow planner — decomposes an operator directive into an EngagementPlan DAG."""

    def __init__(self, llm_router):
        self.llm_router = llm_router
        # Derive the tool's input_schema directly from EngagementPlan so it can
        # never drift from the Pydantic validator applied to the response.
        self._plan_tool = {
            "name": "emit_engagement_plan",
            "description": "Return the decomposed engagement DAG for the operator's directive.",
            "input_schema": EngagementPlan.model_json_schema(),
        }

    async def plan(self, directive_text: str, session) -> EngagementPlan:
        scope = session.scope
        scope_context = (
            f"Approved targets: {scope.targets}\n"
            f"Excluded targets: {scope.exclusions}\n"
            f"Stealth level: {scope.stealth_level}\n"
            f"Approved ports: {scope.ports}\n"
            f"Approved protocols: {scope.protocols}"
        )
        messages = [
            {"role": "user", "content": f"{scope_context}\n\nOperator directive: {directive_text}"}
        ]

        last_error = None
        for attempt in range(1, 4):  # 1 initial + 2 retries = 3 attempts total
            response = await self.llm_router.claude.messages.create(
                model=config.settings.claude_model,
                max_tokens=2048,
                system=_OMX_PLANNING_SYSTEM_PROMPT,
                messages=messages,
                tools=[self._plan_tool],
                tool_choice={
                    "type": "tool",
                    "name": "emit_engagement_plan",
                    "disable_parallel_tool_use": True,
                },
            )
            tool_use = next(b for b in response.content if b.type == "tool_use")

            if getattr(response, "stop_reason", None) == "max_tokens":
                last_error = "response truncated at max_tokens before a complete plan was emitted"
                logger.warning(f"OmX plan validation failed (attempt {attempt}/3): {last_error}")
                messages.append({"role": "assistant", "content": response.content})
                messages.append({
                    "role": "user",
                    "content": f"Your plan failed validation: {last_error}. Return a corrected plan.",
                })
                continue

            try:
                return EngagementPlan.model_validate(tool_use.input)
            except ValidationError as e:
                last_error = e
                logger.warning(f"OmX plan validation failed (attempt {attempt}/3): {e}")
                messages.append({"role": "assistant", "content": response.content})
                messages.append({
                    "role": "user",
                    "content": f"Your plan failed validation: {e}. Return a corrected plan.",
                })

        raise OmXPlanValidationError(
            f"OmX could not produce a valid EngagementPlan after 3 attempts: {last_error}"
        )
