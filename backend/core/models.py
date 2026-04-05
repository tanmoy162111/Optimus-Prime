"""Core data models for Optimus Prime v2.0.

All foundational enums, dataclasses, and type definitions referenced
across the architecture. This is the single source of truth for shared types.
"""

from __future__ import annotations

import enum
from dataclasses import dataclass, field
from datetime import datetime, timezone


def _utcnow() -> datetime:
    """Timezone-aware UTC now (replaces deprecated _utcnow)."""
    return datetime.now(timezone.utc)

from typing import Any


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class EngineType(str, enum.Enum):
    """Engine classification for agent dispatch."""
    INFRASTRUCTURE = "infrastructure"
    ICS = "ics"
    MLAI = "mlai"


class EngineStatus(str, enum.Enum):
    """Engine lifecycle status."""
    ACTIVE = "active"
    STUB = "stub"
    DISABLED = "disabled"


class StealthLevel(str, enum.Enum):
    """Engagement stealth constraint — controls tool availability."""
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


class PermissionMode(str, enum.Enum):
    """Required permission tier for a tool."""
    NONE = "none"
    READ = "read"
    WRITE = "write"
    EXECUTE = "execute"
    DESTRUCTIVE = "destructive"


class VerifyMode(str, enum.Enum):
    """Finding verification mode."""
    AUTO = "auto"
    MANUAL = "manual"


class TaskStatus(str, enum.Enum):
    """Agent task lifecycle states."""
    CREATED = "created"
    RUNNING = "running"
    COMPLETED = "completed"
    FAILED = "failed"
    STOPPED = "stopped"


class ToolPromotion(str, enum.Enum):
    """Custom tool promotion state machine: GENERATED -> SANDBOX_APPROVED -> OPERATOR_APPROVED."""
    BUILTIN = "builtin"
    GENERATED = "generated"
    SANDBOX_APPROVED = "sandbox_approved"
    OPERATOR_APPROVED = "operator_approved"


class ToolBackendType(str, enum.Enum):
    """Tool execution backend classification."""
    LOCAL = "local"
    KALI_SSH = "kali_ssh"
    ML_RUNTIME_IPC = "ml_runtime_ipc"
    ICS_RUNTIME_IPC = "ics_runtime_ipc"
    TOR_SOCKS5 = "tor_socks5"
    SANDBOX = "sandbox"


class AgentType(str, enum.Enum):
    """All agent types in the registry."""
    RECON = "recon"
    SCAN = "scan"
    EXPLOIT = "exploit"
    INTEL = "intel"
    CLOUD = "cloud"
    IAM = "iam"
    DATASEC = "datasec"
    ENDPOINT = "endpoint"
    MODELSEC = "modelsec"
    GENAI = "genai"
    ICS = "ics"
    SCOPE_DISCOVERY = "scope_discovery"
    VERIFICATION_LOOP = "verification_loop"


class FindingClassification(str, enum.Enum):
    """Verification outcome for a finding."""
    CONFIRMED = "confirmed"
    FALSE_POSITIVE = "false_positive"
    MANUAL_REVIEW = "manual_review"
    UNVERIFIED = "unverified"


class EventChannel(str, enum.Enum):
    """DurableEventLog channel categories."""
    FINDINGS = "findings"
    LIFECYCLE = "lifecycle"
    INTEL = "intel"
    COLLAB = "collab"
    RESEARCH = "research"
    SYSTEM = "system"


class WorkerState(str, enum.Enum):
    """Agent worker state machine (Section 5.3)."""
    SPAWNING = "spawning"
    TRUST_REQUIRED = "trust_required"
    READY_FOR_PROMPT = "ready_for_prompt"
    RUNNING = "running"
    FINISHED = "finished"
    FAILED = "failed"


class RBACRole(str, enum.Enum):
    """Collaboration roles (Section 14.1)."""
    LEAD = "lead"
    ANALYST = "analyst"
    OBSERVER = "observer"


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

@dataclass
class StealthProfile:
    """Per-tool stealth metadata."""
    min_stealth_level: StealthLevel
    rate_limit_rps: float | None = None
    passive_only: bool = False


@dataclass
class ScopeConfig:
    """Engagement scope definition (Section 7.2)."""
    targets: list[str] = field(default_factory=list)
    excluded_targets: list[str] = field(default_factory=list)
    ports: list[int] | str = "all"
    protocols: list[str] = field(default_factory=lambda: ["tcp", "udp"])
    stealth_level: StealthLevel = StealthLevel.MEDIUM
    verify_mode: VerifyMode = VerifyMode.AUTO
    cloud_provider: str | None = None
    compliance_frameworks: list[str] = field(default_factory=list)
    notes: str = ""
    # v2.0 additions
    ics_interface: str | None = None
    verify_tools_extend: list[str] = field(default_factory=list)


@dataclass
class ConversationMessage:
    """Single message in a session conversation."""
    role: str  # "system", "user", "assistant", "tool"
    content: str
    timestamp: datetime = field(default_factory=_utcnow)
    tool_call_id: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class TaskMessage:
    """Message within an agent task context."""
    role: str
    content: str
    timestamp: datetime = field(default_factory=_utcnow)


@dataclass
class AgentTask:
    """Task dispatched to an agent via TaskRegistry (Section 5.4)."""
    task_id: str
    agent_class: str
    prompt: str
    status: TaskStatus = TaskStatus.CREATED
    messages: list[TaskMessage] = field(default_factory=list)
    output: str = ""
    team_id: str | None = None
    parent_task_id: str | None = None
    created_at: datetime = field(default_factory=_utcnow)
    updated_at: datetime = field(default_factory=_utcnow)


@dataclass
class AgentResult:
    """Result returned by an agent after task execution."""
    status: str
    findings: list[dict[str, Any]] = field(default_factory=list)
    is_finding: bool = False
    is_terminal: bool = False
    output: str = ""
    error: str | None = None
    metadata: dict[str, Any] | None = None

    def to_event(self) -> dict[str, Any]:
        """Convert to EventBus event payload."""
        return {
            "status": self.status,
            "findings_count": len(self.findings),
            "is_terminal": self.is_terminal,
            "output_preview": self.output[:500] if self.output else "",
            "error": self.error,
        }


@dataclass
class EngineTask:
    """Task dispatched to an engine via EngineRouter."""
    task_id: str
    engine_type: EngineType
    agent_class: str
    prompt: str
    scope: ScopeConfig
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class EngineResult:
    """Result from engine dispatch."""
    task_id: str
    engine_type: EngineType
    agent_results: list[AgentResult] = field(default_factory=list)
    status: str = "completed"
    error: str | None = None


@dataclass
class Finding:
    """A security finding produced by an agent."""
    finding_id: str
    title: str
    severity: str  # critical, high, medium, low, info
    description: str
    evidence: str = ""
    classification: FindingClassification = FindingClassification.UNVERIFIED
    agent: str = ""
    tool: str = ""
    target: str = ""
    port: int | None = None
    cve_ids: list[str] = field(default_factory=list)
    attack_techniques: list[str] = field(default_factory=list)
    remediation: str = ""
    verified_at: datetime | None = None
    created_at: datetime = field(default_factory=_utcnow)
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class XAIEntry:
    """Explainable AI audit trail entry (Section 13.3)."""
    agent: str
    action: str
    result_summary: str
    reasoning: str
    timestamp: datetime = field(default_factory=_utcnow)
    session_id: str = ""
    credential_present: bool = False  # Always False — never logged


@dataclass
class TaskStatusResult:
    """Status of an IPC task (used by MLRuntimeIPC / ICSRuntimeIPC)."""
    status: str  # pending, running, done, error, timeout
    started_at: datetime | None = None
    updated_at: datetime | None = None
    progress: int = 0  # 0-100
    error: str | None = None


@dataclass
class IPCTaskRequest:
    """IPC task submission request."""
    tool: str
    input: dict[str, Any] = field(default_factory=dict)
    timeout_seconds: int = 60


@dataclass
class BranchSummary:
    """Summary of a session branch for audit."""
    branch_id: str
    branch_name: str
    parent_session_id: str
    created_at: datetime
    message_count: int
    finding_count: int
    status: str


@dataclass
class MergeResult:
    """Result of merging a branch back to parent session."""
    branch_id: str
    findings_merged: int
    attack_techniques_merged: int
    tool_effectiveness_records: int
    status: str = "completed"
