"""Clawhip — typed-event router for lifecycle/finding/phase events (D-01 layer 2, D-09).

A thin module wrapping the existing `ws_handler.ConnectionManager` to deliver
typed `ClawhipEvent` payloads to the frontend WebSocket, and conditionally to
the `ExplainableAI` audit trail for decision-worthy events (failures,
rejections, and the terminal GATE_PENDING boundary).

Does NOT deliver to any multi-user, real-time-collaboration transport
(D-09 — out of scope for this project). Does NOT build a generic pub/sub abstraction —
there is exactly one live delivery target (frontend WS) plus one audit sink
(XAI), so `emit()` is a direct two-call method (RESEARCH.md Pattern 1).
"""

import logging
from enum import Enum
from typing import Optional

from pydantic import BaseModel

logger = logging.getLogger(__name__)


class ClawhipEventType(str, Enum):
    PHASE_STARTED = "PHASE_STARTED"
    PHASE_COMPLETED = "PHASE_COMPLETED"
    PHASE_FAILED = "PHASE_FAILED"
    PLAN_REJECTED = "PLAN_REJECTED"  # pre-dispatch validation gate failure
    GATE_PENDING = "GATE_PENDING"  # terminal gate boundary (D-08); see Plan 08


# Event types that represent an auditable decision (failure/rejection/gate
# boundary) rather than routine lifecycle noise (PHASE_STARTED/COMPLETED).
_AUDITABLE_EVENT_TYPES = (
    ClawhipEventType.PHASE_FAILED,
    ClawhipEventType.PLAN_REJECTED,
    ClawhipEventType.GATE_PENDING,
)


class ClawhipEvent(BaseModel):
    event_type: ClawhipEventType
    directive_id: Optional[str] = None
    detail: str = ""
    error: Optional[str] = None


class Clawhip:
    """Routes typed lifecycle/finding/phase events to the frontend WS and
    XAI audit trail. Does NOT deliver to a multi-user collaboration transport
    (D-09 — out of scope)."""

    def __init__(self, connection_manager, xai_logger):
        self._manager = connection_manager  # ws_handler.manager
        self._xai = xai_logger  # ExplainableAI instance

    async def emit(self, session_id: str, event: ClawhipEvent) -> None:
        await self._manager.send(session_id, event.model_dump(mode="json"))

        if event.event_type in _AUDITABLE_EVENT_TYPES:
            self._xai.log_decision(
                decision_type=event.event_type.value,
                reasoning=event.detail,
                confidence=1.0,
                factors=[event.directive_id or "plan-level"],
            )
