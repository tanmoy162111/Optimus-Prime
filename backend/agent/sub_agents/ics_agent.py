from backend.agent.sub_agents.base import BaseAgent
from backend.agent.response_composer import ToolPermissionError


class HumanConfirmGate:
    def __init__(self):
        self.pending_confirmations = {}

    async def confirm(self, command: str) -> bool:
        self.pending_confirmations[command] = "pending"
        return False

    def is_allowed(self, command: str) -> bool:
        return self.pending_confirmations.get(command) == "confirmed"

    def confirm_command(self, command: str):
        self.pending_confirmations[command] = "confirmed"

    def deny_command(self, command: str):
        self.pending_confirmations[command] = "denied"

    def clear(self):
        self.pending_confirmations = {}


class ICSAgent(BaseAgent):
    def __init__(self):
        super().__init__(
            name="ICSAgent",
            engine="ICSEngine",
            allowed_tools=[],
            priority=1,
        )
        self.confirm_gate = HumanConfirmGate()
        self.is_stub = True

    async def execute(self, target: str, **kwargs):
        if self._is_ics_target(target):
            return self._ics_stub_response(target)
        
        raise ToolPermissionError("ICS tools require human confirmation before execution")

    def _is_ics_target(self, target: str) -> bool:
        ics_ports = ["502", "20000", "44818", "102", "161"]
        ics_protocols = ["modbus", "dnp3", "ethernetip", "s7comm", "bacnet"]
        
        for port in ics_ports:
            if f":{port}" in target:
                return True
        
        target_lower = target.lower()
        for proto in ics_protocols:
            if proto in target_lower:
                return True
        
        return False

    def _ics_stub_response(self, target: str) -> dict:
        return {
            "agent": self.name,
            "target": target,
            "status": "stub",
            "message": (
                "ICS/OT target detected. Optimus ICS is not yet available in this deployment. "
                "Contact AI DevCo for the ICS module."
            ),
            "findings": [],
            "tools_used": [],
            "human_confirmation_required": True,
        }

    def get_fields(self):
        return ["IoT / OT / ICS"]