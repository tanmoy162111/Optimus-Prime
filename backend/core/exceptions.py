"""Permission pipeline exceptions.

Each layer in the 7-layer permission pipeline raises a typed exception
on denial, enabling precise error handling and XAI logging.
"""


class PermissionError(Exception):
    """Base class for all permission pipeline denials."""
    def __init__(self, layer: str, reason: str) -> None:
        self.layer = layer
        self.reason = reason
        super().__init__(f"[{layer}] {reason}")


class PathTraversalError(PermissionError):
    """Path traversal or symlink escape detected."""
    def __init__(self, reason: str) -> None:
        super().__init__("PermissionEnforcer", reason)


class WorkspaceBoundaryError(PermissionError):
    """Tool attempted to access outside workspace boundary."""
    def __init__(self, reason: str) -> None:
        super().__init__("PermissionEnforcer", reason)


class ScopeViolationError(PermissionError):
    """Target, port, or protocol not in engagement scope."""
    def __init__(self, reason: str) -> None:
        super().__init__("ScopeEnforcer", reason)


class StealthViolationError(PermissionError):
    """Tool not allowed at current stealth level."""
    def __init__(self, reason: str) -> None:
        super().__init__("StealthEnforcer", reason)


class ToolPermissionError(PermissionError):
    """Agent calling tool outside its declared namespace."""
    def __init__(self, reason: str) -> None:
        super().__init__("NamespaceEnforcer", reason)


class HookDeniedError(PermissionError):
    """Pre-tool hook denied the execution."""
    def __init__(self, reason: str) -> None:
        super().__init__("HookRunner", reason)


class HumanGateRequired(PermissionError):
    """HumanConfirmGate requires operator confirmation."""
    def __init__(self, reason: str) -> None:
        super().__init__("HumanConfirmGate", reason)


class MaxRequestsExceeded(PermissionError):
    """VerificationLoop exceeded max_requests_per_finding."""
    def __init__(self, reason: str) -> None:
        super().__init__("VerificationPolicy", reason)
