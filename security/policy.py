"""Define the target, port, action, and timeout rules for approved scans."""

from dataclasses import dataclass


@dataclass(frozen=True)
class ScopePolicy:
    """Store scan restrictions and evaluate proposed network actions.

    These checks protect calls routed through the controlled executor;
    they are not a process-level or network-level sandbox.
    """

    allowed_targets: frozenset = frozenset({"127.0.0.1"})
    allowed_ports: frozenset = frozenset({8000, 8080})
    allowed_actions: frozenset = frozenset({
        "tcp_connect",
        "http_headers"
    })
    max_timeout: float = 2.0
    max_actions: int = 20

    def validate(self, target, port, action, timeout):
        """Return (permitted, reason) for the proposed scan action."""

        if type(target) is not str:
            return False, "Invalid target"

        # Match the exact authorised target; being reachable is not permission.
        if target not in self.allowed_targets:
            return False, "Target outside authorised scope"

        if type(port) is not int:
            return False, "Invalid port"

        if port not in self.allowed_ports:
            return False, "Port outside authorised scope"

        if type(action) is not str:
            return False, "Invalid action"

        if action not in self.allowed_actions:
            return False, "Action not authorised"

        # Reject non-numeric values, including bool, before checking the limit.
        if type(timeout) not in (int, float):
            return False, "Invalid timeout"

        if not 0 < timeout <= self.max_timeout:
            return False, "Timeout outside permitted range"

        return True, "Authorised"
