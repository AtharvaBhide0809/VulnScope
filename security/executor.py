"""Enforce scope policy before dispatching TCP and HTTP scan actions."""

from scanner.ports import scan_port
from scanner.http_checks import inspect_http_headers
from security.policy import ScopePolicy


class ScanExecutor:
    """Authorise scanning actions and track a shared assessment session."""

    def __init__(self, policy=None):
        self.policy = policy if policy is not None else ScopePolicy()
        self.actions_used = 0
        self.audit_log = []
        self._session_open = True

    def close_session(self):
        """Close the current assessment session to further execution."""
        if not self._session_open:
            raise RuntimeError("Session is already closed")

        self._session_open = False

    def start_session(self):
        """Start a new assessment session with a fresh action budget."""
        if self._session_open:
            raise RuntimeError("Close the current session first")

        # Session resets must be controlled by trusted application code.
        self.actions_used = 0
        self.audit_log = []
        self._session_open = True

    def execute(self, target, port, action="tcp_connect", timeout=1):
        """Authorise a request, audit the decision, then run an approved tool."""
        if not self._session_open:
            raise RuntimeError("Cannot execute in a closed session")

        permitted, reason = self.policy.validate(
            target, port, action, timeout
        )

        # Runs in the same session share one action budget.
        if permitted and self.actions_used >= self.policy.max_actions:
            permitted = False
            reason = "Scan action limit reached"

        # This records authorisation, not whether the network action succeeds.
        event = {
            "target": target,
            "port": port,
            "action": action,
            "permitted": permitted,
            "reason": reason
        }

        self.audit_log.append(event)

        if not permitted:
            return {
                "status": "DENIED",
                "reason": reason
            }

        # Count each approved attempt, even if the network operation later fails.
        self.actions_used += 1

        if action == "tcp_connect":
            return scan_port(target, port, timeout=timeout)

        if action == "http_headers":
            return inspect_http_headers(
                target, port, timeout=timeout
            )

        # Fail explicitly if the policy ever allows a tool not implemented here.
        raise ValueError("Unsupported scan action")
