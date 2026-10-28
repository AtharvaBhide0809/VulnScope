"""Choose follow-up checks from TCP observations using a controlled executor."""


from analysis.risk_rules import analyse_scan
from security.executor import ScanExecutor


class VulnScopeAgent:
    """Select scan follow-ups from observations; delegate all actions to the executor."""

    HTTP_PORTS = frozenset({80, 443, 8000, 8080})

    def __init__(self, executor=None):
        """Use a supplied policy-controlled executor, or create one for this agent."""
        self.executor = (
            executor if executor is not None
            else ScanExecutor()
        )

    def run(self, target, ports):
        """Perform authorised TCP checks and conditional HTTP follow-ups for one run."""
        observations = []
        decisions = []

        # Keep each run's audit history separate from earlier runs in the session.
        audit_start = len(self.executor.audit_log)

        for port in ports:
            tcp_result = self.executor.execute(
                target,
                port,
                action="tcp_connect"
            )

            if tcp_result["status"] == "DENIED":
                decisions.append({
                    "port": port,
                    "decision": "SKIP",
                    "reason": tcp_result["reason"]
                })
                continue

            analysis = analyse_scan(tcp_result)
            observations.append(analysis)

            if tcp_result["status"] != "OPEN":
                decisions.append({
                    "port": port,
                    "decision": "STOP",
                    "reason": "TCP service not confirmed open"
                })
                continue

            # Port conventions guide follow-up selection; they do not identify a service.
            if port not in self.HTTP_PORTS:
                decisions.append({
                    "port": port,
                    "decision": "STOP",
                    "reason": "No suitable follow-up check"
                })
                continue

            decisions.append({
                "port": port,
                "decision": "REQUEST_HTTP_CHECK",
                "reason": "Open port commonly associated with HTTP"
            })

            # A proposed follow-up still needs independent executor authorisation.
            http_result = self.executor.execute(
                target,
                port,
                action="http_headers"
            )

            decisions.append({
                "port": port,
                "decision": "HTTP_CHECK_RESULT",
                "reason": (
                    "HTTP action was denied"
                    if http_result["status"] == "DENIED"
                    else "HTTP execution returned a result"
                ),
                "outcome": http_result["status"]
            })


            observations.append({
                "check": "http_headers",
                "result": http_result
            })

        return {
            "target": target,
            "observations": observations,
            "decisions": decisions,
            "audit_log": list(self.executor.audit_log[audit_start:])
        }
