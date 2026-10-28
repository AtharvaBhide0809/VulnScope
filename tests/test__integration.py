"""Integration tests for agent decisions, policy enforcement, reporting, and sessions."""


import json
import tempfile
import unittest

from pathlib import Path
from unittest.mock import patch

from agent.controller import VulnScopeAgent
from security.executor import ScanExecutor
from security.policy import ScopePolicy
from reporting.json_report import build_report, save_report


class TestIntegration(unittest.TestCase):
    """Exercise cross-module reporting, scope enforcement, and session state."""

    @patch("security.executor.inspect_http_headers")
    @patch("security.executor.scan_port")
    def test_mixed_authorised_and_denied_actions(
        self, mock_tcp, mock_http
    ):
        """Verify mixed-permission scans, tool calls and persisted report counts."""
        mock_tcp.return_value = {
            "target": "127.0.0.1",
            "port": 8000,
            "protocol": "TCP",
            "status": "OPEN",
            "response_time_ms": 1.0
        }

        mock_http.return_value = {
            "target": "127.0.0.1",
            "port": 8000,
            "check": "http_headers",
            "status": "COMPLETED",
            "http_status": 200,
            "findings": [
                {
                    "id": "MISSING-TEST-HEADER",
                    "confirmed_vulnerability": False
                }
            ]
        }

        agent = VulnScopeAgent()

        result = agent.run(
            "127.0.0.1", [8000, 22]
        )

        mock_tcp.assert_called_once_with(
            "127.0.0.1", 8000, timeout=1
        )

        mock_http.assert_called_once_with(
            "127.0.0.1", 8000, timeout=1
        )

        report = build_report(result)

        self.assertEqual(
            report["summary"]["approved_actions"], 2
        )
        self.assertEqual(
            report["summary"]["denied_actions"], 1
        )

        self.assertTrue(any(
            decision["port"] == 22
            and decision["decision"] == "SKIP"
            for decision in report["agent_decisions"]
        ))

        self.assertTrue(any(
            event["port"] == 22
            and not event["permitted"]
            for event in report["policy_audit_log"]
        ))

        with tempfile.TemporaryDirectory() as temp_dir:
            path = save_report(report, temp_dir)

            loaded = json.loads(
                Path(path).read_text(encoding="utf-8")
            )

            self.assertEqual(
                loaded["summary"]["denied_actions"], 1
            )

            self.assertEqual(
                loaded["summary"]["approved_actions"], 2
            )


    @patch("security.executor.inspect_http_headers")
    @patch("security.executor.scan_port")
    def test_budget_denial_recorded_in_report(
        self, mock_tcp, mock_http
    ):
        """Verify a proposed follow-up is denied and included in the report."""
        mock_tcp.return_value = {
            "target": "127.0.0.1",
            "port": 8000,
            "status": "OPEN"
        }

        policy = ScopePolicy(max_actions=1)
        executor = ScanExecutor(policy)
        agent = VulnScopeAgent(executor)

        result = agent.run("127.0.0.1", [8000])

        report = build_report(result)

        mock_tcp.assert_called_once()

        mock_http.assert_not_called()

        self.assertEqual(
            report["summary"]["approved_actions"], 1
        )

        self.assertEqual(
            report["summary"]["denied_actions"], 1
        )

        self.assertTrue(any(
            decision["decision"] == "HTTP_CHECK_RESULT"
            and decision["outcome"] == "DENIED"
            for decision in report["agent_decisions"]
        ))

        self.assertTrue(any(
            event["reason"] == "Scan action limit reached"
            for event in report["policy_audit_log"]
        ))


    @patch("security.executor.scan_port")
    def test_reused_agent_separates_run_logs(self, mock_tcp):
        """Verify cumulative session limits and independent per-run audit slices."""
        mock_tcp.return_value = {
            "target": "127.0.0.1",
            "port": 8000,
            "status": "UNKNOWN"
        }

        executor = ScanExecutor(ScopePolicy(max_actions=2))
        agent = VulnScopeAgent(executor)

        first = agent.run("127.0.0.1", [8000])
        second = agent.run("127.0.0.1", [8000])
        # The third run shares the exhausted session budget, but not earlier audit rows.
        third = agent.run("127.0.0.1", [8000])

        self.assertEqual(len(first["audit_log"]), 1)
        self.assertEqual(len(second["audit_log"]), 1)
        self.assertEqual(len(third["audit_log"]), 1)

        self.assertEqual(executor.actions_used, 2)
        self.assertEqual(mock_tcp.call_count, 2)

        self.assertEqual(
            build_report(second)["summary"]["approved_actions"], 1
        )
        self.assertEqual(
            build_report(third)["summary"]["denied_actions"], 1
        )

    @patch("security.executor.scan_port")
    def test_explicit_session_lifecycle(self, mock_tcp):
        """Verify closed sessions refuse work and a trusted restart resets session state."""
        mock_tcp.return_value = {
            "target": "127.0.0.1",
            "port": 8000,
            "status": "UNKNOWN"
        }

        executor = ScanExecutor(ScopePolicy(max_actions=1))
        agent = VulnScopeAgent(executor)

        agent.run("127.0.0.1", [8000])
        executor.close_session()

        with self.assertRaises(RuntimeError):
            agent.run("127.0.0.1", [8000])

        executor.start_session()

        self.assertEqual(executor.actions_used, 0)
        self.assertEqual(executor.audit_log, [])

        second = agent.run("127.0.0.1", [8000])

        self.assertEqual(executor.actions_used, 1)
        self.assertEqual(len(second["audit_log"]), 1)
        self.assertEqual(mock_tcp.call_count, 2)
