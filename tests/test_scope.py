"""Test that the policy-controlled executor accepts or blocks scan requests."""


import unittest
from unittest.mock import patch

from security.executor import ScanExecutor
from security.policy import ScopePolicy


class TestScopePolicy(unittest.TestCase):
    """Check executor authorisation, action budgets, and audit decisions."""

    def setUp(self):
        """Create a fresh executor so tests do not share budgets or audit events."""
        self.executor = ScanExecutor()

    @patch("security.executor.scan_port")
    def test_authorised_scan(self, mock_scan):
        mock_scan.return_value = {"status": "OPEN"}

        result = self.executor.execute("127.0.0.1", 8000)

        self.assertEqual(result["status"], "OPEN")
        mock_scan.assert_called_once_with(
            "127.0.0.1", 8000, timeout=1
        )

    @patch("security.executor.scan_port")
    def test_unauthorised_target(self, mock_scan):
        result = self.executor.execute("192.168.1.10", 8000)

        self.assertEqual(result["status"], "DENIED")
        mock_scan.assert_not_called()

    @patch("security.executor.scan_port")
    def test_unauthorised_port(self, mock_scan):
        result = self.executor.execute("127.0.0.1", 22)

        self.assertEqual(result["status"], "DENIED")
        mock_scan.assert_not_called()

    @patch("security.executor.scan_port")
    def test_unauthorised_action(self, mock_scan):
        result = self.executor.execute(
            "127.0.0.1", 8000, action="unapproved_test"
        )

        self.assertEqual(result["status"], "DENIED")
        mock_scan.assert_not_called()

    @patch("security.executor.scan_port")
    def test_action_limit(self, mock_scan):
        policy = ScopePolicy(max_actions=2)
        executor = ScanExecutor(policy)

        executor.execute("127.0.0.1", 8000)
        executor.execute("127.0.0.1", 8000)

        result = executor.execute("127.0.0.1", 8000)

        self.assertEqual(result["status"], "DENIED")
        self.assertEqual(mock_scan.call_count, 2)

    @patch("security.executor.scan_port")
    def test_denial_recorded(self, mock_scan):
        self.executor.execute("127.0.0.1", 22)

        event = self.executor.audit_log[-1]

        self.assertFalse(event["permitted"])
        self.assertEqual(
            event["reason"], "Port outside authorised scope"
        )
        mock_scan.assert_not_called()


if __name__ == "__main__":
    unittest.main()
