"""Test agent decisions with mocked scan tools and enforced scope boundaries."""


import unittest
from unittest.mock import patch

from agent.controller import VulnScopeAgent
from security.executor import ScanExecutor


class TestVulnScopeAgent(unittest.TestCase):
    """Check conditional agent requests and rejection of prohibited scans."""

    @patch("security.executor.inspect_http_headers")
    @patch("security.executor.scan_port")
    def test_open_http_port_triggers_check(
        self, mock_tcp, mock_http
    ):
        mock_tcp.return_value = {
            "target": "127.0.0.1",
            "port": 8000,
            "protocol": "TCP",
            "status": "OPEN",
            "response_time_ms": 1.0
        }

        mock_http.return_value = {
            "status": "COMPLETED",
            "findings": []
        }

        agent = VulnScopeAgent()
        report = agent.run("127.0.0.1", [8000])

        self.assertEqual(
            report["decisions"][0]["decision"],
            "REQUEST_HTTP_CHECK"
        )

        mock_http.assert_called_once()

    @patch("security.executor.inspect_http_headers")
    @patch("security.executor.scan_port")
    def test_unknown_port_skips_http(
        self, mock_tcp, mock_http
    ):
        mock_tcp.return_value = {
            "target": "127.0.0.1",
            "port": 8000,
            "status": "UNKNOWN"
        }

        agent = VulnScopeAgent()
        report = agent.run("127.0.0.1", [8000])

        self.assertEqual(
            report["decisions"][0]["decision"],
            "STOP"
        )

        mock_http.assert_not_called()

    @patch("security.executor.inspect_http_headers")
    @patch("security.executor.scan_port")
    def test_unauthorised_target_is_blocked(
        self, mock_tcp, mock_http
    ):
        agent = VulnScopeAgent()
        report = agent.run("192.168.1.10", [8000])

        self.assertEqual(
            report["decisions"][0]["decision"],
            "SKIP"
        )

        mock_tcp.assert_not_called()
        mock_http.assert_not_called()

    @patch("security.executor.inspect_http_headers")
    @patch("security.executor.scan_port")
    def test_unauthorised_port_is_blocked(
        self, mock_tcp, mock_http
    ):
        agent = VulnScopeAgent()
        report = agent.run("127.0.0.1", [22])

        self.assertEqual(
            report["decisions"][0]["decision"],
            "SKIP"
        )

        mock_tcp.assert_not_called()
        mock_http.assert_not_called()

    @patch("security.executor.inspect_http_headers")
    @patch("security.executor.scan_port")
    def test_action_limit_blocks_followup(
        self, mock_tcp, mock_http
    ):
        mock_tcp.return_value = {
            "target": "127.0.0.1",
            "port": 8000,
            "status": "OPEN"
        }

        from security.policy import ScopePolicy

        executor = ScanExecutor(
            ScopePolicy(max_actions=1)
        )

        agent = VulnScopeAgent(executor)
        report = agent.run("127.0.0.1", [8000])

        self.assertEqual(
            report["observations"][-1]["result"]["status"],
            "DENIED"
        )

        mock_http.assert_not_called()


if __name__ == "__main__":
    unittest.main()
