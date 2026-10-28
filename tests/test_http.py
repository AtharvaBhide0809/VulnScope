"""Test HTTP response inspection and executor approval using mocks."""


import unittest
from unittest.mock import patch, MagicMock

from scanner.http_checks import inspect_http_headers
from security.executor import ScanExecutor


class TestHTTPChecks(unittest.TestCase):
    """Verify HTTP header observations and that denied requests never reach tools."""

    @patch("scanner.http_checks.http.client.HTTPConnection")
    def test_missing_headers(self, mock_http):
        response = MagicMock()
        response.status = 200
        response.getheaders.return_value = [
            ("Content-Type", "text/html")
        ]

        mock_http.return_value.getresponse.return_value = response

        result = inspect_http_headers("127.0.0.1", 8000)

        self.assertEqual(result["status"], "COMPLETED")
        self.assertEqual(result["http_status"], 200)
        self.assertEqual(len(result["findings"]), 3)

    @patch("scanner.http_checks.http.client.HTTPConnection")
    def test_all_headers_present(self, mock_http):
        response = MagicMock()
        response.status = 200
        response.getheaders.return_value = [
            ("Content-Security-Policy", "default-src 'self'"),
            ("X-Content-Type-Options", "nosniff"),
            ("Referrer-Policy", "no-referrer")
        ]

        mock_http.return_value.getresponse.return_value = response

        result = inspect_http_headers("127.0.0.1", 8000)

        self.assertEqual(result["findings"], [])

    @patch("scanner.http_checks.http.client.HTTPConnection")
    def test_connection_error(self, mock_http):
        mock_http.return_value.request.side_effect = OSError(
            "Connection failed"
        )

        result = inspect_http_headers("127.0.0.1", 8000)

        self.assertEqual(result["status"], "ERROR")
        self.assertEqual(result["findings"], [])
        mock_http.return_value.close.assert_called_once()

    @patch("security.executor.inspect_http_headers")
    def test_authorised_http_check(self, mock_check):
        mock_check.return_value = {"status": "COMPLETED"}

        executor = ScanExecutor()
        result = executor.execute(
            "127.0.0.1", 8000, action="http_headers"
        )

        self.assertEqual(result["status"], "COMPLETED")
        mock_check.assert_called_once_with(
            "127.0.0.1", 8000, timeout=1
        )

    @patch("security.executor.inspect_http_headers")
    def test_blocked_target_no_http_request(self, mock_check):
        executor = ScanExecutor()

        result = executor.execute(
            "192.168.1.10", 8000, action="http_headers"
        )

        self.assertEqual(result["status"], "DENIED")
        mock_check.assert_not_called()

    @patch("security.executor.inspect_http_headers")
    def test_blocked_port_no_http_request(self, mock_check):
        executor = ScanExecutor()

        result = executor.execute(
            "127.0.0.1", 9000, action="http_headers"
        )

        self.assertEqual(result["status"], "DENIED")
        mock_check.assert_not_called()

    @patch("security.executor.inspect_http_headers")
    def test_http_action_limit(self, mock_check):
        executor = ScanExecutor()

        executor.actions_used = executor.policy.max_actions

        result = executor.execute(
            "127.0.0.1", 8000, action="http_headers"
        )

        self.assertEqual(result["status"], "DENIED")
        mock_check.assert_not_called()


if __name__ == "__main__":
    unittest.main()
