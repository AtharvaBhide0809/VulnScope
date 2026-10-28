"""Test TCP connection outcomes and input validation without live networking."""


import unittest
from unittest.mock import patch, MagicMock

from scanner.ports import scan_port


class TestPortScanner(unittest.TestCase):
    """Simulate TCP outcomes to keep unit tests independent of the network."""

    @patch("scanner.ports.socket.create_connection")
    def test_open_port(self, mock_connection):
        mock_socket = MagicMock()
        mock_connection.return_value = mock_socket

        result = scan_port("127.0.0.1", 8000)

        self.assertEqual(result["status"], "OPEN")
        self.assertEqual(result["port"], 8000)
        self.assertEqual(result["protocol"], "TCP")

    @patch("scanner.ports.socket.create_connection")
    def test_closed_port(self, mock_connection):
        mock_connection.side_effect = ConnectionRefusedError()

        result = scan_port("127.0.0.1", 8000)

        self.assertEqual(result["status"], "CLOSED")

    @patch("scanner.ports.socket.create_connection")
    def test_timeout(self, mock_connection):
        mock_connection.side_effect = TimeoutError()

        result = scan_port("127.0.0.1", 8000)

        self.assertEqual(result["status"], "UNKNOWN")

    @patch("scanner.ports.socket.create_connection")
    def test_network_error(self, mock_connection):
        mock_connection.side_effect = OSError("Network error")

        result = scan_port("127.0.0.1", 8000)

        self.assertEqual(result["status"], "ERROR")

    def test_invalid_port(self):
        with self.assertRaises(ValueError):
            scan_port("127.0.0.1", 70000)

    def test_invalid_timeout(self):
        with self.assertRaises(ValueError):
            scan_port("127.0.0.1", 8000, timeout=-1)

    @patch("scanner.ports.socket.create_connection")
    def test_response_time(self, mock_connection):
        result = scan_port("127.0.0.1", 8000)

        self.assertIn("response_time_ms", result)
        self.assertGreaterEqual(result["response_time_ms"], 0)


if __name__ == "__main__":
    unittest.main()
