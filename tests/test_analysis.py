"""Test port-based service hints and preliminary risk observations."""


import unittest

from analysis.services import identify_service
from analysis.risk_rules import analyse_scan


class TestSecurityAnalysis(unittest.TestCase):
    """Verify service inference and unconfirmed risk classifications."""

    def test_known_open_port(self):
        scan = {"port": 8000, "status": "OPEN"}

        result = identify_service(scan)

        self.assertEqual(
            result["service"], "Alternative HTTP"
        )
        self.assertEqual(result["confidence"], "LOW")

    def test_unknown_service(self):
        scan = {"port": 9999, "status": "OPEN"}

        result = identify_service(scan)

        self.assertEqual(result["service"], "Unknown")

    def test_closed_port_has_no_service(self):
        scan = {"port": 8000, "status": "CLOSED"}

        result = identify_service(scan)

        self.assertIsNone(result["service"])

    def test_risk_detection(self):
        scan = {"port": 8000, "status": "OPEN"}

        result = analyse_scan(scan)

        self.assertEqual(len(result["findings"]), 1)
        self.assertEqual(
            result["findings"][0]["severity"], "INFO"
        )

    def test_no_findings_for_closed_port(self):
        scan = {"port": 8000, "status": "CLOSED"}

        result = analyse_scan(scan)

        self.assertEqual(result["findings"], [])

    def test_no_confirmed_vulnerability(self):
        scan = {"port": 23, "status": "OPEN"}

        result = analyse_scan(scan)

        self.assertFalse(
            result["findings"][0]["confirmed_vulnerability"]
        )


if __name__ == "__main__":
    unittest.main()
