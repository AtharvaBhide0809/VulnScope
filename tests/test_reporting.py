"""Test JSON reporting summaries and persistence using synthetic scan results."""


import json
import tempfile
import unittest
from pathlib import Path

from reporting.json_report import build_report, save_report


class TestReporting(unittest.TestCase):
    """Verify summary counting and that JSON reports can be saved and read."""

    def setUp(self):
        """Create synthetic observations and audit events shared by reporting tests."""
        self.agent_result = {
            "target": "127.0.0.1",
            "observations": [
                {
                    "scan": {
                        "target": "127.0.0.1",
                        "port": 8000,
                        "status": "OPEN"
                    },
                    "findings": [
                        {
                            "id": "PORT-8000",
                            "severity": "INFO"
                        }
                    ]
                },
                {
                    "check": "http_headers",
                    "result": {
                        "status": "COMPLETED",
                        "findings": [
                            {
                                "id": "MISSING-CSP",
                                "severity": "REVIEW"
                            }
                        ]
                    }
                }
            ],
            "decisions": [
                {
                    "port": 8000,
                    "decision": "REQUEST_HTTP_CHECK"
                }
            ],
            "audit_log": [
                {
                    "action": "tcp_connect",
                    "permitted": True
                },
                {
                    "action": "http_headers",
                    "permitted": True
                }
            ]
        }

    def test_findings_collected(self):
        report = build_report(self.agent_result)

        self.assertEqual(len(report["findings"]), 2)

    def test_action_summary(self):
        report = build_report(self.agent_result)

        self.assertEqual(
            report["summary"]["approved_actions"], 2
        )
        self.assertEqual(
            report["summary"]["denied_actions"], 0
        )

    def test_denied_action_counted(self):
        self.agent_result["audit_log"].append({
            "action": "http_headers",
            "permitted": False
        })

        report = build_report(self.agent_result)

        self.assertEqual(
            report["summary"]["denied_actions"], 1
        )

    def test_json_saved_and_readable(self):
        report = build_report(self.agent_result)

        with tempfile.TemporaryDirectory() as temp_dir:
            path = save_report(report, temp_dir)

            self.assertTrue(Path(path).exists())

            with open(path, encoding="utf-8") as file:
                loaded = json.load(file)

            self.assertEqual(
                loaded["target"], "127.0.0.1"
            )
            self.assertEqual(
                len(loaded["findings"]), 2
            )


if __name__ == "__main__":
    unittest.main()
