"""Build and persist per-run JSON reports from agent observations and audits."""


import json
from datetime import datetime, timezone
from pathlib import Path


def build_report(agent_result):
    """Aggregate observations, findings, decisions and per-run policy audit counts."""

    findings = []

    # Combine port-based review prompts with observations from HTTP inspection.
    for observation in agent_result["observations"]:
        if observation.get("check") == "http_headers":
            result = observation["result"]
            findings.extend(result.get("findings", []))
        else:
            findings.extend(observation.get("findings", []))

    return {
        "schema_version": "1.0",
        "tool": "VulnScope",
        "generated_at": datetime.now(
            timezone.utc
        ).isoformat(),
        "target": agent_result["target"],
        "observations": agent_result["observations"],
        "findings": findings,
        "agent_decisions": agent_result["decisions"],
        "policy_audit_log": agent_result["audit_log"],
        "summary": {
            "observations": len(agent_result["observations"]),
            "findings": len(findings),
            # Policy approvals count permitted attempts, not successful network execution.
            "approved_actions": sum(
                1 for event in agent_result["audit_log"]
                if event["permitted"]
            ),
            "denied_actions": sum(
                1 for event in agent_result["audit_log"]
                if not event["permitted"]
            )
        }
    }


def save_report(report, output_directory="reports"):
    """Write the report as a new timestamped UTF-8 JSON file in output_directory."""

    directory = Path(output_directory)
    directory.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now(timezone.utc).strftime(
        "%Y%m%d_%H%M%S_%f"
    )

    file_path = directory / f"vulnscope_{timestamp}.json"

    # Exclusive creation prevents accidentally overwriting a report.
    with file_path.open("x", encoding="utf-8") as file:
        json.dump(report, file, indent=4)

    return file_path
