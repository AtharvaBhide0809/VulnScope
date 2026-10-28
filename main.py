"""Run the local VulnScope assessment and display and save its findings."""


from agent.controller import VulnScopeAgent
from reporting.json_report import build_report, save_report


def main():
    """Run a localhost assessment, print observations and persist its JSON report."""
    agent = VulnScopeAgent()

    target = "127.0.0.1"
    ports = [8000, 8080]

    print("VulnScope v1.0 - Agentic Security Scanner")
    print(f"Target: {target}")
    print("-" * 50)

    report = agent.run(target, ports)

    print("\nAgent decisions:")

    for decision in report["decisions"]:
        print(
            f"Port {decision['port']}: "
            f"{decision['decision']}"
        )
        print(f"Reason: {decision['reason']}")

    print("\nScan observations:")

    for observation in report["observations"]:
        if observation.get("check") == "http_headers":
            result = observation["result"]

            print(f"\nHTTP check: {result['status']}")

            for finding in result.get("findings", []):
                print(f"Finding: {finding['description']}")
        else:
            scan = observation["scan"]

            print(
                f"TCP port {scan['port']}: "
                f"{scan['status']}"
            )

    print("\nPolicy audit log:")

    for event in report["audit_log"]:
        print(event)

    json_report = build_report(report)
    saved_path = save_report(json_report)

    print("\nReport generated successfully.")
    print(f"Saved to: {saved_path}")

    summary = json_report["summary"]

    print(f"Observations: {summary['observations']}")
    print(f"Findings: {summary['findings']}")
    print(f"Approved actions: {summary['approved_actions']}")
    print(f"Denied actions: {summary['denied_actions']}")


if __name__ == "__main__":
    main()
