"""Demonstrate approved and denied scans with run-specific JSON evidence."""


from agent.controller import VulnScopeAgent
from reporting.json_report import build_report, save_report


def main():
    """Exercise approved and denied scan requests and save the corresponding reports."""
    print("VulnScope - Security Boundary Demonstration")
    print("-" * 50)

    agent = VulnScopeAgent()

    print("\n1. Authorised target with mixed permissions")

    local_result = agent.run(
        "127.0.0.1",
        [8000, 22]
    )

    local_report = build_report(local_result)

    for decision in local_result["decisions"]:
        print(decision)

    assert any(
        event["port"] == 8000 and event["permitted"]
        for event in local_result["audit_log"]
    )

    assert any(
        event["port"] == 22 and not event["permitted"]
        for event in local_result["audit_log"]
    )

    print("\n2. Unauthorised external target")

    # Rejected targets must not consume the session action budget.
    actions_before = agent.executor.actions_used

    external_result = agent.run(
        "192.0.2.10",
        [8000]
    )

    external_report = build_report(external_result)

    assert agent.executor.actions_used == actions_before

    assert all(
        not event["permitted"]
        for event in external_result["audit_log"]
    )

    for event in external_result["audit_log"]:
        print(event)

    print("\n3. Generating evidence reports")

    local_path = save_report(local_report)
    external_path = save_report(external_report)

    print(f"Local report: {local_path}")
    print(f"Denied-target report: {external_path}")

    print("\nLocal action summary:")
    print(local_report["summary"])

    print("\nExternal action summary:")
    print(external_report["summary"])

    print("\nSecurity demonstration PASSED")


if __name__ == "__main__":
    main()
