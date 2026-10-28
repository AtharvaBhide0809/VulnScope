"""Produce low-confidence, port-based security review observations."""


from analysis.services import identify_service


# These rules prompt further review; matching a port is not evidence of a CVE.
RISK_RULES = {
    21: {
        "risk": "FTP may use unencrypted communication",
        "severity": "REVIEW",
        "recommendation": "Verify encryption and consider SFTP."
    },
    23: {
        "risk": "Telnet may expose unencrypted sessions",
        "severity": "REVIEW",
        "recommendation": "Verify the service and prefer SSH."
    },
    80: {
        "risk": "HTTP may expose unencrypted traffic",
        "severity": "REVIEW",
        "recommendation": "Check HTTPS support and redirection."
    },
    8000: {
        "risk": "Possible HTTP service requires inspection",
        "severity": "INFO",
        "recommendation": "Inspect HTTP headers and TLS usage."
    },
    8080: {
        "risk": "Possible web or proxy service",
        "severity": "INFO",
        "recommendation": "Verify service identity and access."
    }
}


def analyse_scan(scan_result):
    """Return a service hint and potential risks, never a confirmed vulnerability."""

    service_info = identify_service(scan_result)

    findings = []

    if scan_result["status"] != "OPEN":
        return {
            "scan": scan_result,
            "service": service_info,
            "findings": findings
        }

    port = scan_result["port"]

    if port in RISK_RULES:
        rule = RISK_RULES[port]

        # Port mapping alone cannot establish an exploitable vulnerability.
        findings.append({
            "id": f"PORT-{port}",
            "type": "POTENTIAL_RISK",
            "severity": rule["severity"],
            "description": rule["risk"],
            "recommendation": rule["recommendation"],
            "confidence": "LOW",
            "confirmed_vulnerability": False
        })

    return {
        "scan": scan_result,
        "service": service_info,
        "findings": findings
    }
