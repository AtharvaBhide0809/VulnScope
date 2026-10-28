"""Suggest possible services from common TCP port conventions."""


# Port numbers suggest common services; no application fingerprinting occurs.
COMMON_SERVICES = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    443: "HTTPS",
    445: "SMB",
    3389: "RDP",
    8000: "Alternative HTTP",
    8080: "Alternative HTTP / Proxy"
}


def identify_service(scan_result):
    """Infer a possible service only for an open port; do not fingerprint it."""

    if scan_result["status"] != "OPEN":
        return {
            "service": None,
            "confidence": "NONE",
            "method": "NOT_TESTED"
        }

    port = scan_result["port"]

    service = COMMON_SERVICES.get(port, "Unknown")

    return {
        "service": service,
        "confidence": "LOW" if service != "Unknown" else "NONE",
        "method": "PORT_MAPPING"
    }
