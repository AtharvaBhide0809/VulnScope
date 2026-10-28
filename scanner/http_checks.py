"""Inspect selected HTTP response headers after caller-side scope approval."""


import http.client


SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "Consider an appropriate policy to restrict "
        "the resources browsers may load."
    ),
    "X-Content-Type-Options": (
        "Consider setting this header to 'nosniff'."
    ),
    "Referrer-Policy": (
        "Consider a policy such as "
        "'strict-origin-when-cross-origin'."
    )
}


def inspect_http_headers(target, port, timeout=1):
    """Send one plain-HTTP request and flag selected missing response headers.

    Call through the executor; this function does not enforce scope.
    """

    # Callers must authorise target and port before reaching this function.
    connection = http.client.HTTPConnection(
        target, port, timeout=timeout
    )

    try:
        connection.request(
            "GET",
            "/",
            headers={"Connection": "close"}
        )

        response = connection.getresponse()

        # HTTP header names are case-insensitive; values are not assessed here.
        headers = {
            name.lower(): value
            for name, value in response.getheaders()
        }

        findings = []

        # Absent headers prompt review but are not confirmed exploitable weaknesses.
        for header, recommendation in SECURITY_HEADERS.items():
            if header.lower() not in headers:
                findings.append({
                    "id": f"MISSING-{header.upper()}",
                    "type": "MISSING_SECURITY_HEADER",
                    "header": header,
                    "severity": "REVIEW",
                    "description": f"{header} header is absent",
                    "recommendation": recommendation,
                    "confirmed_vulnerability": False
                })

        return {
            "target": target,
            "port": port,
            "check": "http_headers",
            "status": "COMPLETED",
            "http_status": response.status,
            "headers": headers,
            "findings": findings
        }

    except (OSError, http.client.HTTPException) as error:
        return {
            "target": target,
            "port": port,
            "check": "http_headers",
            "status": "ERROR",
            "error": type(error).__name__,
            "findings": []
        }

    finally:
        connection.close()
