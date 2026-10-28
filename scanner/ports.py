"""Perform a single TCP connect check and return a structured observation."""


import socket
import time


def scan_port(host, port, timeout=1):
    """Attempt one TCP connection and return its status and elapsed time."""

    if not isinstance(port, int) or isinstance(port, bool):
        raise ValueError("Port must be an integer")

    if not 1 <= port <= 65535:
        raise ValueError("Port must be between 1 and 65535")

    if not isinstance(timeout, (int, float)) or isinstance(timeout, bool):
        raise ValueError("Timeout must be numeric")

    if not 0 < timeout <= 10:
        raise ValueError("Timeout must be between 0 and 10 seconds")

    start_time = time.perf_counter()

    try:
        with socket.create_connection((host, port),timeout=timeout):
            status = "OPEN"

    except ConnectionRefusedError:
        status = "CLOSED"

    # No response within the timeout does not establish that the port is closed.
    except TimeoutError:
        status = "UNKNOWN"

    except OSError:
        status = "ERROR"

    end_time = time.perf_counter()

    # Measure elapsed time for failed attempts as well as successful connections.
    response_time = round((end_time - start_time) * 1000, 2)

    return {
        "target": host,
        "port": port,
        "protocol": "TCP",
        "status": status,
        "response_time_ms": response_time
    }
