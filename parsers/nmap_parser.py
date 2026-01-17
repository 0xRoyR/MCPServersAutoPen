"""
Parser for Nmap tool output.

Extracts port and service information from Nmap scan results.
"""

import re
import uuid
from datetime import datetime
from database import get_db


def parse_nmap_output(output: str, host: str) -> list[dict]:
    """
    Parse Nmap output and store results in database.

    Args:
        output: Raw Nmap command output
        host: The host/IP that was scanned

    Returns:
        list of dicts with parsed port data
    """
    results = []

    # Try to extract the resolved IP address
    ip_match = re.search(r"Nmap scan report for .+?\((\d+\.\d+\.\d+\.\d+)\)", output)
    if not ip_match:
        # Try alternate format
        ip_match = re.search(r"Nmap scan report for (\d+\.\d+\.\d+\.\d+)", output)

    ip_address = ip_match.group(1) if ip_match else None

    # Parse port lines: "80/tcp   open  http    Apache httpd 2.4.41"
    # Format: PORT/PROTOCOL  STATE  SERVICE  VERSION
    port_pattern = re.compile(
        r"(\d+)/(tcp|udp)\s+"  # Port and protocol
        r"(\w+)\s+"            # State (open, closed, filtered)
        r"(\S+)"               # Service name
        r"(?:\s+(.+))?"        # Optional version info
    )

    for line in output.split("\n"):
        match = port_pattern.match(line.strip())
        if match:
            port_num = int(match.group(1))
            protocol = match.group(2)
            state = match.group(3)
            service = match.group(4)
            version = match.group(5).strip() if match.group(5) else None

            parsed = {
                "uuid": str(uuid.uuid4()),
                "host": host.lower(),
                "ip_address": ip_address,
                "port": port_num,
                "protocol": protocol,
                "state": state,
                "service": service,
                "version": version,
                "scanned_at": datetime.utcnow().isoformat(),
            }

            results.append(parsed)

    # Store in database
    if results:
        db = get_db()
        db.insert_many("ports", results)

    return results
