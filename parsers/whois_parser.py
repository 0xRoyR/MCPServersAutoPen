"""
Parser for WHOIS tool output.

Extracts domain registration information from WHOIS lookup results.
"""

import re
import uuid
import json
from datetime import datetime
from database import get_db


def parse_whois_output(output: str, domain: str) -> dict:
    """
    Parse WHOIS output and store results in database.

    Args:
        output: Raw WHOIS command output
        domain: The domain that was queried

    Returns:
        dict with parsed data and database UUID
    """
    parsed = {
        "uuid": str(uuid.uuid4()),
        "domain": domain.lower(),
        "registrar": None,
        "creation_date": None,
        "expiration_date": None,
        "name_servers": None,
        "registrant_name": None,
        "registrant_org": None,
        "registrant_country": None,
        "raw_output": output,
        "scanned_at": datetime.utcnow().isoformat(),
    }

    # Parse registrar
    registrar_match = re.search(r"Registrar:\s*(.+)", output, re.IGNORECASE)
    if registrar_match:
        parsed["registrar"] = registrar_match.group(1).strip()

    # Parse creation date
    creation_patterns = [
        r"Creation Date:\s*(.+)",
        r"Created:\s*(.+)",
        r"Created Date:\s*(.+)",
        r"Registration Date:\s*(.+)",
    ]
    for pattern in creation_patterns:
        match = re.search(pattern, output, re.IGNORECASE)
        if match:
            parsed["creation_date"] = match.group(1).strip()
            break

    # Parse expiration date
    expiry_patterns = [
        r"Registry Expiry Date:\s*(.+)",
        r"Expiration Date:\s*(.+)",
        r"Expiry Date:\s*(.+)",
        r"Expires:\s*(.+)",
    ]
    for pattern in expiry_patterns:
        match = re.search(pattern, output, re.IGNORECASE)
        if match:
            parsed["expiration_date"] = match.group(1).strip()
            break

    # Parse name servers
    ns_matches = re.findall(r"Name Server:\s*(.+)", output, re.IGNORECASE)
    if ns_matches:
        name_servers = [ns.strip().lower() for ns in ns_matches]
        parsed["name_servers"] = json.dumps(name_servers)

    # Parse registrant info
    registrant_name_match = re.search(r"Registrant Name:\s*(.+)", output, re.IGNORECASE)
    if registrant_name_match:
        parsed["registrant_name"] = registrant_name_match.group(1).strip()

    registrant_org_match = re.search(r"Registrant Organi[sz]ation:\s*(.+)", output, re.IGNORECASE)
    if registrant_org_match:
        parsed["registrant_org"] = registrant_org_match.group(1).strip()

    registrant_country_match = re.search(r"Registrant Country:\s*(.+)", output, re.IGNORECASE)
    if registrant_country_match:
        parsed["registrant_country"] = registrant_country_match.group(1).strip()

    # Store in database
    db = get_db()
    db.insert("whois_results", parsed)

    return parsed
