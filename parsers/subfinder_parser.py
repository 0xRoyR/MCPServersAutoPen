"""
Parser for Subfinder tool output.

Extracts discovered subdomains from Subfinder results.
"""

import uuid
from datetime import datetime
from database import get_db


def parse_subfinder_output(output: str, domain: str) -> list[dict]:
    """
    Parse Subfinder output and store results in database.

    Args:
        output: Raw Subfinder command output (one subdomain per line)
        domain: The parent domain that was queried

    Returns:
        list of dicts with parsed subdomain data
    """
    results = []
    seen = set()  # Deduplicate within this run

    domain = domain.lower()

    for line in output.strip().split("\n"):
        subdomain = line.strip().lower()

        # Skip empty lines and duplicates
        if not subdomain or subdomain in seen:
            continue

        # Validate it looks like a subdomain
        if not subdomain or " " in subdomain:
            continue

        # Ensure it's related to the target domain
        if not subdomain.endswith(domain) and subdomain != domain:
            continue

        seen.add(subdomain)

        parsed = {
            "uuid": str(uuid.uuid4()),
            "domain": domain,
            "subdomain": subdomain,
            "source": "subfinder",
            "scanned_at": datetime.utcnow().isoformat(),
        }

        results.append(parsed)

    # Store in database
    if results:
        db = get_db()
        db.insert_many("subdomains", results)

    return results
