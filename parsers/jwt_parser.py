"""
Parser for jwt_tool output.

Extracts token information, cracked secrets, and tampered tokens from jwt_tool results.
"""

import re
import uuid
from datetime import datetime
from database import get_db


def clean_ansi_codes(text: str) -> str:
    """
    Remove ANSI escape sequences (terminal colors/formatting) from output.
    """
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    return ansi_escape.sub('', text)


def parse_jwt_output(output: str, target_uuid: str, host: str, token: str) -> list[dict]:
    """
    Parse jwt_tool output and store results in database.

    Args:
        output: Raw jwt_tool command output
        target_identifier: The target context (e.g., the URL or app the token belongs to)

    Returns:
        list of dicts with parsed JWT findings
    """
    results = []

    # 1. Clean the raw output from terminal noise
    clean_output = clean_ansi_codes(output)

    # 2. Extract the Algorithm used (e.g., "HS256", "RS256", "None")
    alg_pattern = re.search(r'"alg"\s*:\s*"([^"]+)"', clean_output, re.IGNORECASE)
    algorithm = alg_pattern.group(1) if alg_pattern else "Unknown"

    # 3. Extract cracked secret (if Brute-Force was successful)
    # jwt-tool typically outputs: [+] Valid secret found: mysecret123
    secret_pattern = re.search(r'\[\+\]\s*Valid\s*secret\s*found:\s*(.+)', clean_output, re.IGNORECASE)
    cracked_secret = secret_pattern.group(1).strip() if secret_pattern else None

    # 4. Extract generated tampered token (if Exploit was successful)
    # jwt-tool typically outputs: [+] Tampered token: eyJhb...
    tampered_pattern = re.search(r'\[\+\]\s*Tampered\s*token(?:.*)?:\s*([A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]*)', clean_output, re.IGNORECASE)
    tampered_token = tampered_pattern.group(1).strip() if tampered_pattern else None

    # 5. Classify the finding type
    finding_type = "info"
    if cracked_secret:
        finding_type = "cracked_secret"
    elif tampered_token:
        finding_type = "exploit_success"

    # 6. Build the result dictionary
    parsed = {
        "uuid": str(uuid.uuid4()),
        "target_uuid": target_uuid,  
        "host": host,               
        "token": token,
        "target": target_identifier,
        "algorithm": algorithm,
        "finding_type": finding_type,
        "cracked_secret": cracked_secret,
        "tampered_token": tampered_token,
        "scanned_at": datetime.utcnow().isoformat(),
    }

    results.append(parsed)

    # 7. Store in database
    if results:
        db = get_db()
        # Insert into a dedicated table for JWT or a generic vulnerabilities table
        db.insert_many("jwt_results", results)

    return results