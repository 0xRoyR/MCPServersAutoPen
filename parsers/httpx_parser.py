"""
Parser for Httpx tool output.

Extracts HTTP service information from Httpx probe results.
"""

import re
import uuid
import json
from datetime import datetime
from urllib.parse import urlparse
from database import get_db


def parse_httpx_output(output: str, target: str = None) -> list[dict]:
    """
    Parse Httpx output and store results in database.

    Httpx output format (with flags): URL [STATUS_CODE] [TITLE] [TECH]
    Example: https://example.com [200] [Example Domain] [Nginx,PHP]

    Args:
        output: Raw Httpx command output
        target: Original target (optional, for reference)

    Returns:
        list of dicts with parsed HTTP service data
    """
    results = []
    seen_urls = set()

    # Pattern for httpx output with various fields
    # Format: URL [status] [title] [webserver] [tech]
    # The fields in brackets are optional and may appear in different orders

    for line in output.strip().split("\n"):
        line = line.strip()
        if not line:
            continue

        parsed = {
            "uuid": str(uuid.uuid4()),
            "host": None,
            "url": None,
            "status_code": None,
            "title": None,
            "webserver": None,
            "technologies": None,
            "content_length": None,
            "content_type": None,
            "redirect_url": None,
            "scanned_at": datetime.utcnow().isoformat(),
        }

        # Extract URL (first non-bracket part)
        url_match = re.match(r"^(https?://\S+)", line)
        if url_match:
            url = url_match.group(1)
            parsed["url"] = url

            # Extract host from URL
            try:
                parsed_url = urlparse(url)
                parsed["host"] = parsed_url.netloc.lower()
            except Exception:
                parsed["host"] = target.lower() if target else None

        # Skip if no URL found or already seen
        if not parsed["url"] or parsed["url"] in seen_urls:
            continue

        seen_urls.add(parsed["url"])

        # Extract bracketed fields
        brackets = re.findall(r"\[([^\]]+)\]", line)

        for bracket in brackets:
            bracket = bracket.strip()

            # Status code (3-digit number)
            if re.match(r"^\d{3}$", bracket):
                parsed["status_code"] = int(bracket)

            # Content length (number with optional suffix)
            elif re.match(r"^\d+$", bracket) and len(bracket) > 3:
                parsed["content_length"] = int(bracket)

            # Technologies (comma-separated, often contains known tech names)
            elif "," in bracket or any(tech in bracket.lower() for tech in
                ["nginx", "apache", "iis", "php", "asp", "node", "react", "vue",
                 "angular", "jquery", "wordpress", "drupal", "cloudflare"]):
                if parsed["technologies"]:
                    # Append to existing
                    existing = json.loads(parsed["technologies"])
                    existing.extend([t.strip() for t in bracket.split(",")])
                    parsed["technologies"] = json.dumps(existing)
                else:
                    parsed["technologies"] = json.dumps([t.strip() for t in bracket.split(",")])

            # Webserver (single known server name)
            elif bracket.lower() in ["nginx", "apache", "iis", "lighttpd", "caddy", "gunicorn", "uvicorn"]:
                parsed["webserver"] = bracket

            # Title (usually longer text, not matching other patterns)
            elif len(bracket) > 3 and not bracket.isdigit():
                if not parsed["title"]:
                    parsed["title"] = bracket

        # If we still don't have a host, use target
        if not parsed["host"] and target:
            parsed["host"] = target.lower()

        results.append(parsed)

    # Store in database
    if results:
        db = get_db()
        db.insert_many("http_services", results)

    return results
