"""
Parser for Gobuster tool output.

Extracts directory/file discovery results from Gobuster scans.
"""

import re
import uuid
from datetime import datetime
from urllib.parse import urlparse, urljoin
from database import get_db


def parse_gobuster_output(output: str, target: str) -> list[dict]:
    """
    Parse Gobuster output and store results in database.

    Gobuster output format varies by mode:
    - dir mode: /path (Status: 200) [Size: 1234]
    - Also: https://example.com/path (Status: 200) [Size: 1234]

    Args:
        output: Raw Gobuster command output
        target: The target URL that was scanned

    Returns:
        list of dicts with parsed directory/file data
    """
    results = []
    seen_paths = set()

    # Extract host from target
    try:
        parsed_target = urlparse(target)
        host = parsed_target.netloc.lower()
        base_url = f"{parsed_target.scheme}://{parsed_target.netloc}"
    except Exception:
        host = target.lower()
        base_url = target

    # Pattern for gobuster dir output
    # Matches: /path (Status: 200) [Size: 1234]
    # Or: https://example.com/path (Status: 200) [Size: 1234]
    dir_pattern = re.compile(
        r"^(https?://\S+|/\S*)\s+"      # URL or path
        r"\(Status:\s*(\d+)\)"           # Status code
        r"(?:\s+\[Size:\s*(\d+)\])?"     # Optional size
        r"(?:\s+\[--> (.*?)\])?"         # Optional redirect
    )

    # Alternative simpler pattern (quiet mode)
    # Just URLs or paths, one per line
    simple_pattern = re.compile(r"^(https?://\S+|/\S+)$")

    for line in output.strip().split("\n"):
        line = line.strip()
        if not line or line.startswith("=") or line.startswith("Gobuster"):
            continue

        parsed = {
            "uuid": str(uuid.uuid4()),
            "host": host,
            "url": None,
            "path": None,
            "status_code": None,
            "content_length": None,
            "redirect_url": None,
            "scanned_at": datetime.utcnow().isoformat(),
        }

        # Try full pattern first
        match = dir_pattern.match(line)
        if match:
            path_or_url = match.group(1)
            parsed["status_code"] = int(match.group(2))

            if match.group(3):
                parsed["content_length"] = int(match.group(3))

            if match.group(4):
                parsed["redirect_url"] = match.group(4).strip()

            # Determine if it's a full URL or just a path
            if path_or_url.startswith("http"):
                parsed["url"] = path_or_url
                try:
                    parsed["path"] = urlparse(path_or_url).path
                except Exception:
                    parsed["path"] = path_or_url
            else:
                parsed["path"] = path_or_url
                parsed["url"] = urljoin(base_url, path_or_url)

        else:
            # Try simple pattern
            simple_match = simple_pattern.match(line)
            if simple_match:
                path_or_url = simple_match.group(1)

                if path_or_url.startswith("http"):
                    parsed["url"] = path_or_url
                    try:
                        parsed["path"] = urlparse(path_or_url).path
                    except Exception:
                        parsed["path"] = path_or_url
                else:
                    parsed["path"] = path_or_url
                    parsed["url"] = urljoin(base_url, path_or_url)
            else:
                continue

        # Skip if no path found or duplicate
        if not parsed["path"] or parsed["path"] in seen_paths:
            continue

        seen_paths.add(parsed["path"])
        results.append(parsed)

    # Store in database
    if results:
        db = get_db()
        db.insert_many("directories", results)

    return results
