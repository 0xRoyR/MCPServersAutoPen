import re
from typing import Optional
from pydantic import BaseModel, Field
from urllib.parse import urlparse

from tools.base import BaseTool, ToolResult
from execution.runner import run_command

GOBUSTER_WORDLIST = "/usr/share/dirb/wordlists/small.txt"


class GobusterInput(BaseModel):
    scan_uuid: Optional[str] = Field(default=None, description="Scan UUID — required for DB mode")
    target_uuid: Optional[str] = Field(default=None, description="Target UUID — required for DB mode")
    target: Optional[str] = Field(default=None, description="Target URL to brute-force. If omitted and scan_uuid+target_uuid provided, reads http_services from DB automatically.")
    extensions: Optional[str] = Field(default=None, description="File extensions to search for (e.g., 'php,html,txt')")
    status_codes: Optional[str] = Field(default=None, description="Status codes to match (e.g., '200,204,301')")
    exclude_status: Optional[str] = Field(default=None, description="Status codes to exclude (e.g., '404,403')")
    exclude_length: Optional[int] = Field(
        default=None,
        description=(
            "Exclude responses with this exact body length. "
            "Use when the server returns 200 for every request (wildcard responses). "
            "Gobuster will report the required value in its error output."
        ),
    )
    threads: int = Field(default=30, description="Number of concurrent threads")
    timeout: int = Field(default=10, description="HTTP timeout in seconds")
    max_time: int = Field(default=300, description="Maximum total execution time in seconds")
    follow_redirect: bool = Field(default=False, description="Follow redirects")
    no_error: bool = Field(default=True, description="Don't display errors")
    quiet: bool = Field(default=False, description="Quiet mode, minimal output")
    insecure: bool = Field(default=True, description="Skip TLS certificate verification (recommended for pentest targets)")
    headers: Optional[dict] = Field(
        default=None,
        description=(
            "Custom HTTP headers to include with every request. "
            "Use this to pass session cookies or Authorization tokens for authenticated scanning. "
            "Example: {\"Authorization\": \"Bearer eyJ...\", \"Cookie\": \"session=abc\"}"
        ),
    )
    cookies: Optional[str] = Field(
        default=None,
        description=(
            "Cookie string to include with every request (e.g. 'session=abc123; csrf=xyz'). "
            "Convenience field — equivalent to setting Cookie in headers."
        ),
    )


def _parse_gobuster_line(line: str):
    """
    Parse a gobuster output line like:
      /admin                (Status: 200) [Size: 1234]
      /admin                (Status: 301) [--> /admin/]
    Returns (path, status_code, content_length, redirect_url) or None.
    """
    line = line.strip()
    if not line or line.startswith("=") or line.startswith("/usr") or "Progress:" in line:
        return None

    path_match = re.match(r'^(/\S*)', line)
    if not path_match:
        return None
    path = path_match.group(1)

    status_match = re.search(r'\(Status:\s*(\d+)\)', line)
    status_code = int(status_match.group(1)) if status_match else None

    size_match = re.search(r'\[Size:\s*(\d+)\]', line)
    content_length = int(size_match.group(1)) if size_match else None

    redirect_match = re.search(r'-->\s*(\S+)', line)
    redirect_url = redirect_match.group(1).rstrip(']') if redirect_match else ""

    return path, status_code, content_length, redirect_url


def _run_gobuster_on_target(target_url: str, data: GobusterInput):
    """Run gobuster against a single target URL and return raw output."""
    cmd = [
        "gobuster", "dir",
        "-u", target_url,
        "-w", GOBUSTER_WORDLIST,
        "-t", str(data.threads),
        "--timeout", f"{data.timeout}s",
    ]

    if data.extensions:
        cmd += ["-x", data.extensions]

    if data.status_codes:
        cmd += ["-s", data.status_codes]

    if data.exclude_status:
        cmd += ["-b", data.exclude_status]

    if data.follow_redirect:
        cmd.append("-r")

    if data.exclude_length is not None:
        cmd += ["--exclude-length", str(data.exclude_length)]

    merged_headers = dict(data.headers or {})
    if data.cookies:
        merged_headers["Cookie"] = data.cookies

    for header_name, header_value in merged_headers.items():
        cmd += ["-H", f"{header_name}: {header_value}"]

    if data.insecure:
        cmd.append("--no-tls-validation")

    if data.no_error:
        cmd.append("--no-error")

    if data.quiet:
        cmd.append("-q")

    code, out, err = run_command(cmd, timeout=data.max_time + 10)
    return out if out else err


class GobusterTool(BaseTool):
    name = "run_gobuster"
    description = (
        "Run gobuster directory brute-forcing (dir mode) against a target URL. "
        "When scan_uuid and target_uuid are provided without an explicit target, "
        "gobuster automatically reads live HTTP services from the database and scans each one. "
        "Results are saved to the database (endpoints table) and a summary is returned. "
        "Supports both unauthenticated and authenticated scanning via the 'headers' and 'cookies' fields."
    )
    input_model = GobusterInput

    def run(self, data: GobusterInput) -> ToolResult:
        db_mode = bool(data.scan_uuid and data.target_uuid)

        # Determine targets to scan
        if db_mode and not data.target:
            try:
                from db import get_repo
                repo = get_repo()
                http_services = repo.get_http_services(data.target_uuid)
                if not http_services:
                    return ToolResult(success=False, output="No HTTP services found in DB for this target. Run httpx first.")
                # Only scan services with a 2xx status code
                targets = [s["url"] for s in http_services if s.get("status_code") and 200 <= s["status_code"] <= 299]
                if not targets:
                    return ToolResult(success=False, output="No HTTP services with 2xx status found in DB. Nothing to scan with gobuster.")
            except Exception as e:
                return ToolResult(success=False, output=f"Failed to read http_services from DB: {e}")
        elif data.target:
            targets = [data.target]
        else:
            return ToolResult(success=False, output="Error: either 'target' or scan_uuid+target_uuid must be provided")

        all_output = []
        total_saved = 0
        total_found = 0

        for target_url in targets:
            try:
                output = _run_gobuster_on_target(target_url, data)
            except Exception as e:
                all_output.append(f"[{target_url}] Error: {e}")
                continue

            if not output:
                all_output.append(f"[{target_url}] No output from gobuster")
                continue

            all_output.append(f"[{target_url}]\n{output}")

            if db_mode:
                try:
                    from db import get_repo
                    repo = get_repo()
                    parsed = urlparse(target_url)
                    host = parsed.netloc or parsed.path

                    for line in output.splitlines():
                        parsed_line = _parse_gobuster_line(line)
                        if not parsed_line:
                            continue
                        path, status_code, content_length, redirect_url = parsed_line
                        full_url = target_url.rstrip("/") + path
                        total_found += 1
                        result = repo.upsert_endpoint(
                            target_uuid=data.target_uuid,
                            scan_uuid=data.scan_uuid,
                            host=host,
                            url=full_url,
                            path=path,
                            source="gobuster",
                            method="GET",
                            status_code=status_code,
                            content_length=content_length,
                            redirect_url=redirect_url or "",
                        )
                        if result:
                            total_saved += 1
                except Exception as e:
                    all_output.append(f"[{target_url}] DB save error: {e}")

        combined_output = "\n\n".join(all_output)

        if db_mode:
            return ToolResult(
                success=True,
                output=f"gobuster complete. Scanned {len(targets)} targets, found {total_found} endpoints, saved {total_saved} new to DB.",
                db_ref={"table": "endpoints", "rows_saved": total_saved, "total_found": total_found},
            )

        return ToolResult(success=True, output=combined_output if combined_output else "gobuster returned no output")
