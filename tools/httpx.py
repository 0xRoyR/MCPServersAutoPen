import json
from typing import Optional
from pydantic import BaseModel, Field

from tools.base import BaseTool, ToolResult
from execution.runner import run_command


class HttpxInput(BaseModel):
    scan_uuid: Optional[str] = Field(default=None, description="Scan UUID — required for DB mode")
    target_uuid: Optional[str] = Field(default=None, description="Target UUID — required for DB mode")
    target: Optional[str] = Field(default=None, description="Single target URL or host. If omitted and scan_uuid+target_uuid provided, reads subdomains from DB automatically.")
    targets_list: Optional[list[str]] = Field(default=None, description="List of target URLs to probe (e.g., ['https://example.com', 'http://example.com:8080']). All probed in a single httpx invocation.")
    targets_file: Optional[str] = Field(default=None, description="File containing list of targets")
    ports: Optional[str] = Field(default=None, description="Ports to probe (e.g., '80,443,8080')")
    path: Optional[str] = Field(default=None, description="Path to append to URLs")
    status_code: bool = Field(default=True, description="Display status code")
    title: bool = Field(default=True, description="Display page title")
    tech_detect: bool = Field(default=False, description="Display technology detected")
    follow_redirects: bool = Field(default=True, description="Follow HTTP redirects")
    timeout: int = Field(default=10, description="Timeout in seconds per request")
    max_time: int = Field(default=120, description="Maximum total execution time in seconds")
    threads: int = Field(default=30, description="Number of concurrent threads")
    silent: bool = Field(default=False, description="Silent mode, only output results")
    headers: Optional[dict] = Field(
        default=None,
        description=(
            "Custom HTTP headers to send with every request. "
            "Use to pass Authorization tokens or session cookies for authenticated probing. "
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


class HttpxTool(BaseTool):
    name = "run_httpx"
    description = (
        "Run httpx for HTTP probing and analysis. "
        "When scan_uuid and target_uuid are provided without an explicit target, "
        "httpx automatically reads subdomains from the database and probes all of them. "
        "Results are saved to the database (http_services table) and a summary is returned. "
        "Supports both unauthenticated and authenticated scanning via the 'headers' and 'cookies' fields."
    )
    input_model = HttpxInput

    def run(self, data: HttpxInput) -> ToolResult:
        # DB mode: auto-read subdomains when no explicit target
        targets_to_probe = []
        db_mode = bool(data.scan_uuid and data.target_uuid)

        if data.targets_list:
            targets_to_probe = data.targets_list
        elif db_mode and not data.target and not data.targets_file:
            try:
                from db import get_repo
                repo = get_repo()
                subdomains = repo.get_subdomains(data.target_uuid)
                if not subdomains:
                    return ToolResult(success=False, output="No subdomains found in DB for this target. Run subfinder first.")
                targets_to_probe = [s["subdomain"] for s in subdomains]
            except Exception as e:
                return ToolResult(success=False, output=f"Failed to read subdomains from DB: {e}")
        elif data.target:
            targets_to_probe = [data.target]
        elif not data.targets_file:
            return ToolResult(success=False, output="Error: either 'target', 'targets_list', 'targets_file', or scan_uuid+target_uuid must be provided")

        # Build command
        cmd = ["httpx", "-json"]

        if targets_to_probe:
            # Write targets to stdin via the targets list
            cmd += ["-l", "/dev/stdin"]
            stdin_input = "\n".join(targets_to_probe)
        elif data.targets_file:
            cmd += ["-l", data.targets_file]
            stdin_input = None
        else:
            stdin_input = None

        if data.target and not targets_to_probe:
            cmd = ["httpx", "-json", "-u", data.target]
            stdin_input = None

        if data.ports:
            cmd += ["-ports", data.ports]

        if data.path:
            cmd += ["-path", data.path]

        if data.status_code:
            cmd.append("-status-code")

        if data.title:
            cmd.append("-title")

        if data.tech_detect:
            cmd.append("-tech-detect")

        if data.follow_redirects:
            cmd.append("-follow-redirects")

        cmd += ["-timeout", str(data.timeout)]
        cmd += ["-threads", str(data.threads)]

        if data.silent:
            cmd.append("-silent")

        merged_headers = dict(data.headers or {})
        if data.cookies:
            merged_headers["Cookie"] = data.cookies

        for header_name, header_value in merged_headers.items():
            cmd += ["-H", f"{header_name}: {header_value}"]

        try:
            code, out, err = run_command(cmd, timeout=data.max_time + 10, stdin_input=stdin_input)
        except Exception as e:
            return ToolResult(success=False, output=f"Error: {str(e)}")

        if code != 0 and not out:
            return ToolResult(success=False, output=err if err else "httpx failed with no output")

        output = out if out else err

        # DB mode: parse JSON output and persist
        if db_mode and output:
            try:
                from db import get_repo
                repo = get_repo()
                saved = 0
                for line in output.splitlines():
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        record = json.loads(line)
                    except json.JSONDecodeError:
                        continue

                    url = record.get("url", "")
                    host = record.get("host", record.get("input", ""))
                    status_code = record.get("status-code") or record.get("status_code")
                    title = record.get("title", "")
                    webserver = record.get("webserver", "")
                    tech = record.get("tech", record.get("technologies", []))
                    content_length = record.get("content-length") or record.get("content_length")
                    content_type = record.get("content-type", "")
                    redirect_url = record.get("location", "")

                    if not url:
                        continue

                    result = repo.upsert_http_service(
                        target_uuid=data.target_uuid,
                        scan_uuid=data.scan_uuid,
                        host=host,
                        url=url,
                        status_code=int(status_code) if status_code else None,
                        title=title,
                        webserver=webserver,
                        technologies=tech if isinstance(tech, list) else [tech] if tech else [],
                        content_length=int(content_length) if content_length else None,
                        content_type=content_type,
                        redirect_url=redirect_url,
                    )
                    if result:
                        saved += 1

                return ToolResult(
                    success=True,
                    output=f"httpx complete. Probed {len(targets_to_probe)} targets, saved {saved} live HTTP services to DB.",
                    db_ref={"table": "http_services", "rows_saved": saved},
                )
            except Exception as e:
                return ToolResult(success=True, output=f"httpx complete but DB save failed: {e}\n\n{output}")

        return ToolResult(success=True, output=output)
