import os
from pathlib import Path
from typing import Optional, Literal
from pydantic import BaseModel, Field

from tools.base import BaseTool, ToolResult
from execution.runner import run_command

# Wordlist is resolved from AUTOPEN_WORDLISTS_DIR env var (if set),
# otherwise falls back to MCPServersAutoPen/wordlists/.
_WORDLISTS_DIR = Path(os.environ.get(
    "AUTOPEN_WORDLISTS_DIR",
    Path(__file__).parent.parent / "wordlists",
))
GOBUSTER_WORDLIST = str(_WORDLISTS_DIR / "http-directories-wordlist.txt")


class GobusterInput(BaseModel):
    mode: Literal["dir", "dns", "vhost"] = Field(default="dir", description="Gobuster mode: dir, dns, or vhost")
    target: str = Field(description="Target URL (for dir/vhost) or domain (for dns)")
    extensions: Optional[str] = Field(default=None, description="File extensions to search for (e.g., 'php,html,txt')")
    status_codes: Optional[str] = Field(default=None, description="Status codes to match (e.g., '200,204,301')")
    exclude_status: Optional[str] = Field(default=None, description="Status codes to exclude (e.g., '404,403')")
    threads: int = Field(default=30, description="Number of concurrent threads")
    timeout: int = Field(default=10, description="HTTP timeout in seconds")
    max_time: int = Field(default=300, description="Maximum total execution time in seconds")
    follow_redirect: bool = Field(default=False, description="Follow redirects")
    no_error: bool = Field(default=True, description="Don't display errors")
    quiet: bool = Field(default=False, description="Quiet mode, minimal output")
    insecure: bool = Field(default=True, description="Skip TLS certificate verification (recommended for pentest targets)")
    # Authentication support — for re-running recon in authenticated/privileged context
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


class GobusterTool(BaseTool):
    name = "run_gobuster"
    description = (
        "Run gobuster for directory/DNS/vhost brute-forcing. "
        "Supports both unauthenticated and authenticated scanning via the 'headers' and 'cookies' fields. "
        "Use authenticated mode (with session cookies/JWT) to discover endpoints that return 200 "
        "instead of 401/403 when a valid session is present."
    )
    input_model = GobusterInput

    def run(self, data: GobusterInput) -> ToolResult:
        if not Path(GOBUSTER_WORDLIST).exists():
            return ToolResult(
                success=False,
                output=(
                    f"Wordlist not found: {GOBUSTER_WORDLIST}\n"
                    "Place http-directories-wordlist.txt in MCPServersAutoPen/wordlists/ "
                    "or set the AUTOPEN_WORDLISTS_DIR environment variable."
                ),
            )

        cmd = ["gobuster", data.mode]

        if data.mode == "dir":
            cmd += ["-u", data.target]
        elif data.mode == "dns":
            cmd += ["-d", data.target]
        elif data.mode == "vhost":
            cmd += ["-u", data.target]

        cmd += ["-w", GOBUSTER_WORDLIST]
        cmd += ["-t", str(data.threads)]
        cmd += ["--timeout", f"{data.timeout}s"]

        if data.mode == "dir":
            if data.extensions:
                cmd += ["-x", data.extensions]

            if data.status_codes:
                cmd += ["-s", data.status_codes]

            if data.exclude_status:
                cmd += ["-b", data.exclude_status]

            if data.follow_redirect:
                cmd.append("-r")

            # Inject authentication headers
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

        try:
            code, out, err = run_command(cmd, timeout=data.max_time + 10)
        except Exception as e:
            return ToolResult(success=False, output=f"Error: {str(e)}")

        output = out if out else err
        if not output:
            return ToolResult(success=False, output="gobuster returned no output")

        # Raw output returned to agent. DB persistence via backend API.
        return ToolResult(success=True, output=output)
