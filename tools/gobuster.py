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


class GobusterTool(BaseTool):
    name = "run_gobuster"
    description = "Run gobuster for directory/DNS/vhost brute-forcing"
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
