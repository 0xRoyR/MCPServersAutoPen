from typing import Optional, Literal
from pydantic import BaseModel, Field

from tools.base import BaseTool, ToolResult
from execution.runner import run_command
from parsers.gobuster_parser import parse_gobuster_output


class GobusterInput(BaseModel):
    mode: Literal["dir", "dns", "vhost"] = Field(default="dir", description="Gobuster mode: dir, dns, or vhost")
    target: str = Field(description="Target URL (for dir/vhost) or domain (for dns)")
    wordlist: str = Field(description="Path to wordlist file")
    extensions: Optional[str] = Field(default=None, description="File extensions to search for (e.g., 'php,html,txt')")
    status_codes: Optional[str] = Field(default=None, description="Status codes to match (e.g., '200,204,301')")
    exclude_status: Optional[str] = Field(default=None, description="Status codes to exclude (e.g., '404,403')")
    threads: int = Field(default=10, description="Number of concurrent threads")
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
        cmd = ["gobuster", data.mode]

        # Target flag depends on mode
        if data.mode == "dir":
            cmd += ["-u", data.target]
        elif data.mode == "dns":
            cmd += ["-d", data.target]
        elif data.mode == "vhost":
            cmd += ["-u", data.target]

        cmd += ["-w", data.wordlist]
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

        # Gobuster may return non-zero even with results
        output = out if out else err
        if not output:
            return ToolResult(success=False, output="gobuster returned no output")

        # Parse and store results in database (only for dir mode)
        if data.mode == "dir":
            parse_gobuster_output(output, data.target)

        return ToolResult(success=True, output=output)
