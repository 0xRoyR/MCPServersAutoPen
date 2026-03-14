import os
import tempfile
from typing import Optional
from pydantic import BaseModel, Field

from tools.base import BaseTool, ToolResult
from execution.runner import run_command


class ArjunInput(BaseModel):
    url: str = Field(description="Target URL for HTTP parameter discovery")
    method: str = Field(default="GET", description="HTTP method: GET, POST, JSON, XML")
    timeout: int = Field(default=10, description="Per-request timeout in seconds")
    threads: int = Field(default=5, description="Number of concurrent threads")
    stable: bool = Field(default=True, description="Stable mode — slower but fewer false positives")
    max_time: int = Field(default=120, description="Maximum total execution time in seconds")
    headers: Optional[dict] = Field(
        default=None,
        description="Custom HTTP headers for authenticated scanning. Example: {\"Authorization\": \"Bearer eyJ...\"}"
    )
    cookies: Optional[str] = Field(
        default=None,
        description="Cookie string for authenticated scanning (e.g. 'session=abc123; csrf=xyz')."
    )


class ArjunTool(BaseTool):
    name = "run_arjun"
    description = (
        "Run arjun to discover hidden HTTP parameters on a URL. "
        "Uses wordlist-based fuzzing and heuristics to find undocumented GET/POST parameters. "
        "Supports authenticated scanning via 'headers' and 'cookies'. "
        "Returns discovered parameters as JSON."
    )
    input_model = ArjunInput

    def run(self, data: ArjunInput) -> ToolResult:
        tmpfile_path = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".json", delete=False, prefix="arjun_"
            ) as tmpf:
                tmpfile_path = tmpf.name

            cmd = [
                "arjun",
                "-u", data.url,
                "-m", data.method.upper(),
                "-o", tmpfile_path,
                "--oT", "json",
                "-t", str(data.threads),
                "--timeout", str(data.timeout),
                "-q",  # quiet mode
            ]

            if data.stable:
                cmd.append("--stable")

            # Build merged headers
            merged_headers = dict(data.headers or {})
            if data.cookies:
                merged_headers["Cookie"] = data.cookies

            if merged_headers:
                # arjun expects headers as a single newline-separated string
                header_str = "\n".join(f"{k}: {v}" for k, v in merged_headers.items())
                cmd += ["--headers", header_str]

            try:
                code, out, err = run_command(cmd, timeout=data.max_time + 10)
            except Exception as e:
                return ToolResult(success=False, output=f"arjun execution error: {str(e)}")

            # Read the JSON output file
            if tmpfile_path and os.path.exists(tmpfile_path):
                with open(tmpfile_path, "r", encoding="utf-8", errors="ignore") as f:
                    content = f.read().strip()
                if content:
                    return ToolResult(success=True, output=content)

            # Fall back to stdout
            stdout = out.strip() if out else ""
            if stdout:
                return ToolResult(success=True, output=stdout)

            return ToolResult(success=True, output='{}')

        finally:
            if tmpfile_path and os.path.exists(tmpfile_path):
                try:
                    os.unlink(tmpfile_path)
                except OSError:
                    pass
