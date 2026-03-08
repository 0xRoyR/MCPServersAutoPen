from typing import Optional
from pydantic import BaseModel, Field

from tools.base import BaseTool, ToolResult
from execution.runner import run_command


class HttpxInput(BaseModel):
    target: Optional[str] = Field(default=None, description="Single target URL or host")
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


class HttpxTool(BaseTool):
    name = "run_httpx"
    description = "Run httpx for HTTP probing and analysis"
    input_model = HttpxInput

    def run(self, data: HttpxInput) -> ToolResult:
        if not data.target and not data.targets_file:
            return ToolResult(success=False, output="Error: either 'target' or 'targets_file' must be provided")

        cmd = ["httpx"]

        if data.target:
            cmd += ["-u", data.target]

        if data.targets_file:
            cmd += ["-l", data.targets_file]

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

        try:
            code, out, err = run_command(cmd, timeout=data.max_time + 10)
        except Exception as e:
            return ToolResult(success=False, output=f"Error: {str(e)}")

        if code != 0 and not out:
            return ToolResult(success=False, output=err if err else "httpx failed with no output")

        # Raw output returned to agent. DB persistence via backend API.
        output = out if out else err
        return ToolResult(success=True, output=output)
