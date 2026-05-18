from typing import Optional
from pydantic import BaseModel, Field
import urllib.parse

from tools.base import BaseTool, ToolResult
from execution.runner import run_command


class NosqlmapInput(BaseModel):
    url: str = Field(description="Target URL to test (e.g., http://example.com/page?id=1)")
    method: str = Field(default="GET", description="HTTP method (GET or POST)")
    data: Optional[str] = Field(default=None, description="POST data string (e.g., 'user=admin&pass=test')")
    # NoSQLMap specific arguments mapping
    attack: int = Field(default=2, description="Attack type (1: DB Access, 2: Web App, 3: Scan)")
    inject_format: int = Field(default=1, description="Format of injection (1: JSON, 2: PHP, etc.)")
    timeout: int = Field(default=300, description="Maximum execution time in seconds")


class NosqlmapTool(BaseTool):
    name = "run_nosqlmap"
    description = (
        "Run NoSQLMap for automated NoSQL injection detection and exploitation. "
        "Useful for testing MongoDB, CouchDB, and other NoSQL databases via web parameters."
    )
    input_model = NosqlmapInput

    def run(self, data: NosqlmapInput) -> ToolResult:
        # Parse URL to get host, port, and path
        parsed_url = urllib.parse.urlparse(data.url)
        victim = parsed_url.hostname
        if not victim:
            return ToolResult(success=False, output="Invalid URL: Hostname not found.")

        port = parsed_url.port or (443 if parsed_url.scheme == "https" else 80)
        uri = parsed_url.path
        if parsed_url.query:
            uri += "?" + parsed_url.query

        # Construct command based on NoSQLMap CLI arguments
        cmd = [
            "python3", "NoSQLMap.py",
            "--attack", str(data.attack),
            "--victim", victim,
            "--webPort", str(port),
            "--uri", uri,
            "--httpMethod", data.method.upper(),
            "--injectFormat", str(data.inject_format),
            "--doTimeAttack", "n",
        ]

        try:
            code, out, err = run_command(cmd, timeout=data.timeout + 10)
        except Exception as e:
            return ToolResult(success=False, output=f"nosqlmap execution error: {str(e)}")

        output = out if out else err
        if not output:
            return ToolResult(success=True, output="nosqlmap executed (no output returned)")

        return ToolResult(success=True, output=output)
