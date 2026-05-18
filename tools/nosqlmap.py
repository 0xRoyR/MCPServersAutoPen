from typing import Optional
from pydantic import BaseModel, Field
import os

from tools.base import BaseTool, ToolResult
from execution.runner import run_command


class NosqlmapInput(BaseModel):
    url: str = Field(description="Target URL to test (e.g., http://example.com/page?id=1)")
    method: str = Field(default="GET", description="HTTP method (GET or POST)")
    data: Optional[str] = Field(default=None, description="POST data string (JSON or URL encoded)")
    timeout: int = Field(default=300, description="Maximum execution time in seconds")


class NosqlmapTool(BaseTool):
    name = "run_nosqlmap"
    description = (
        "Run an automated NoSQL injection scanner to detect vulnerabilities in MongoDB and other NoSQL databases. "
        "Tests for common injection patterns in both URL parameters and POST data."
    )
    input_model = NosqlmapInput

    def run(self, data: NosqlmapInput) -> ToolResult:
        # Path to the custom nosql_scan.py script
        base_dir = os.path.dirname(os.path.abspath(__file__))
        scanner_path = os.path.join(base_dir, "nosql_scan.py")

        # Construct command
        cmd = [
            "python", scanner_path,
            "--url", data.url,
            "--method", data.method.upper(),
        ]
        
        if data.data:
            cmd.extend(["--data", data.data])

        try:
            # We use run_command which handles the execution environment and live output
            code, out, err = run_command(cmd, timeout=data.timeout + 10)
        except Exception as e:
            return ToolResult(success=False, output=f"nosql_scan execution error: {str(e)}")

        output = out if out else err
        if not output:
            return ToolResult(success=True, output="nosql_scan executed (no output returned)")

        # Check if vulnerability was found in the output
        success = "[+]" in output
        
        return ToolResult(success=True, output=output)
