import os
import tempfile
from pydantic import BaseModel, Field

from tools.base import BaseTool, ToolResult
from execution.runner import run_command


class ParamSpiderInput(BaseModel):
    domain: str = Field(description="Target domain for parameter mining (e.g., example.com)")
    level: int = Field(default=2, description="Mining aggressiveness: 1=low, 2=medium, 3=high (slowest)")
    quiet: bool = Field(default=True, description="Suppress banner and non-URL output")
    max_time: int = Field(default=180, description="Maximum total execution time in seconds")


class ParamSpiderTool(BaseTool):
    name = "run_paramspider"
    description = (
        "Run paramspider to mine URL parameters from web archives (Wayback Machine, Common Crawl, etc.). "
        "Discovers URLs with parameters that were historically present on the target domain. "
        "Very useful for finding hidden or forgotten API endpoints with testable parameters. "
        "Returns discovered parameterized URLs, one per line."
    )
    input_model = ParamSpiderInput

    def run(self, data: ParamSpiderInput) -> ToolResult:
        # Use a temp file so we capture output regardless of paramspider version behavior
        tmpfile_path = None
        try:
            with tempfile.NamedTemporaryFile(
                mode="w", suffix=".txt", delete=False, prefix="paramspider_"
            ) as tmpf:
                tmpfile_path = tmpf.name

            cmd = [
                "paramspider",
                "-d", data.domain,
                "-l", str(data.level),
                "-o", tmpfile_path,
            ]

            if data.quiet:
                cmd.append("-q")

            try:
                code, out, err = run_command(cmd, timeout=data.max_time + 10)
            except Exception as e:
                return ToolResult(success=False, output=f"paramspider execution error: {str(e)}")

            # Prefer the output file; fall back to stdout
            file_content = ""
            if tmpfile_path and os.path.exists(tmpfile_path):
                with open(tmpfile_path, "r", encoding="utf-8", errors="ignore") as f:
                    file_content = f.read().strip()

            output_content = file_content or (out.strip() if out else "")

            if not output_content:
                return ToolResult(success=True, output="No parameterized URLs found for this domain.")

            return ToolResult(success=True, output=output_content)

        finally:
            if tmpfile_path and os.path.exists(tmpfile_path):
                try:
                    os.unlink(tmpfile_path)
                except OSError:
                    pass
