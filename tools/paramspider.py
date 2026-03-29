import os
from pathlib import Path
from pydantic import BaseModel, Field

from tools.base import BaseTool, ToolResult
from execution.runner import run_command


class ParamSpiderInput(BaseModel):
    domain: str = Field(description="Target domain for parameter mining (e.g., example.com)")
    include_subdomains: bool = Field(default=False, description="Include results from subdomains (-s flag)")
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
        # paramspider v2: writes results to results/<domain>.txt automatically
        cmd = ["paramspider", "-d", data.domain]

        if data.include_subdomains:
            cmd.append("-s")

        try:
            code, out, err = run_command(cmd, timeout=data.max_time + 10)
        except Exception as e:
            return ToolResult(success=False, output=f"paramspider execution error: {str(e)}")

        # v2 writes to results/<domain>.txt relative to cwd
        results_file = Path("results") / f"{data.domain}.txt"
        file_content = ""
        if results_file.exists():
            file_content = results_file.read_text(encoding="utf-8", errors="ignore").strip()
            try:
                results_file.unlink()
            except OSError:
                pass

        output_content = file_content or (out.strip() if out else "") or (err.strip() if err else "")

        if not output_content:
            return ToolResult(success=True, output="No parameterized URLs found for this domain.")

        return ToolResult(success=True, output=output_content)
