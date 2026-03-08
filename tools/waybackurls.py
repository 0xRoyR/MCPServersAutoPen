from typing import Optional
from pydantic import BaseModel, Field

from tools.base import BaseTool, ToolResult
from execution.runner import run_command


class WaybackurlsInput(BaseModel):
    domain: str = Field(description="Domain to fetch historical URLs for (e.g., example.com)")
    no_subs: bool = Field(default=False, description="Don't include subdomains in results")
    date: Optional[str] = Field(default=None, description="Filter URLs to those before this date (YYYYMMDD)")
    get_versions: bool = Field(default=False, description="List URLs and the dates they appeared (slow)")
    max_time: int = Field(default=120, description="Maximum execution time in seconds")


class WaybackurlsTool(BaseTool):
    name = "run_waybackurls"
    description = (
        "Fetch historical URLs for a domain from the Wayback Machine (web.archive.org). "
        "Returns a list of URLs that were crawled at some point in the past. "
        "Very useful for discovering hidden endpoints, old API versions, backup files, "
        "and forgotten parameters that may still be accessible on the live target."
    )
    input_model = WaybackurlsInput

    def run(self, data: WaybackurlsInput) -> ToolResult:
        # waybackurls reads domains from stdin
        cmd = ["waybackurls"]

        if data.no_subs:
            cmd.append("--no-subs")

        if data.date:
            cmd += ["--date", data.date]

        if data.get_versions:
            cmd.append("--get-versions")

        try:
            # waybackurls takes input via stdin — pipe the domain
            code, out, err = run_command(
                cmd,
                timeout=data.max_time + 10,
                stdin_input=data.domain,
            )
        except Exception as e:
            return ToolResult(success=False, output=f"waybackurls execution error: {str(e)}")

        if code != 0 and not out:
            return ToolResult(success=False, output=err or "waybackurls returned no output")

        output = out if out else err
        if not output or output.strip() == "":
            return ToolResult(success=True, output="No historical URLs found for this domain.")

        return ToolResult(success=True, output=output)
