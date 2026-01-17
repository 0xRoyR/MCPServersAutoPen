from typing import Optional
from pydantic import BaseModel, Field

from tools.base import BaseTool, ToolResult
from execution.runner import run_command
from parsers.subfinder_parser import parse_subfinder_output


class SubfinderInput(BaseModel):
    domain: Optional[str] = Field(default=None, description="Single domain to enumerate")
    domains_file: Optional[str] = Field(default=None, description="File containing list of domains")
    recursive: bool = Field(default=False, description="Use recursive enumeration")
    all_sources: bool = Field(default=False, description="Use all sources")
    silent: bool = Field(default=False, description="Silent mode, only output subdomains")
    timeout: int = Field(default=60, description="Timeout in seconds for each source")
    max_time: int = Field(default=180, description="Maximum total execution time in seconds")
    resolvers_file: Optional[str] = Field(default=None, description="File containing resolvers")
    sources: Optional[list[str]] = Field(default=None, description="Specific sources to use")


class SubfinderTool(BaseTool):
    name = "run_subfinder"
    description = "Run subfinder for subdomain enumeration"
    input_model = SubfinderInput

    def run(self, data: SubfinderInput) -> ToolResult:
        if not data.domain and not data.domains_file:
            return ToolResult(success=False, output="Error: either 'domain' or 'domains_file' must be provided")

        cmd = ["subfinder"]

        if data.domain:
            cmd += ["-d", data.domain]

        if data.domains_file:
            cmd += ["-dL", data.domains_file]

        if data.recursive:
            cmd.append("-recursive")

        if data.all_sources:
            cmd.append("-all")

        if data.silent:
            cmd.append("-silent")

        # Add timeout for each source
        cmd += ["-timeout", str(data.timeout)]

        if data.resolvers_file:
            cmd += ["-r", data.resolvers_file]

        if data.sources:
            cmd += ["-sources", ",".join(data.sources)]

        try:
            # Use max_time + buffer for subprocess timeout
            code, out, err = run_command(cmd, timeout=data.max_time + 10)
        except Exception as e:
            return ToolResult(success=False, output=f"Error: {str(e)}")

        if code != 0:
            return ToolResult(success=False, output=err)

        # Parse and store results in database
        if data.domain:
            parse_subfinder_output(out, data.domain)

        return ToolResult(success=True, output=out)
