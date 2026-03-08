from typing import Optional
from pydantic import BaseModel, Field

from tools.base import BaseTool, ToolResult
from execution.runner import run_command


class CurlInput(BaseModel):
    url: str = Field(description="Target URL to request")
    method: str = Field(default="GET", description="HTTP method: GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS")
    headers: Optional[list[str]] = Field(default=None, description="List of headers in 'Key: Value' format")
    data: Optional[str] = Field(default=None, description="Request body data (for POST/PUT/PATCH)")
    data_urlencode: Optional[str] = Field(default=None, description="URL-encoded POST data")
    cookies: Optional[str] = Field(default=None, description="Cookie string: 'name=value; name2=value2'")
    follow_redirects: bool = Field(default=True, description="Follow HTTP redirects (-L)")
    max_redirects: int = Field(default=10, description="Maximum number of redirects to follow")
    include_headers: bool = Field(default=True, description="Include response headers in output (-i)")
    insecure: bool = Field(default=True, description="Allow insecure SSL/TLS connections (-k)")
    user_agent: Optional[str] = Field(default=None, description="Custom User-Agent string")
    timeout: int = Field(default=30, description="Request timeout in seconds")
    proxy: Optional[str] = Field(default=None, description="Proxy URL (e.g., http://127.0.0.1:8080)")
    output_file: Optional[str] = Field(default=None, description="Save response body to file (-o)")
    max_time: int = Field(default=60, description="Maximum total time for the operation in seconds")
    verbose: bool = Field(default=False, description="Verbose mode — shows request/response headers (-v)")
    silent: bool = Field(default=False, description="Silent mode — suppress progress output (-s)")


class CurlTool(BaseTool):
    name = "run_curl"
    description = (
        "Execute an HTTP request using curl. Supports all common HTTP methods, "
        "custom headers, cookies, request bodies, proxies, and SSL bypass. "
        "Returns the full response including status line and headers."
    )
    input_model = CurlInput

    def run(self, data: CurlInput) -> ToolResult:
        cmd = ["curl"]

        # Method
        cmd += ["-X", data.method.upper()]

        # Always show response headers for analysis
        if data.include_headers:
            cmd.append("-i")

        # Silent mode (suppress progress bar) — almost always want this
        if data.silent or not data.verbose:
            cmd.append("-s")

        # Verbose (shows both request and response headers)
        if data.verbose:
            cmd.append("-v")

        # Follow redirects
        if data.follow_redirects:
            cmd += ["-L", "--max-redirs", str(data.max_redirects)]

        # Insecure (bypass SSL cert validation)
        if data.insecure:
            cmd.append("-k")

        # Custom headers
        if data.headers:
            for header in data.headers:
                cmd += ["-H", header]

        # User-Agent
        if data.user_agent:
            cmd += ["-A", data.user_agent]

        # Cookies
        if data.cookies:
            cmd += ["-b", data.cookies]

        # Request body
        if data.data:
            cmd += ["-d", data.data]

        if data.data_urlencode:
            cmd += ["--data-urlencode", data.data_urlencode]

        # Proxy
        if data.proxy:
            cmd += ["--proxy", data.proxy]

        # Output file
        if data.output_file:
            cmd += ["-o", data.output_file]

        # Timeouts
        cmd += ["--connect-timeout", str(data.timeout)]
        cmd += ["--max-time", str(data.max_time)]

        # Write-out: append HTTP status code at the end for easy parsing
        cmd += ["-w", "\n\n[HTTP_STATUS: %{http_code}] [TIME: %{time_total}s] [SIZE: %{size_download}b]"]

        # Target URL (always last)
        cmd.append(data.url)

        try:
            code, out, err = run_command(cmd, timeout=data.max_time + 5)
        except Exception as e:
            return ToolResult(success=False, output=f"curl execution error: {str(e)}")

        output = out if out else err
        if not output:
            return ToolResult(success=False, output="curl returned no output")

        return ToolResult(success=True, output=output)
