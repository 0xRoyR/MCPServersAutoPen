from typing import Optional
from pydantic import BaseModel, Field

from tools.base import BaseTool, ToolResult
from execution.runner import run_command


class KatanaInput(BaseModel):
    url: str = Field(description="Target URL to crawl")
    depth: int = Field(default=3, description="Crawl depth limit")
    js_crawl: bool = Field(default=True, description="Enable JavaScript crawling (passive JS parsing)")
    headless: bool = Field(default=False, description="Use headless browser for JS rendering (slower)")
    concurrency: int = Field(default=10, description="Number of concurrent requests")
    timeout: int = Field(default=10, description="Per-request timeout in seconds")
    max_time: int = Field(default=180, description="Maximum total execution time in seconds")
    silent: bool = Field(default=True, description="Silent mode — only output discovered URLs")
    headers: Optional[dict] = Field(
        default=None,
        description=(
            "Custom HTTP headers to include with every request. "
            "Use for authenticated crawling. "
            "Example: {\"Authorization\": \"Bearer eyJ...\", \"Cookie\": \"session=abc\"}"
        ),
    )
    cookies: Optional[str] = Field(
        default=None,
        description=(
            "Cookie string (e.g. 'session=abc123; csrf=xyz'). "
            "Convenience field — merged into headers as Cookie."
        ),
    )


class KatanaTool(BaseTool):
    name = "run_katana"
    description = (
        "Run katana web crawler to discover endpoints and URLs in a web application. "
        "Supports passive JavaScript crawling (finds URLs in JS files without executing them). "
        "Supports authenticated crawling via 'headers' and 'cookies' fields. "
        "Returns a list of discovered URLs, one per line."
    )
    input_model = KatanaInput

    def run(self, data: KatanaInput) -> ToolResult:
        cmd = [
            "katana",
            "-u", data.url,
            "-d", str(data.depth),
            "-c", str(data.concurrency),
            "-timeout", str(data.timeout),
        ]

        if data.js_crawl:
            cmd.append("-jc")

        if data.headless:
            cmd.append("-headless")

        if data.silent:
            cmd.append("-silent")

        # Merge cookies into headers
        merged_headers = dict(data.headers or {})
        if data.cookies:
            merged_headers["Cookie"] = data.cookies

        for header_name, header_value in merged_headers.items():
            cmd += ["-H", f"{header_name}: {header_value}"]

        try:
            code, out, err = run_command(cmd, timeout=data.max_time + 10)
        except Exception as e:
            return ToolResult(success=False, output=f"katana execution error: {str(e)}")

        output = out if out else err
        if not output or not output.strip():
            return ToolResult(success=True, output="No URLs discovered by katana.")

        return ToolResult(success=True, output=output)
