from typing import Optional, Literal
from pydantic import BaseModel, Field

from tools.base import BaseTool, ToolResult
from execution.runner import run_command


class NosqlmapInput(BaseModel):
    url: str = Field(description="Target URL to test (e.g., https://example.com/api/login). When testing query params, append the param: https://example.com/page?id=1")
    data: Optional[str] = Field(default=None, description="POST data string. Use valid default values — do NOT include injection strings (the tool injects automatically)")
    method: Optional[str] = Field(default=None, description="HTTP method override (kept for prompt-compatibility; the tool infers GET vs POST from the presence of data)")
    headers: Optional[list[str]] = Field(default=None, description="Extra HTTP headers in 'Key: Value' format (kept for prompt-compatibility; not directly supported by the underlying tool)")
    cookie: Optional[str] = Field(default=None, description="HTTP Cookie header value (kept for prompt-compatibility; not directly supported by the underlying tool)")
    attack_type: Literal["auth_bypass", "exists", "regex", "timing", "js_inject"] = Field(
        default="auth_bypass",
        description=(
            "NoSQL injection technique hint. The underlying tool runs ALL its detection modes "
            "(operator injection, error-based, blind boolean, blind time-based) on every call, "
            "so this field documents intent for the agent's analyzer but does not change the command line."
        ),
    )
    dbms: Literal["mongodb", "couchdb", "redis"] = Field(
        default="mongodb",
        description="Backend NoSQL database hint. Documents intent only; the tool fingerprints automatically."
    )
    verbose: bool = Field(default=False, description="Verbose mode")
    proxy: Optional[str] = Field(default=None, description="Proxy URL (e.g., http://127.0.0.1:8080)")
    random_agent: bool = Field(default=True, description="Use a random User-Agent (kept for prompt-compatibility)")
    timeout: int = Field(default=20, description="Per-request timeout in seconds (kept for prompt-compatibility)")
    max_time: int = Field(default=180, description="Maximum total execution time in seconds")


class NosqlmapTool(BaseTool):
    name = "run_nosqlmap"
    description = (
        "Run automated NoSQL injection detection (MongoDB, CouchDB, Redis). "
        "Probes operator injection ($ne, $gt, $regex), $where JavaScript predicates, "
        "auth-bypass shortcuts, and time-based blind via sleep() in $where. "
        "Read-only — never enumerates databases or dumps records. "
        "IMPORTANT: Designed for proof-of-concept. Never modifies or deletes data."
    )
    input_model = NosqlmapInput

    def run(self, data: NosqlmapInput) -> ToolResult:
        # The underlying binary uses subcommand syntax: `nosqli scan -t <url> [flags]`.
        # The Go-tool variant runs every detection mode internally on each invocation
        # (auth-bypass, error-based, boolean blind, time-based) — so the agent does not
        # have to switch attack_type explicitly. Headers / cookies are not supported by
        # the tool natively; for authenticated probes the agent falls back to run_curl.
        cmd = ["nosqlmap", "scan", "-t", data.url]

        if data.data:
            cmd += ["-d", data.data]

        if data.proxy:
            cmd += ["-p", data.proxy]

        if data.url.lower().startswith("https://"):
            cmd.append("--https")
            cmd.append("--insecure")

        try:
            code, out, err = run_command(cmd, timeout=data.max_time + 10)
        except FileNotFoundError:
            return ToolResult(
                success=False,
                output="nosqlmap binary not found on PATH \u2014 install nosqli or fall back to manual curl probes",
            )
        except Exception as e:
            return ToolResult(success=False, output=f"nosqlmap execution error: {str(e)}")

        output = out if out else err
        if not output:
            return ToolResult(success=False, output="nosqlmap returned no output")

        return ToolResult(success=True, output=output)
