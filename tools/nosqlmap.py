from typing import Optional, Literal
from pydantic import BaseModel, Field

from tools.base import BaseTool, ToolResult
from execution.runner import run_command


class NosqlmapInput(BaseModel):
    url: str = Field(description="Target URL to test (e.g., https://example.com/api/login)")
    data: Optional[str] = Field(default=None, description="POST data string (JSON body or url-encoded form)")
    method: Optional[str] = Field(default=None, description="HTTP method override (GET/POST)")
    headers: Optional[list[str]] = Field(default=None, description="Extra HTTP headers in 'Key: Value' format")
    cookie: Optional[str] = Field(default=None, description="HTTP Cookie header value")
    attack_type: Literal["auth_bypass", "exists", "regex", "timing", "js_inject"] = Field(
        default="auth_bypass",
        description=(
            "NoSQL injection technique to attempt: "
            "auth_bypass (operator injection {$ne, $gt, $regex} on credential fields), "
            "exists (probe operator-acceptable filter params with $exists), "
            "regex (boolean blind via $regex character-by-character), "
            "timing (server-side JS sleep() blind via $where), "
            "js_inject ($where with arbitrary JavaScript predicate)."
        ),
    )
    dbms: Literal["mongodb", "couchdb", "redis"] = Field(
        default="mongodb",
        description="Backend NoSQL database to target. Determines payload syntax."
    )
    verbose: bool = Field(default=False, description="Verbose mode — log every request/response")
    proxy: Optional[str] = Field(default=None, description="Proxy URL (e.g., http://127.0.0.1:8080)")
    random_agent: bool = Field(default=True, description="Use a random User-Agent")
    timeout: int = Field(default=20, description="Per-request timeout in seconds")
    max_time: int = Field(default=180, description="Maximum total execution time in seconds")


class NosqlmapTool(BaseTool):
    name = "run_nosqlmap"
    description = (
        "Run nosqlmap for automated NoSQL injection detection (MongoDB, CouchDB, Redis). "
        "Probes operator injection ($ne, $gt, $regex), $where JavaScript predicates, "
        "and time-based blind via sleep() in $where. "
        "Read-only — never enumerates databases or dumps records (those flags are not exposed). "
        "IMPORTANT: Designed for proof-of-concept. Never modifies or deletes data."
    )
    input_model = NosqlmapInput

    def run(self, data: NosqlmapInput) -> ToolResult:
        # nosqlmap CLI flags (codingo/NoSQLMap fork). The wrapper builds a non-interactive
        # invocation; if the installed binary requires prompts and lacks --batch support,
        # the agent falls back to manual curl probes (see SENTINEL-NOSQLI prompts).
        cmd = [
            "nosqlmap",
            "-u", data.url,
            "--attack", data.attack_type,
            "--dbms", data.dbms,
            "--batch",
        ]

        if data.data:
            cmd += ["--data", data.data]

        if data.method:
            cmd += ["--method", data.method.upper()]

        if data.headers:
            for header in data.headers:
                cmd += ["-H", header]

        if data.cookie:
            cmd += ["--cookie", data.cookie]

        if data.random_agent:
            cmd.append("--random-agent")

        if data.proxy:
            cmd += ["--proxy", data.proxy]

        cmd += ["--timeout", str(data.timeout)]

        if data.verbose:
            cmd.append("-v")

        try:
            code, out, err = run_command(cmd, timeout=data.max_time + 10)
        except FileNotFoundError:
            return ToolResult(
                success=False,
                output="nosqlmap binary not found on PATH — install nosqlmap or fall back to manual curl probes",
            )
        except Exception as e:
            return ToolResult(success=False, output=f"nosqlmap execution error: {str(e)}")

        output = out if out else err
        if not output:
            return ToolResult(success=False, output="nosqlmap returned no output")

        return ToolResult(success=True, output=output)
