import re
import subprocess
from typing import Optional
from pydantic import BaseModel, Field

from tools.base import BaseTool, ToolResult
from execution.runner import run_command


class CommixInput(BaseModel):
    url: str = Field(description="Target URL to test for OS command injection (e.g. https://target.com/ping?host=test).")
    data: Optional[str] = Field(default=None, description="POST body to test; mark the injection point or let commix find it (e.g. 'host=127.0.0.1').")
    method: Optional[str] = Field(default=None, description="HTTP method override (GET/POST).")
    cookie: Optional[str] = Field(default=None, description="Cookie header value for authenticated testing.")
    headers: Optional[list[str]] = Field(default=None, description="Extra HTTP headers in 'Key: Value' format (e.g. Authorization).")
    test_parameter: Optional[str] = Field(default=None, description="Restrict testing to this parameter (-p).")
    level: int = Field(default=1, ge=1, le=3, description="Test level (1-3). Higher = more injection points/techniques.")
    technique: Optional[str] = Field(default=None, description="Restrict techniques: c(lassic) e(file-based) t(ime-based) f(ile-write). E.g. 'ct'.")
    os_cmd: Optional[str] = Field(
        default=None,
        description="Single OS command to execute through a confirmed injection (--os-cmd). Proof-of-impact only; keep it read-only (e.g. 'id').",
    )
    timeout: int = Field(default=30, description="Per-request timeout in seconds.")
    max_time: int = Field(default=240, description="Maximum total execution time in seconds.")
    random_agent: bool = Field(default=True, description="Use a random User-Agent.")
    # Scope plumbing (injected by BaseAgent.call_mcp; ignored if absent)
    mcp_scopes: Optional[list[dict]] = Field(default=None, description="Scope rules for filtering DB writes")
    mcp_default_in_out: str = Field(default="in", description="Default in/out for assets matching no rule")


_CONFIRMED_PATTERNS = (
    r"is vulnerable",
    r"appears to be (?:injectable|vulnerable)",
    r"the .* parameter is vulnerable",
    r"command injection",
    r"Type:\s*(?:results-based|time-based|file-based)",
)


def _is_injectable(output: str) -> bool:
    return any(re.search(p, output, re.IGNORECASE) for p in _CONFIRMED_PATTERNS)


class CommixTool(BaseTool):
    name = "run_commix"
    description = (
        "Run commix to detect and exploit OS command injection. Probes a URL/parameter for "
        "classic, time-based, and file-based command injection and, when an --os-cmd is supplied, "
        "executes a single read-only proof command through a confirmed injection. Returns the raw "
        "commix output and whether injection was confirmed. Target-agnostic."
    )
    input_model = CommixInput

    def run(self, data: CommixInput) -> ToolResult:
        cmd = [
            "commix",
            "--url", data.url,
            "--batch",
            "--level", str(data.level),
            "--timeout", str(data.timeout),
        ]
        if data.data:
            cmd += ["--data", data.data]
        if data.method:
            cmd += ["--method", data.method.upper()]
        if data.cookie:
            cmd += ["--cookie", data.cookie]
        for header in (data.headers or []):
            cmd += ["--header", header]
        if data.test_parameter:
            cmd += ["-p", data.test_parameter]
        if data.technique:
            cmd += ["--technique", data.technique]
        if data.os_cmd:
            cmd += ["--os-cmd", data.os_cmd]
        if data.random_agent:
            cmd.append("--random-agent")

        try:
            code, out, err = run_command(cmd, timeout=data.max_time + 10)
        except subprocess.TimeoutExpired:
            return ToolResult(success=False, output=f"commix timed out after {data.max_time}s on {data.url}")
        except Exception as e:
            return ToolResult(success=False, output=f"commix execution error: {e}")

        output = out if out else err
        if not output:
            return ToolResult(success=True, output=f"commix completed on {data.url} — no command injection confirmed.")

        confirmed = _is_injectable(output)
        header = (
            f"[COMMAND INJECTION CONFIRMED] {data.url}\n" if confirmed
            else f"commix finished on {data.url} — not confirmed.\n"
        )
        return ToolResult(success=True, output=header + "\n" + output[:6000])
