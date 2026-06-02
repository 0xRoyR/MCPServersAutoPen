import subprocess
from typing import Optional
from pydantic import BaseModel, Field

from tools.base import BaseTool, ToolResult
from execution.runner import run_command


class DalfoxInput(BaseModel):
    url: str = Field(description="Target URL to test for XSS. Mark the injection point with a parameter (e.g. https://target.com/search?q=test); dalfox will fuzz it.")
    method: Optional[str] = Field(default=None, description="HTTP method override (GET/POST/PUT). Defaults to GET.")
    data: Optional[str] = Field(default=None, description="POST/PUT body to fuzz (e.g. 'comment=test'). Use with method=POST.")
    headers: Optional[dict] = Field(
        default=None,
        description=(
            "Custom HTTP headers sent with every request. Pass session cookies or "
            "Authorization tokens here for authenticated XSS testing. "
            "Example: {\"Authorization\": \"Bearer eyJ...\"}"
        ),
    )
    cookies: Optional[str] = Field(default=None, description="Cookie string sent with every request (e.g. 'session=abc; csrf=xyz').")
    blind: Optional[str] = Field(
        default=None,
        description=(
            "Out-of-band (blind XSS) callback URL. When provided, dalfox injects a "
            "payload that calls back to this collaborator so stored/blind XSS that "
            "fires later (e.g. when a privileged user views the content) is detected."
        ),
    )
    custom_payload_file: Optional[str] = Field(default=None, description="Path to a file of custom payloads to try in addition to the built-in set.")
    worker: int = Field(default=40, description="Number of concurrent workers.")
    delay: int = Field(default=0, description="Delay between requests in milliseconds.")
    timeout: int = Field(default=10, description="Per-request HTTP timeout in seconds.")
    max_time: int = Field(default=180, description="Maximum total execution time in seconds.")
    follow_redirects: bool = Field(default=False, description="Follow HTTP redirects.")
    user_agent: Optional[str] = Field(default=None, description="Custom User-Agent string.")
    mining: bool = Field(default=True, description="Mine extra parameters from the response (DOM + dictionary) before fuzzing.")
    skip_bav: bool = Field(default=False, description="Skip Basic Another Vulnerability checks (SSTI/SQLi/etc.) and focus purely on XSS.")
    # Scope plumbing (injected by BaseAgent.call_mcp; ignored if absent)
    mcp_scopes: Optional[list[dict]] = Field(default=None, description="Scope rules for filtering DB writes")
    mcp_default_in_out: str = Field(default="in", description="Default in/out for assets matching no rule")


def _build_dalfox_cmd(data: DalfoxInput) -> list[str]:
    """Assemble the dalfox command for a single URL target."""
    cmd = [
        "dalfox", "url", data.url,
        "--worker", str(data.worker),
        "--timeout", str(data.timeout),
        "--format", "plain",
        "--no-color",
        "--silence",
    ]

    if data.method:
        cmd += ["--method", data.method.upper()]

    if data.data:
        cmd += ["--data", data.data]

    merged_headers = dict(data.headers or {})
    if data.cookies:
        cmd += ["--cookie", data.cookies]
    for header_name, header_value in merged_headers.items():
        cmd += ["--header", f"{header_name}: {header_value}"]

    if data.blind:
        cmd += ["-b", data.blind]

    if data.custom_payload_file:
        cmd += ["--custom-payload", data.custom_payload_file]

    if data.delay:
        cmd += ["--delay", str(data.delay)]

    if data.follow_redirects:
        cmd.append("--follow-redirects")

    if data.user_agent:
        cmd += ["--user-agent", data.user_agent]

    if data.mining:
        cmd.append("--mining-dom")
    if data.skip_bav:
        cmd.append("--skip-bav")

    return cmd


class DalfoxTool(BaseTool):
    name = "run_dalfox"
    description = (
        "Run dalfox for automated XSS discovery and payload generation against a target URL. "
        "Probes reflected, stored, and DOM-based XSS, fingerprints the response context, "
        "and emits proof-of-concept payloads for confirmed injection points. "
        "Supports authenticated testing via 'headers'/'cookies' and out-of-band (blind) XSS "
        "via the 'blind' callback URL. Returns the raw dalfox output (confirmed PoCs and "
        "candidate parameters) for the agent to weaponize."
    )
    input_model = DalfoxInput

    def run(self, data: DalfoxInput) -> ToolResult:
        cmd = _build_dalfox_cmd(data)
        try:
            code, out, err = run_command(cmd, timeout=data.max_time + 10)
        except subprocess.TimeoutExpired:
            return ToolResult(success=False, output=f"dalfox timed out after {data.max_time}s on {data.url}")
        except Exception as e:
            return ToolResult(success=False, output=f"dalfox execution error: {e}")

        output = out if out else err
        if not output:
            return ToolResult(success=True, output="dalfox completed — no XSS confirmed on the tested injection point(s).")

        # Surface confirmed PoCs first so the agent can act on them immediately.
        poc_lines = [ln for ln in output.splitlines() if "[POC]" in ln or "[VULN]" in ln]
        summary = (
            f"dalfox confirmed {len(poc_lines)} XSS PoC(s) on {data.url}."
            if poc_lines else f"dalfox finished on {data.url} — review output for candidate parameters."
        )
        return ToolResult(success=True, output=f"{summary}\n\n{output}")
