import json
import subprocess
from typing import Optional
from pydantic import BaseModel, Field

from tools.base import BaseTool, ToolResult
from execution.runner import run_command


class NucleiInput(BaseModel):
    url: str = Field(description="Target URL to scan with nuclei templates.")
    severity: Optional[str] = Field(
        default="critical,high,medium,low",
        description="Comma-separated severities to include (info,low,medium,high,critical).",
    )
    tags: Optional[str] = Field(
        default=None,
        description="Comma-separated template tags to restrict the scan (e.g. 'cve,exposure,misconfig,xss,sqli').",
    )
    templates: Optional[str] = Field(default=None, description="Specific template/dir path to run (-t). Defaults to the full community set.")
    headers: Optional[list[str]] = Field(default=None, description="Extra HTTP headers in 'Key: Value' format for authenticated scanning.")
    rate_limit: int = Field(default=150, description="Max requests per second (-rl).")
    concurrency: int = Field(default=25, description="Template concurrency (-c).")
    timeout: int = Field(default=10, description="Per-request timeout in seconds.")
    max_time: int = Field(default=300, description="Maximum total execution time in seconds.")
    # Scope plumbing (injected by BaseAgent.call_mcp; ignored if absent)
    mcp_scopes: Optional[list[dict]] = Field(default=None, description="Scope rules for filtering DB writes")
    mcp_default_in_out: str = Field(default="in", description="Default in/out for assets matching no rule")


def _parse_nuclei_jsonl(output: str) -> list[dict]:
    """Parse nuclei -jsonl output into a list of normalized finding dicts."""
    findings: list[dict] = []
    for line in output.splitlines():
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            ev = json.loads(line)
        except json.JSONDecodeError:
            continue
        info = ev.get("info", {}) or {}
        findings.append({
            "template": ev.get("template-id", ""),
            "name": info.get("name", ev.get("template-id", "")),
            "severity": info.get("severity", "info"),
            "matched": ev.get("matched-at") or ev.get("host", ""),
            "description": info.get("description", ""),
            "reference": info.get("reference", []),
        })
    return findings


class NucleiTool(BaseTool):
    name = "run_nuclei"
    description = (
        "Run nuclei to scan a target with the community template set for known CVEs, "
        "misconfigurations, exposures, default credentials, and technology-specific issues. "
        "Returns the structured matches (template, severity, matched URL) for the agent to turn "
        "into findings. Complements the LLM agents with cheap, broad, template-driven coverage."
    )
    input_model = NucleiInput

    def run(self, data: NucleiInput) -> ToolResult:
        cmd = [
            "nuclei",
            "-u", data.url,
            "-jsonl",
            "-silent",
            "-rl", str(data.rate_limit),
            "-c", str(data.concurrency),
            "-timeout", str(data.timeout),
            "-no-color",
            "-disable-update-check",
        ]
        if data.severity:
            cmd += ["-severity", data.severity]
        if data.tags:
            cmd += ["-tags", data.tags]
        if data.templates:
            cmd += ["-t", data.templates]
        for header in (data.headers or []):
            cmd += ["-H", header]

        try:
            code, out, err = run_command(cmd, timeout=data.max_time + 15)
        except subprocess.TimeoutExpired:
            return ToolResult(success=False, output=f"nuclei timed out after {data.max_time}s on {data.url}")
        except Exception as e:
            return ToolResult(success=False, output=f"nuclei execution error: {e}")

        output = out or ""
        findings = _parse_nuclei_jsonl(output)
        if not findings:
            return ToolResult(success=True, output=f"nuclei completed on {data.url} — no template matches.")

        lines = [f"nuclei matched {len(findings)} template(s) on {data.url}:"]
        for f in findings[:60]:
            lines.append(f"  [{f['severity'].upper()}] {f['name']} ({f['template']}) → {f['matched']}")
        # Append the raw JSONL so the agent can build precise findings.
        return ToolResult(
            success=True,
            output="\n".join(lines) + "\n\nRAW_JSONL:\n" + output[:8000],
            db_ref={"matches": len(findings)},
        )
