from typing import Literal
from pydantic import BaseModel, Field

from tools.base import BaseTool, ToolResult
from execution.runner import run_command


class NmapInput(BaseModel):
    target: str = Field(description="IP or hostname")
    scan_type: Literal["quick", "ports", "service"] = "quick"


class NmapTool(BaseTool):
    name = "run_nmap"
    description = "Run a restricted Nmap scan"
    input_model = NmapInput

    def run(self, data: NmapInput) -> ToolResult:
        # NOTE: nmap currently runs with NO flags at all (no -sV, -T4, -F, or -p-)
        # — the fuller scans were too heavy. This is a plain default scan
        # (top-1000-port connect scan), which still detects port states such as
        # 21/tcp open for the FTP agent. scan_type is accepted but ignored for
        # now; re-introduce per-profile flags later — see TODO.md "Nmap scan depth".
        profiles = {
            "quick": [],
            "ports": [],
            "service": [],
        }

        cmd = ["nmap"] + profiles[data.scan_type] + [data.target]

        code, out, err = run_command(cmd)

        if code != 0:
            return ToolResult(success=False, output=err)

        # Raw output returned to agent. DB persistence via backend API.
        return ToolResult(success=True, output=out)
