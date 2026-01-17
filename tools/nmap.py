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
        profiles = {
            "quick": ["-T4", "-F"],
            "ports": ["-p-", "-T4"],
            "service": ["-sV", "-T4"],
        }

        cmd = ["nmap"] + profiles[data.scan_type] + [data.target]

        code, out, err = run_command(cmd)

        if code != 0:
            return ToolResult(success=False, output=err)

        return ToolResult(success=True, output=out)
