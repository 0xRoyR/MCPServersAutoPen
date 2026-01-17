from pydantic import BaseModel, Field

from tools.base import BaseTool, ToolResult
from execution.runner import run_command


class WhoisInput(BaseModel):
    target: str = Field(description="Domain name")


class WhoisTool(BaseTool):
    name = "run_whois"
    description = "Perform a WHOIS lookup"
    input_model = WhoisInput

    def run(self, data: WhoisInput) -> ToolResult:
        cmd = ["whois", data.target]

        code, out, err = run_command(cmd, timeout=30)

        if code != 0:
            return ToolResult(success=False, output=err)

        return ToolResult(success=True, output=out)
