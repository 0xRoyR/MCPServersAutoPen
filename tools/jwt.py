from typing import Literal
from pydantic import BaseModel, Field

from tools.base import BaseTool, ToolResult
from execution.runner import run_command


class JwtInput(BaseModel):
    token: str = Field(description="The target JWT token string")
    action: Literal["decode", "bruteforce", "exploit"] = Field(
        default="decode", 
        description="The operation to perform on the JWT"
    )
    wordlist_path: str = Field(
        default="wordlists/jwt_secrets_wordlist.txt",
        description="Path to the dictionary file (used only if action='bruteforce')"
    )
    exploit_type: Literal["alg_none", "blank_secret", "spoof_jwks"] = Field(
        default="alg_none",
        description="Specific known exploit to attempt (used only if action='exploit')"
    )


class JwtTool(BaseTool):
    name = "run_jwt_tool"
    description = "Analyze, decode, brute-force, or exploit JSON Web Tokens (JWT)"
    input_model = JwtInput

    def run(self, data: JwtInput) -> ToolResult:
        cmd = ["jwt_tool", data.token]


        if data.action == "decode":
            pass
            
        elif data.action == "bruteforce":
            cmd.extend(["-d", data.wordlist_path])
            
        elif data.action == "exploit":
            exploit_flags = {
                "alg_none": "a",
                "blank_secret": "b",
                "spoof_jwks": "j"
            }
            flag = exploit_flags.get(data.exploit_type, "a")
            cmd.extend(["-X", flag])

        code, out, err = run_command(cmd)

        if code != 0:
            return ToolResult(success=False, output=err)

        return ToolResult(success=True, output=out)