from pydantic import BaseModel, Field
from playwright.sync_api import sync_playwright

class BrowserInput(BaseModel):
    url: str = Field(..., description="The full URL to navigate to, including any injected XSS payloads.")

class BrowserResult:
    def __init__(self, output: str):
        self.output = output

class BrowserTool:
    name = "run_browser"
    description = "Navigate to a URL using a headless browser to test for DOM-based and Reflected XSS. Detects if a JavaScript alert dialog pops up."
    input_model = BrowserInput

    def run(self, data: BrowserInput) -> BrowserResult:
        try:
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                page = browser.new_page()
                
                alert_triggered = False
                alert_message = ""
                
                # מאזין שקופץ ברגע שיש חלון alert
                def handle_dialog(dialog):
                    nonlocal alert_triggered, alert_message
                    alert_triggered = True
                    alert_message = dialog.message
                    dialog.accept()
                
                page.on("dialog", handle_dialog)
                
                # ניווט לכתובת והמתנה לרינדור
                page.goto(data.url)
                page.wait_for_timeout(3000) 
                
                browser.close()
                
                if alert_triggered:
                    return BrowserResult(f"XSS CONFIRMED: JavaScript alert dialog was triggered! Message: {alert_message}")
                else:
                    return BrowserResult("No alert was triggered. The payload did not execute in the DOM.")
        except Exception as e:
            return BrowserResult(f"Error running browser: {str(e)}")