import json
import os
import subprocess
import sys
from typing import Optional
from pydantic import BaseModel, Field

from tools.base import BaseTool, ToolResult
from execution.runner import run_command

_DRIVER = os.path.join(os.path.dirname(os.path.abspath(__file__)), "browser_driver.py")


class BrowserInput(BaseModel):
    url: str = Field(
        description=(
            "URL to load in a headless browser. For a DOM-XSS check, put the payload in the URL "
            "(query string or SPA hash fragment) and have it call alert/print containing the canary, "
            "e.g. https://target.com/#/search?q=<img src=x onerror=alert('CANARY')>."
        ),
    )
    mode: str = Field(default="xss_check", description="'xss_check' (detect DOM payload execution), 'render' (rendered DOM + links + CSP), or 'theater' (render under a session in a VISIBLE browser + capture a screenshot — used to watch a weaponized exploit fire live).")
    canary: Optional[str] = Field(default=None, description="Unique token your payload triggers (e.g. inside alert()). Execution is confirmed when it appears in a dialog/console/error.")
    cookies: Optional[str] = Field(default=None, description="Cookie string for authenticated rendering (e.g. 'session=abc; token=xyz').")
    headers: Optional[dict] = Field(default=None, description="Extra HTTP headers (e.g. {'Authorization': 'Bearer ...'}).")
    timeout: int = Field(default=15, description="Navigation timeout in seconds.")
    wait_ms: int = Field(default=2500, description="Milliseconds to let client-side JS settle after load.")
    max_time: int = Field(default=60, description="Maximum total execution time in seconds.")
    headed: bool = Field(default=False, description="Open a VISIBLE browser window on the tool host (also enabled by AUTOPEN_HEADED_BROWSER env).")
    slow_mo: int = Field(default=0, description="Slow each browser action by N ms so a watcher can follow it.")
    screenshot: bool = Field(default=False, description="Capture a JPEG screenshot and return it (base64) for the live filmstrip.")
    dwell: int = Field(default=0, description="Extra ms to keep a headed window open after the page settles.")
    # Scope plumbing (injected by BaseAgent.call_mcp; ignored if absent)
    mcp_scopes: Optional[list[dict]] = Field(default=None, description="Scope rules for filtering DB writes")
    mcp_default_in_out: str = Field(default="in", description="Default in/out for assets matching no rule")


class BrowserTool(BaseTool):
    name = "run_browser"
    description = (
        "Render a URL in a real headless browser to detect client-side / DOM-based XSS that "
        "pure-HTTP probing cannot see (payload execution via dialogs/console/errors), to read the "
        "Content-Security-Policy, and to crawl client-rendered (SPA) routes and links. "
        "Returns whether an injected payload executed, the CSP, and discovered links. Target-agnostic."
    )
    input_model = BrowserInput

    def run(self, data: BrowserInput) -> ToolResult:
        cmd = [
            sys.executable, _DRIVER,
            "--url", data.url,
            "--mode", data.mode,
            "--timeout", str(data.timeout),
            "--wait", str(data.wait_ms),
        ]
        if data.canary:
            cmd += ["--canary", data.canary]
        if data.cookies:
            cmd += ["--cookies", data.cookies]
        for k, v in (data.headers or {}).items():
            cmd += ["--header", f"{k}: {v}"]
        # The driver owns the headed decision (theater-by-default + the
        # AUTOPEN_HEADED_BROWSER env it inherits from this process); we only forward
        # an explicit per-call request.
        if data.headed:
            cmd += ["--headed"]
        if data.slow_mo:
            cmd += ["--slow-mo", str(data.slow_mo)]
        if data.screenshot or data.mode == "theater":
            cmd += ["--screenshot"]
        if data.dwell:
            cmd += ["--dwell", str(data.dwell)]

        try:
            code, out, err = run_command(cmd, timeout=data.max_time + 10)
        except subprocess.TimeoutExpired:
            return ToolResult(success=False, output=f"headless browser timed out after {data.max_time}s on {data.url}")
        except Exception as e:
            return ToolResult(success=False, output=f"headless browser error: {e}")

        raw = (out or "").strip()
        # The driver prints a single JSON object on stdout.
        parsed = None
        start = raw.rfind("{")
        if start != -1:
            try:
                parsed = json.loads(raw[start:])
            except json.JSONDecodeError:
                parsed = None
        if parsed is None:
            return ToolResult(success=False, output=f"headless browser produced no parseable result. stderr:\n{(err or '')[:500]}")

        if not parsed.get("available", False):
            return ToolResult(success=False, output=f"headless browser unavailable: {parsed.get('error', 'unknown')}")

        # A captured screenshot is appended as a parseable trailer so the calling
        # agent can stream it to the live filmstrip without changing the human-
        # readable head of the output. Keep it LAST.
        shot = parsed.get("screenshot_b64", "")
        shot_trailer = f"\n__SHOT__:{shot}" if shot else ""

        if data.mode == "xss_check":
            executed = parsed.get("executed", False)
            head = ("[DOM XSS EXECUTED] " if executed else "[DOM XSS not executed] ") + data.url
            body = (
                f"\nexecuted={executed}"
                f"\ndialogs={parsed.get('dialogs')}"
                f"\nconsole={parsed.get('console')[:10]}"
                f"\npage_errors={parsed.get('page_errors')}"
                f"\ncsp={parsed.get('csp') or '(none)'}"
            )
            return ToolResult(success=True, output=head + body + shot_trailer)

        # render / theater mode
        links = parsed.get("links", [])
        visible = " (visible window)" if parsed.get("headed") else ""
        return ToolResult(
            success=True,
            output=(
                f"Rendered {data.url}{visible} (title: {parsed.get('title')}).\n"
                f"CSP: {parsed.get('csp') or '(none)'}\n"
                f"Discovered {len(links)} link(s):\n" + "\n".join(links[:80])
                + shot_trailer
            ),
        )
