"""
Headless-browser driver (subprocess).

Invoked by tools/browser.py as a SEPARATE process because the MCP server runs
tool.run() inside an asyncio loop, where Playwright's sync API cannot run. Here,
in its own process, the sync API is fine.

Loads a URL in headless Chromium and reports JSON on stdout:
  - mode=xss_check : whether an injected payload EXECUTED in the DOM (dialogs,
                     console, uncaught errors), so DOM/CSP-relevant XSS that a
                     pure-HTTP probe cannot see is detected.
  - mode=render    : the rendered DOM + in-page links/routes (SPA crawling) and
                     the Content-Security-Policy header.

Degrades gracefully: if Playwright or its browser is unavailable, prints
{"available": false, "error": ...} and exits 0 so the caller reports cleanly.
"""

import argparse
import base64
import json
import os
import sys


def _emit(obj: dict) -> None:
    sys.stdout.write(json.dumps(obj))
    sys.stdout.flush()


def _truthy(v: str) -> bool:
    return str(v).strip().lower() in ("1", "true", "yes", "on")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", required=True)
    ap.add_argument("--mode", default="xss_check", choices=["xss_check", "render", "theater"])
    ap.add_argument("--canary", default="")
    ap.add_argument("--cookies", default="")          # "k=v; k2=v2"
    ap.add_argument("--header", action="append", default=[])  # "K: V"
    ap.add_argument("--timeout", type=int, default=15)
    ap.add_argument("--wait", type=int, default=2500)  # ms to settle after load
    ap.add_argument("--headed", action="store_true", help="Launch a VISIBLE browser window")
    ap.add_argument("--slow-mo", type=int, default=0, help="Slow each action by N ms (watchable)")
    ap.add_argument("--screenshot", action="store_true", help="Capture a JPEG screenshot (base64 in output)")
    ap.add_argument("--dwell", type=int, default=0, help="Extra ms to keep the (headed) window open after settle")
    args = ap.parse_args()

    # Headed-by-default for the weaponization "theater" so the operator watches the
    # exploit live with NO env var needed; routine modes (xss_check/render) stay
    # headless unless asked. AUTOPEN_HEADED_BROWSER overrides: "1" → headed for ALL
    # modes; "0" → force headless everywhere (for display-less VMs). Falls back to
    # headless automatically if a headed launch fails (no $DISPLAY).
    _env = os.environ.get("AUTOPEN_HEADED_BROWSER", "").strip().lower()
    if _env in ("0", "false", "no", "off"):
        headed = False
    else:
        headed = args.headed or args.mode == "theater" or _truthy(_env)
    slow_mo = args.slow_mo or (250 if headed else 0)
    want_shot = args.screenshot or args.mode == "theater"

    try:
        from playwright.sync_api import sync_playwright
    except Exception as exc:  # noqa: BLE001
        _emit({"available": False, "error": f"playwright not installed: {exc}"})
        return

    dialogs: list[str] = []
    console_msgs: list[str] = []
    page_errors: list[str] = []
    csp = ""
    title = ""
    rendered = ""
    links: list[str] = []
    screenshot_b64 = ""

    extra_headers = {}
    for h in args.header:
        if ":" in h:
            k, v = h.split(":", 1)
            extra_headers[k.strip()] = v.strip()

    def _launch(p, want_headed: bool):
        return p.chromium.launch(
            headless=not want_headed,
            slow_mo=slow_mo,
            args=["--no-sandbox", "--disable-dev-shm-usage", "--start-maximized"],
        )

    try:
        with sync_playwright() as p:
            try:
                browser = _launch(p, headed)
            except Exception:
                # No display / headed launch failed → fall back to headless so the
                # screenshot filmstrip still works even without a desktop on the VM.
                browser = _launch(p, False)
            context = browser.new_context(ignore_https_errors=True, extra_http_headers=extra_headers or None)
            if args.cookies:
                from urllib.parse import urlparse
                host = urlparse(args.url).hostname or ""
                cookie_objs = []
                for pair in args.cookies.split(";"):
                    pair = pair.strip()
                    if "=" in pair:
                        ck, cv = pair.split("=", 1)
                        cookie_objs.append({"name": ck.strip(), "value": cv.strip(), "domain": host, "path": "/"})
                if cookie_objs:
                    try:
                        context.add_cookies(cookie_objs)
                    except Exception:
                        pass
            page = context.new_page()
            page.on("dialog", lambda d: (dialogs.append(d.message), d.dismiss()))
            page.on("console", lambda m: console_msgs.append(f"{m.type}: {m.text}"))
            page.on("pageerror", lambda e: page_errors.append(str(e)))

            try:
                resp = page.goto(args.url, timeout=args.timeout * 1000, wait_until="load")
            except Exception:
                resp = None
            try:
                page.wait_for_timeout(args.wait)
            except Exception:
                pass

            if resp is not None:
                try:
                    csp = resp.headers.get("content-security-policy", "")
                except Exception:
                    csp = ""
            try:
                title = page.title()
            except Exception:
                title = ""
            try:
                rendered = page.content()[:4000]
            except Exception:
                rendered = ""
            if args.mode in ("render", "theater"):
                try:
                    links = page.eval_on_selector_all(
                        "a[href]", "els => els.map(e => e.href)"
                    )
                except Exception:
                    links = []

            if want_shot:
                try:
                    png = page.screenshot(type="jpeg", quality=60, full_page=False)
                    screenshot_b64 = base64.b64encode(png).decode("ascii")
                except Exception:
                    screenshot_b64 = ""

            # Keep the visible window on screen for a beat so the operator can
            # watch the change land before it closes.
            if args.dwell and headed:
                try:
                    page.wait_for_timeout(args.dwell)
                except Exception:
                    pass

            browser.close()
    except Exception as exc:  # noqa: BLE001
        _emit({"available": True, "error": f"browser run failed: {exc}"})
        return

    canary = args.canary
    executed = bool(dialogs) or any(
        canary and canary in s for s in (dialogs + console_msgs + page_errors)
    )

    _emit({
        "available": True,
        "url": args.url,
        "mode": args.mode,
        "executed": executed,
        "dialogs": dialogs[:10],
        "console": console_msgs[:30],
        "page_errors": page_errors[:10],
        "csp": csp,
        "title": title,
        "links": list(dict.fromkeys(links))[:100],
        "rendered_excerpt": rendered,
        "headed": headed,
        "screenshot_b64": screenshot_b64,
    })


if __name__ == "__main__":
    main()
