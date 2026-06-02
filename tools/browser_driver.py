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
import json
import sys


def _emit(obj: dict) -> None:
    sys.stdout.write(json.dumps(obj))
    sys.stdout.flush()


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", required=True)
    ap.add_argument("--mode", default="xss_check", choices=["xss_check", "render"])
    ap.add_argument("--canary", default="")
    ap.add_argument("--cookies", default="")          # "k=v; k2=v2"
    ap.add_argument("--header", action="append", default=[])  # "K: V"
    ap.add_argument("--timeout", type=int, default=15)
    ap.add_argument("--wait", type=int, default=2500)  # ms to settle after load
    args = ap.parse_args()

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

    extra_headers = {}
    for h in args.header:
        if ":" in h:
            k, v = h.split(":", 1)
            extra_headers[k.strip()] = v.strip()

    try:
        with sync_playwright() as p:
            browser = p.chromium.launch(headless=True, args=["--no-sandbox", "--disable-dev-shm-usage"])
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
            if args.mode == "render":
                try:
                    links = page.eval_on_selector_all(
                        "a[href]", "els => els.map(e => e.href)"
                    )
                except Exception:
                    links = []

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
    })


if __name__ == "__main__":
    main()
