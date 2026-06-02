import json
import os
import re
import subprocess
import tempfile
from typing import Optional
from urllib.parse import urljoin, urlparse

import requests
from pydantic import BaseModel, Field

from tools.base import BaseTool, ToolResult
from execution.runner import run_command


class RetireJsInput(BaseModel):
    url: str = Field(description="Target URL whose JavaScript bundles should be checked for known-vulnerable libraries.")
    max_scripts: int = Field(default=20, description="Maximum number of linked .js files to download and scan.")
    timeout: int = Field(default=10, description="Per-request timeout in seconds when fetching scripts.")
    max_time: int = Field(default=120, description="Maximum total execution time in seconds for the retire scan.")
    cookies: Optional[str] = Field(default=None, description="Cookie string for authenticated pages.")
    # Scope plumbing (injected by BaseAgent.call_mcp; ignored if absent)
    mcp_scopes: Optional[list[dict]] = Field(default=None, description="Scope rules for filtering DB writes")
    mcp_default_in_out: str = Field(default="in", description="Default in/out for assets matching no rule")


_SRC_RE = re.compile(r"<script[^>]+src=[\"']([^\"']+)[\"']", re.IGNORECASE)


def _collect_script_urls(page_url: str, html: str, limit: int) -> list[str]:
    urls: list[str] = []
    for src in _SRC_RE.findall(html):
        full = urljoin(page_url, src)
        if full.split("?")[0].lower().endswith(".js") and full not in urls:
            urls.append(full)
        if len(urls) >= limit:
            break
    return urls


def _parse_retire_json(output: str) -> list[dict]:
    """Parse retire.js JSON output into normalized component findings."""
    try:
        data = json.loads(output)
    except json.JSONDecodeError:
        return []
    results = data.get("data", data) if isinstance(data, dict) else data
    findings: list[dict] = []
    for entry in results if isinstance(results, list) else []:
        for comp in entry.get("results", []) or []:
            for vuln in comp.get("vulnerabilities", []) or []:
                ident = vuln.get("identifiers", {}) or {}
                findings.append({
                    "component": comp.get("component", ""),
                    "version": comp.get("version", ""),
                    "severity": vuln.get("severity", "medium"),
                    "summary": ident.get("summary", "") or (ident.get("CVE", [""])[0] if ident.get("CVE") else ""),
                    "cve": ", ".join(ident.get("CVE", []) or []),
                    "file": entry.get("file", ""),
                })
    return findings


class RetireJsTool(BaseTool):
    name = "run_retirejs"
    description = (
        "Detect known-vulnerable JavaScript libraries (software composition analysis) on a target. "
        "Downloads the page's linked .js bundles and runs retire.js against them, returning each "
        "vulnerable component, its version, severity, and CVEs. Target-agnostic."
    )
    input_model = RetireJsInput

    def run(self, data: RetireJsInput) -> ToolResult:
        headers = {}
        if data.cookies:
            headers["Cookie"] = data.cookies
        try:
            page = requests.get(data.url, headers=headers, timeout=data.timeout, verify=False)
            html = page.text or ""
        except requests.exceptions.RequestException as e:
            return ToolResult(success=False, output=f"retire.js: could not fetch {data.url}: {e}")

        script_urls = _collect_script_urls(data.url, html, data.max_scripts)
        if not script_urls:
            return ToolResult(success=True, output=f"retire.js: no linked .js bundles found on {data.url}.")

        with tempfile.TemporaryDirectory(prefix="retirejs_") as tmp:
            saved = 0
            for i, su in enumerate(script_urls):
                try:
                    r = requests.get(su, headers=headers, timeout=data.timeout, verify=False)
                    if r.status_code != 200 or not r.text:
                        continue
                    name = os.path.basename(urlparse(su).path) or f"script_{i}.js"
                    if not name.endswith(".js"):
                        name += ".js"
                    with open(os.path.join(tmp, f"{i}_{name}"), "w", encoding="utf-8", errors="replace") as fh:
                        fh.write(r.text)
                    saved += 1
                except requests.exceptions.RequestException:
                    continue

            if saved == 0:
                return ToolResult(success=True, output=f"retire.js: fetched no scannable .js from {data.url}.")

            cmd = ["retire", "--jspath", tmp, "--outputformat", "json", "--exitwith", "0"]
            try:
                code, out, err = run_command(cmd, timeout=data.max_time + 10)
            except subprocess.TimeoutExpired:
                return ToolResult(success=False, output=f"retire.js timed out after {data.max_time}s.")
            except Exception as e:
                return ToolResult(success=False, output=f"retire.js execution error: {e}")

        findings = _parse_retire_json(out or err or "")
        if not findings:
            return ToolResult(success=True, output=f"retire.js scanned {saved} bundle(s) on {data.url} — no known-vulnerable libraries.")

        lines = [f"retire.js found {len(findings)} vulnerable component instance(s) on {data.url}:"]
        for f in findings[:60]:
            cve = f" [{f['cve']}]" if f["cve"] else ""
            lines.append(f"  [{f['severity'].upper()}] {f['component']} {f['version']}{cve} — {f['summary'][:120]}")
        return ToolResult(success=True, output="\n".join(lines), db_ref={"vulnerable_components": len(findings)})
