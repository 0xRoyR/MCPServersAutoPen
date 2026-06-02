import subprocess
from typing import Optional
from pydantic import BaseModel, Field
from urllib.parse import urlparse

from tools.base import BaseTool, ToolResult
from execution.runner import run_command

# Reuse a small, fast default wordlist; the agent can override per call.
FFUF_WORDLIST = "/usr/share/dirb/wordlists/small.txt"


class FfufInput(BaseModel):
    scan_uuid: Optional[str] = Field(default=None, description="Scan UUID — required for DB mode (path discovery is saved to the endpoints table)")
    target_uuid: Optional[str] = Field(default=None, description="Target UUID — required for DB mode")
    url: str = Field(
        description=(
            "Target URL containing the FUZZ keyword at the position to fuzz. "
            "Path discovery: https://target.com/FUZZ . "
            "Value/IDOR sweep: https://target.com/api/orders/FUZZ . "
            "Parameter value fuzz: https://target.com/item?id=FUZZ ."
        ),
    )
    wordlist: Optional[str] = Field(default=None, description="Path to the wordlist to use. Defaults to a small built-in directory list. For numeric ID sweeps, point this at a list of candidate IDs.")
    method: str = Field(default="GET", description="HTTP method. POST/PUT/PATCH/DELETE require approval (mutating fuzz).")
    data: Optional[str] = Field(default=None, description="Request body; put FUZZ where the payload should be injected (e.g. '{\"id\":\"FUZZ\"}').")
    match_codes: str = Field(default="200,204,301,302,307,401,403,405,500", description="Comma-separated HTTP status codes to treat as hits (-mc).")
    filter_codes: Optional[str] = Field(default=None, description="Comma-separated status codes to discard (-fc).")
    filter_size: Optional[str] = Field(default=None, description="Comma-separated response sizes to discard (-fs) — use to drop wildcard/boilerplate responses.")
    extensions: Optional[str] = Field(default=None, description="Comma-separated extensions to append to each word (-e), e.g. '.php,.json,.bak'.")
    headers: Optional[dict] = Field(default=None, description="Custom headers (pass session cookies / Authorization for authenticated fuzzing).")
    cookies: Optional[str] = Field(default=None, description="Cookie string sent with every request.")
    threads: int = Field(default=40, description="Number of concurrent threads (-t).")
    timeout: int = Field(default=10, description="Per-request HTTP timeout in seconds.")
    max_time: int = Field(default=180, description="Maximum total execution time in seconds.")
    follow_redirects: bool = Field(default=False, description="Follow redirects (-r).")
    insecure: bool = Field(default=True, description="Skip TLS certificate verification (-k).")
    # Scope plumbing (injected by BaseAgent.call_mcp; ignored if absent)
    mcp_scopes: Optional[list[dict]] = Field(default=None, description="Scope rules for filtering DB writes")
    mcp_default_in_out: str = Field(default="in", description="Default in/out for assets matching no rule")


def _build_ffuf_cmd(data: FfufInput) -> list[str]:
    cmd = [
        "ffuf",
        "-u", data.url,
        "-w", data.wordlist or FFUF_WORDLIST,
        "-t", str(data.threads),
        "-timeout", str(data.timeout),
        "-mc", data.match_codes,
        "-s",  # silent: emit only the matched FUZZ values, one per line
    ]

    if data.method and data.method.upper() != "GET":
        cmd += ["-X", data.method.upper()]

    if data.data:
        cmd += ["-d", data.data]

    if data.filter_codes:
        cmd += ["-fc", data.filter_codes]

    if data.filter_size:
        cmd += ["-fs", data.filter_size]

    if data.extensions:
        cmd += ["-e", data.extensions]

    merged_headers = dict(data.headers or {})
    if data.cookies:
        merged_headers["Cookie"] = data.cookies
    for header_name, header_value in merged_headers.items():
        cmd += ["-H", f"{header_name}: {header_value}"]

    if data.follow_redirects:
        cmd.append("-r")

    return cmd


class FfufTool(BaseTool):
    name = "run_ffuf"
    description = (
        "Run ffuf to fuzz a target for content discovery, hidden parameters/endpoints, "
        "object-id ranges (IDOR sweeps), and value-level logic fuzzing. The URL must contain "
        "the FUZZ keyword at the position to fuzz. Each matched payload is returned, and when "
        "scan_uuid+target_uuid are supplied for path discovery the discovered endpoints are "
        "saved to the database. Supports authenticated fuzzing via 'headers'/'cookies'."
    )
    input_model = FfufInput

    def run(self, data: FfufInput) -> ToolResult:
        if "FUZZ" not in data.url and not (data.data and "FUZZ" in data.data):
            return ToolResult(success=False, output="ffuf needs a FUZZ keyword in the url (or data) marking the fuzz position.")

        cmd = _build_ffuf_cmd(data)
        try:
            code, out, err = run_command(cmd, timeout=data.max_time + 10)
        except subprocess.TimeoutExpired:
            return ToolResult(success=False, output=f"ffuf timed out after {data.max_time}s on {data.url}")
        except Exception as e:
            return ToolResult(success=False, output=f"ffuf execution error: {e}")

        output = out if out else ""
        matches = [ln.strip() for ln in output.splitlines() if ln.strip()]
        if not matches:
            return ToolResult(success=True, output=f"ffuf completed on {data.url} — no matches.")

        # Reconstruct the concrete URLs the matches correspond to (path-position fuzz).
        reconstructed = [data.url.replace("FUZZ", m) for m in matches]
        report = f"ffuf found {len(matches)} match(es) on {data.url}:\n" + "\n".join(reconstructed[:200])

        # DB mode: persist path-discovery hits as endpoints (only when FUZZ is in
        # the URL path, mirroring gobuster's endpoint persistence).
        db_mode = bool(data.scan_uuid and data.target_uuid and "FUZZ" in data.url)
        if db_mode:
            try:
                from db import get_repo
                from scope_filter import is_in_scope
                repo = get_repo()
                total_saved = 0
                total_oos = 0
                for full_url in reconstructed:
                    parsed = urlparse(full_url)
                    host = parsed.netloc or parsed.path
                    path = parsed.path or "/"
                    if not is_in_scope(full_url, data.mcp_scopes, data.mcp_default_in_out):
                        total_oos += 1
                        continue
                    saved = repo.upsert_endpoint(
                        target_uuid=data.target_uuid,
                        scan_uuid=data.scan_uuid,
                        host=host,
                        url=full_url,
                        path=path,
                        source="ffuf",
                        method=data.method.upper() if data.method else "GET",
                        status_code=None,
                        content_length=None,
                        redirect_url="",
                    )
                    if saved:
                        total_saved += 1
                summary = f"ffuf complete. {len(matches)} match(es), saved {total_saved} new endpoint(s) to DB."
                if total_oos:
                    summary += f" Skipped {total_oos} out-of-scope."
                return ToolResult(
                    success=True,
                    output=f"{summary}\n\n{report}",
                    db_ref={"table": "endpoints", "rows_saved": total_saved, "total_found": len(matches), "scope_skipped": total_oos},
                )
            except Exception as e:
                return ToolResult(success=True, output=f"{report}\n\n[DB save error: {e}]")

        return ToolResult(success=True, output=report)
