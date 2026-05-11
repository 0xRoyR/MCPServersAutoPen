from typing import Optional
from pydantic import BaseModel, Field

from tools.base import BaseTool, ToolResult
from execution.runner import run_command


class SubfinderInput(BaseModel):
    scan_uuid: Optional[str] = Field(default=None, description="Scan UUID — required for DB persistence")
    target_uuid: Optional[str] = Field(default=None, description="Target UUID — required for DB persistence")
    domain: Optional[str] = Field(default=None, description="Single domain to enumerate")
    domains_file: Optional[str] = Field(default=None, description="File containing list of domains")
    recursive: bool = Field(default=False, description="Use recursive enumeration")
    all_sources: bool = Field(default=False, description="Use all sources")
    silent: bool = Field(default=False, description="Silent mode, only output subdomains")
    timeout: int = Field(default=60, description="Timeout in seconds for each source")
    max_time: int = Field(default=180, description="Maximum total execution time in seconds")
    resolvers_file: Optional[str] = Field(default=None, description="File containing resolvers")
    sources: Optional[list[str]] = Field(default=None, description="Specific sources to use")
    # Scope plumbing (injected by BaseAgent.call_mcp; ignored if absent)
    mcp_scopes: Optional[list[dict]] = Field(default=None, description="Scope rules for filtering DB writes")
    mcp_default_in_out: str = Field(default="in", description="Default in/out for assets matching no rule")


class SubfinderTool(BaseTool):
    name = "run_subfinder"
    description = (
        "Run subfinder for subdomain enumeration. "
        "When scan_uuid and target_uuid are provided, discovered subdomains are saved directly "
        "to the database and a summary is returned instead of raw output."
    )
    input_model = SubfinderInput

    def run(self, data: SubfinderInput) -> ToolResult:
        if not data.domain and not data.domains_file:
            return ToolResult(success=False, output="Error: either 'domain' or 'domains_file' must be provided")

        cmd = ["subfinder"]

        if data.domain:
            cmd += ["-d", data.domain]

        if data.domains_file:
            cmd += ["-dL", data.domains_file]

        if data.recursive:
            cmd.append("-recursive")

        if data.all_sources:
            cmd.append("-all")

        if data.silent:
            cmd.append("-silent")

        cmd += ["-timeout", str(data.timeout)]

        if data.resolvers_file:
            cmd += ["-r", data.resolvers_file]

        if data.sources:
            cmd += ["-sources", ",".join(data.sources)]

        try:
            code, out, err = run_command(cmd, timeout=data.max_time + 10)
        except Exception as e:
            return ToolResult(success=False, output=f"Error: {str(e)}")

        if code != 0:
            return ToolResult(success=False, output=err)

        # If scan_uuid + target_uuid provided, persist to DB
        if data.scan_uuid and data.target_uuid and out:
            try:
                from db import get_repo
                from scope_filter import is_in_scope
                repo = get_repo()
                root_domain = data.domain or "unknown"
                lines = [l.strip() for l in out.splitlines() if l.strip()]
                saved = 0
                skipped_oos = 0
                for subdomain in lines:
                    if not is_in_scope(subdomain, data.mcp_scopes, data.mcp_default_in_out):
                        skipped_oos += 1
                        continue
                    result = repo.upsert_subdomain(
                        target_uuid=data.target_uuid,
                        scan_uuid=data.scan_uuid,
                        domain=root_domain,
                        subdomain=subdomain,
                        source="subfinder",
                    )
                    if result:
                        saved += 1
                msg = f"subfinder complete. Found {len(lines)} subdomains, saved {saved} new to DB."
                if skipped_oos:
                    msg += f" Skipped {skipped_oos} out-of-scope."
                return ToolResult(
                    success=True,
                    output=msg,
                    db_ref={"table": "subdomains", "rows_saved": saved, "total_found": len(lines), "scope_skipped": skipped_oos},
                )
            except Exception as e:
                # DB save failed — fall through to return raw output
                return ToolResult(success=True, output=f"subfinder complete but DB save failed: {e}\n\n{out}")

        return ToolResult(success=True, output=out)
