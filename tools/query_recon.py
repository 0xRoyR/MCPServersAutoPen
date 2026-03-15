"""
Query tools for reading reconnaissance data from the database.
Used by master agents to get a full picture of the attack surface
after the preflight recon phase completes.
"""
from typing import Optional
from pydantic import BaseModel, Field

from tools.base import BaseTool, ToolResult


# ── get_attack_surface ────────────────────────────────────────────────────────

class GetAttackSurfaceInput(BaseModel):
    scan_uuid: str = Field(description="Scan UUID")
    target_uuid: str = Field(description="Target UUID")


class GetAttackSurfaceTool(BaseTool):
    name = "get_attack_surface"
    description = (
        "Query the database for the complete attack surface of a target after recon is complete. "
        "Returns all subdomains, live HTTP services, and discovered endpoints (with their GET parameters). "
        "Call this after run_subfinder + run_httpx + run_gobuster + run_waybackurls + run_katana "
        "to get a consolidated view before planning attacks."
    )
    input_model = GetAttackSurfaceInput

    def run(self, data: GetAttackSurfaceInput) -> ToolResult:
        try:
            from db import get_repo
            repo = get_repo()
            surface = repo.get_attack_surface(data.target_uuid)

            subdomains = surface.get("subdomains", [])
            http_services = surface.get("http_services", [])
            endpoints = surface.get("endpoints", [])

            lines = [
                f"=== Attack Surface for target {data.target_uuid} ===",
                f"",
                f"SUBDOMAINS ({len(subdomains)}):",
            ]
            for s in subdomains:
                lines.append(f"  {s.get('subdomain')} [{s.get('source')}]")

            lines += ["", f"LIVE HTTP SERVICES ({len(http_services)}):"]
            for h in http_services:
                tech = h.get("technologies", "[]")
                lines.append(f"  {h.get('url')} [{h.get('status_code')}] {h.get('title', '')} | {h.get('webserver', '')} | tech={tech}")

            lines += ["", f"ENDPOINTS ({len(endpoints)}):"]
            for e in endpoints:
                params = e.get("params", [])
                param_str = f" ?params=[{','.join(params)}]" if params else ""
                lines.append(f"  {e.get('method', 'GET')} {e.get('url')} [{e.get('status_code', '?')}] [{e.get('source')}]{param_str}")

            return ToolResult(
                success=True,
                output="\n".join(lines),
                db_ref={
                    "subdomains": len(subdomains),
                    "http_services": len(http_services),
                    "endpoints": len(endpoints),
                },
            )
        except Exception as e:
            return ToolResult(success=False, output=f"Failed to query attack surface: {e}")


# ── get_endpoints ─────────────────────────────────────────────────────────────

class GetEndpointsInput(BaseModel):
    scan_uuid: str = Field(description="Scan UUID")
    target_uuid: str = Field(description="Target UUID")
    source: Optional[str] = Field(default=None, description="Filter by source (gobuster, waybackurls, katana)")


class GetEndpointsTool(BaseTool):
    name = "get_endpoints"
    description = (
        "Query the database for all discovered endpoints for a target. "
        "Each endpoint includes URL, path, method, status code, source tool, and GET parameters. "
        "Use to find specific endpoints to attack."
    )
    input_model = GetEndpointsInput

    def run(self, data: GetEndpointsInput) -> ToolResult:
        try:
            from db import get_repo
            repo = get_repo()
            endpoints = repo.get_endpoints(data.target_uuid)

            if data.source:
                endpoints = [e for e in endpoints if e.get("source") == data.source]

            if not endpoints:
                return ToolResult(success=True, output="No endpoints found in DB for this target.")

            lines = [f"Endpoints ({len(endpoints)}):"]
            for e in endpoints:
                params = e.get("params", [])
                param_str = f" params=[{','.join(params)}]" if params else ""
                lines.append(
                    f"  [{e.get('method', 'GET')}] {e.get('url')} "
                    f"status={e.get('status_code', '?')} source={e.get('source')}{param_str}"
                )

            return ToolResult(success=True, output="\n".join(lines))
        except Exception as e:
            return ToolResult(success=False, output=f"Failed to query endpoints: {e}")


# ── get_http_services ─────────────────────────────────────────────────────────

class GetHttpServicesInput(BaseModel):
    scan_uuid: str = Field(description="Scan UUID")
    target_uuid: str = Field(description="Target UUID")


class GetHttpServicesTool(BaseTool):
    name = "get_http_services"
    description = (
        "Query the database for all live HTTP services discovered for a target. "
        "Returns URL, status code, title, webserver, and detected technologies. "
        "Use to select specific services to attack or enumerate further."
    )
    input_model = GetHttpServicesInput

    def run(self, data: GetHttpServicesInput) -> ToolResult:
        try:
            from db import get_repo
            repo = get_repo()
            services = repo.get_http_services(data.target_uuid)

            if not services:
                return ToolResult(success=True, output="No HTTP services found in DB for this target.")

            lines = [f"Live HTTP Services ({len(services)}):"]
            for h in services:
                lines.append(
                    f"  {h.get('url')} [{h.get('status_code')}] "
                    f"title={h.get('title', '')} server={h.get('webserver', '')} "
                    f"tech={h.get('technologies', '[]')}"
                )

            return ToolResult(success=True, output="\n".join(lines))
        except Exception as e:
            return ToolResult(success=False, output=f"Failed to query HTTP services: {e}")


# ── get_subdomains ────────────────────────────────────────────────────────────

class GetSubdomainsInput(BaseModel):
    scan_uuid: str = Field(description="Scan UUID")
    target_uuid: str = Field(description="Target UUID")


class GetSubdomainsTool(BaseTool):
    name = "get_subdomains"
    description = (
        "Query the database for all discovered subdomains for a target. "
        "Use to see what subdomains were found during reconnaissance."
    )
    input_model = GetSubdomainsInput

    def run(self, data: GetSubdomainsInput) -> ToolResult:
        try:
            from db import get_repo
            repo = get_repo()
            subdomains = repo.get_subdomains(data.target_uuid)

            if not subdomains:
                return ToolResult(success=True, output="No subdomains found in DB for this target.")

            lines = [f"Subdomains ({len(subdomains)}):"]
            for s in subdomains:
                lines.append(f"  {s.get('subdomain')} [source={s.get('source')}]")

            return ToolResult(success=True, output="\n".join(lines))
        except Exception as e:
            return ToolResult(success=False, output=f"Failed to query subdomains: {e}")
