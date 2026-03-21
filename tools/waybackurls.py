from typing import Optional
from urllib.parse import urlparse, parse_qs
from pydantic import BaseModel, Field

from tools.base import BaseTool, ToolResult
from execution.runner import run_command


class WaybackurlsInput(BaseModel):
    scan_uuid: Optional[str] = Field(default=None, description="Scan UUID — required for DB mode")
    target_uuid: Optional[str] = Field(default=None, description="Target UUID — required for DB mode")
    domain: Optional[str] = Field(default=None, description="Domain to fetch historical URLs for (e.g., example.com). If omitted with scan_uuid+target_uuid, reads http_services from DB.")
    no_subs: bool = Field(default=False, description="Don't include subdomains in results")
    date: Optional[str] = Field(default=None, description="Filter URLs to those before this date (YYYYMMDD)")
    get_versions: bool = Field(default=False, description="List URLs and the dates they appeared (slow)")
    max_time: int = Field(default=120, description="Maximum execution time in seconds")


def _run_waybackurls(domain: str, data: WaybackurlsInput) -> tuple[int, str, str]:
    cmd = ["waybackurls"]
    if data.no_subs:
        cmd.append("--no-subs")
    if data.date:
        cmd += ["--date", data.date]
    if data.get_versions:
        cmd.append("--get-versions")
    return run_command(cmd, timeout=data.max_time + 10, stdin_input=domain)


def _deduplicate(urls: list[str], existing_urls: set[str]) -> list[str]:
    """Deduplicate URL list (anew-style: only keep new URLs)."""
    seen = set(existing_urls)
    result = []
    for url in urls:
        url = url.strip()
        if url and url not in seen:
            seen.add(url)
            result.append(url)
    return result


def _parse_url_params(url: str) -> list[str]:
    """Extract GET parameter names from a URL."""
    try:
        parsed = urlparse(url)
        params = list(parse_qs(parsed.query).keys())
        return params
    except Exception:
        return []


class WaybackurlsTool(BaseTool):
    name = "run_waybackurls"
    description = (
        "Fetch historical URLs for a domain from the Wayback Machine (web.archive.org). "
        "When scan_uuid and target_uuid are provided, waybackurls reads the root domain from the "
        "http_services table, deduplicates against already-known endpoints (anew-style), "
        "and saves new endpoints + GET parameters to the database. "
        "Very useful for discovering hidden endpoints, old API versions, and forgotten parameters."
    )
    input_model = WaybackurlsInput

    def run(self, data: WaybackurlsInput) -> ToolResult:
        db_mode = bool(data.scan_uuid and data.target_uuid)
        domains_to_query = []

        if db_mode and not data.domain:
            try:
                from db import get_repo
                repo = get_repo()
                http_services = repo.get_http_services(data.target_uuid)
                if not http_services:
                    return ToolResult(success=False, output="No HTTP services found in DB. Run httpx first.")
                # Extract unique root domains from http_services
                seen_domains = set()
                for svc in http_services:
                    parsed = urlparse(svc.get("url", ""))
                    host = parsed.netloc or svc.get("host", "")
                    # Strip port
                    domain = host.split(":")[0]
                    if domain and domain not in seen_domains:
                        seen_domains.add(domain)
                        domains_to_query.append(domain)
            except Exception as e:
                return ToolResult(success=False, output=f"Failed to read http_services from DB: {e}")
        elif data.domain:
            domains_to_query = [data.domain]
        else:
            return ToolResult(success=False, output="Error: either 'domain' or scan_uuid+target_uuid must be provided")

        # Get existing endpoint URLs for deduplication
        existing_urls: set[str] = set()
        if db_mode:
            try:
                from db import get_repo
                existing_endpoints = get_repo().get_endpoints(data.target_uuid)
                existing_urls = {e["url"] for e in existing_endpoints}
            except Exception:
                pass

        all_urls: list[str] = []
        last_error: str | None = None
        for domain in domains_to_query:
            try:
                code, out, err = _run_waybackurls(domain, data)
            except Exception as e:
                last_error = str(e)
                continue
            if out and out.strip():
                all_urls.extend(out.strip().splitlines())

        if not all_urls:
            if last_error:
                return ToolResult(success=False, output=f"waybackurls failed: {last_error}")
            return ToolResult(success=True, output="No historical URLs found.")

        # Deduplicate (anew-style)
        new_urls = _deduplicate(all_urls, existing_urls)

        if not db_mode:
            return ToolResult(success=True, output="\n".join(new_urls))

        # Persist new endpoints + parameters to DB
        try:
            from db import get_repo
            repo = get_repo()
            endpoints_saved = 0
            params_saved = 0

            for url in new_urls:
                url = url.strip()
                if not url:
                    continue
                try:
                    parsed = urlparse(url)
                    host = parsed.netloc or ""
                    path = parsed.path or "/"
                    # Only save URLs with a proper host
                    if not host:
                        continue

                    endpoint_uuid = repo.upsert_endpoint(
                        target_uuid=data.target_uuid,
                        scan_uuid=data.scan_uuid,
                        host=host,
                        url=url,
                        path=path,
                        source="waybackurls",
                        method="GET",
                    )
                    if endpoint_uuid:
                        endpoints_saved += 1

                        # Save GET params
                        for param_name in _parse_url_params(url):
                            result = repo.upsert_endpoint_parameter(
                                target_uuid=data.target_uuid,
                                scan_uuid=data.scan_uuid,
                                endpoint_uuid=endpoint_uuid,
                                name=param_name,
                                param_type="GET",
                                source="waybackurls",
                            )
                            if result:
                                params_saved += 1
                except Exception:
                    continue

            return ToolResult(
                success=True,
                output=(
                    f"waybackurls complete. Found {len(all_urls)} total URLs, "
                    f"{len(new_urls)} new after deduplication. "
                    f"Saved {endpoints_saved} endpoints and {params_saved} parameters to DB."
                ),
                db_ref={
                    "table": "endpoints+endpoint_parameters",
                    "endpoints_saved": endpoints_saved,
                    "params_saved": params_saved,
                    "total_found": len(all_urls),
                    "new_after_dedup": len(new_urls),
                },
            )
        except Exception as e:
            return ToolResult(
                success=True,
                output=f"waybackurls complete but DB save failed: {e}\n\n" + "\n".join(new_urls[:50]),
            )
