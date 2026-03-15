from typing import Optional
from urllib.parse import urlparse, parse_qs
from pydantic import BaseModel, Field

from tools.base import BaseTool, ToolResult
from execution.runner import run_command


class KatanaInput(BaseModel):
    scan_uuid: Optional[str] = Field(default=None, description="Scan UUID — required for DB mode")
    target_uuid: Optional[str] = Field(default=None, description="Target UUID — required for DB mode")
    url: Optional[str] = Field(default=None, description="Target URL to crawl. If omitted with scan_uuid+target_uuid, reads http_services from DB automatically.")
    depth: int = Field(default=3, description="Crawl depth limit")
    js_crawl: bool = Field(default=True, description="Enable JavaScript crawling (passive JS parsing)")
    headless: bool = Field(default=False, description="Use headless browser for JS rendering (slower)")
    concurrency: int = Field(default=10, description="Number of concurrent requests")
    timeout: int = Field(default=10, description="Per-request timeout in seconds")
    max_time: int = Field(default=180, description="Maximum total execution time in seconds")
    silent: bool = Field(default=True, description="Silent mode — only output discovered URLs")
    headers: Optional[dict] = Field(
        default=None,
        description=(
            "Custom HTTP headers to include with every request. "
            "Use for authenticated crawling. "
            "Example: {\"Authorization\": \"Bearer eyJ...\", \"Cookie\": \"session=abc\"}"
        ),
    )
    cookies: Optional[str] = Field(
        default=None,
        description=(
            "Cookie string (e.g. 'session=abc123; csrf=xyz'). "
            "Convenience field — merged into headers as Cookie."
        ),
    )


def _run_katana_on_target(target_url: str, data: KatanaInput) -> str:
    cmd = [
        "katana",
        "-u", target_url,
        "-d", str(data.depth),
        "-c", str(data.concurrency),
        "-timeout", str(data.timeout),
    ]

    if data.js_crawl:
        cmd.append("-jc")

    if data.headless:
        cmd.append("-headless")

    if data.silent:
        cmd.append("-silent")

    merged_headers = dict(data.headers or {})
    if data.cookies:
        merged_headers["Cookie"] = data.cookies

    for header_name, header_value in merged_headers.items():
        cmd += ["-H", f"{header_name}: {header_value}"]

    code, out, err = run_command(cmd, timeout=data.max_time + 10)
    return out if out else err


def _deduplicate(urls: list[str], existing_urls: set[str]) -> list[str]:
    seen = set(existing_urls)
    result = []
    for url in urls:
        url = url.strip()
        if url and url not in seen:
            seen.add(url)
            result.append(url)
    return result


def _parse_url_params(url: str) -> list[str]:
    try:
        parsed = urlparse(url)
        return list(parse_qs(parsed.query).keys())
    except Exception:
        return []


class KatanaTool(BaseTool):
    name = "run_katana"
    description = (
        "Run katana web crawler to discover endpoints and URLs in a web application. "
        "When scan_uuid and target_uuid are provided without an explicit url, "
        "katana automatically reads all live HTTP services from the database and crawls each one. "
        "New endpoints and GET parameters are deduplicated (anew-style) and saved to the database. "
        "Supports passive JavaScript crawling and authenticated crawling via 'headers'/'cookies'."
    )
    input_model = KatanaInput

    def run(self, data: KatanaInput) -> ToolResult:
        db_mode = bool(data.scan_uuid and data.target_uuid)
        targets: list[str] = []

        if db_mode and not data.url:
            try:
                from db import get_repo
                repo = get_repo()
                http_services = repo.get_http_services(data.target_uuid)
                if not http_services:
                    return ToolResult(success=False, output="No HTTP services found in DB. Run httpx first.")
                targets = [s["url"] for s in http_services]
            except Exception as e:
                return ToolResult(success=False, output=f"Failed to read http_services from DB: {e}")
        elif data.url:
            targets = [data.url]
        else:
            return ToolResult(success=False, output="Error: either 'url' or scan_uuid+target_uuid must be provided")

        # Get existing URLs for deduplication
        existing_urls: set[str] = set()
        if db_mode:
            try:
                from db import get_repo
                existing_endpoints = get_repo().get_endpoints(data.target_uuid)
                existing_urls = {e["url"] for e in existing_endpoints}
            except Exception:
                pass

        all_discovered: list[str] = []
        for target_url in targets:
            try:
                output = _run_katana_on_target(target_url, data)
                if output and output.strip():
                    all_discovered.extend(output.strip().splitlines())
            except Exception as e:
                continue

        if not all_discovered:
            return ToolResult(success=True, output="No URLs discovered by katana.")

        # Deduplicate
        new_urls = _deduplicate(all_discovered, existing_urls)

        if not db_mode:
            return ToolResult(success=True, output="\n".join(new_urls))

        # Persist to DB
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
                    if not host:
                        continue

                    endpoint_uuid = repo.upsert_endpoint(
                        target_uuid=data.target_uuid,
                        scan_uuid=data.scan_uuid,
                        host=host,
                        url=url,
                        path=path,
                        source="katana",
                        method="GET",
                    )
                    if endpoint_uuid:
                        endpoints_saved += 1

                        for param_name in _parse_url_params(url):
                            result = repo.upsert_endpoint_parameter(
                                target_uuid=data.target_uuid,
                                scan_uuid=data.scan_uuid,
                                endpoint_uuid=endpoint_uuid,
                                name=param_name,
                                param_type="GET",
                                source="katana",
                            )
                            if result:
                                params_saved += 1
                except Exception:
                    continue

            return ToolResult(
                success=True,
                output=(
                    f"katana complete. Crawled {len(targets)} services, discovered {len(all_discovered)} URLs, "
                    f"{len(new_urls)} new after deduplication. "
                    f"Saved {endpoints_saved} endpoints and {params_saved} parameters to DB."
                ),
                db_ref={
                    "table": "endpoints+endpoint_parameters",
                    "endpoints_saved": endpoints_saved,
                    "params_saved": params_saved,
                    "total_discovered": len(all_discovered),
                    "new_after_dedup": len(new_urls),
                },
            )
        except Exception as e:
            return ToolResult(
                success=True,
                output=f"katana complete but DB save failed: {e}\n\n" + "\n".join(new_urls[:50]),
            )
