from typing import Optional, Literal
from pydantic import BaseModel, Field

from tools.base import BaseTool, ToolResult
from execution.runner import run_command


class SqlmapInput(BaseModel):
    url: str = Field(description="Target URL to test (e.g., https://example.com/page?id=1)")
    data: Optional[str] = Field(default=None, description="POST data string (e.g., 'user=admin&pass=test')")
    method: Optional[str] = Field(default=None, description="HTTP method override (GET/POST)")
    headers: Optional[list[str]] = Field(default=None, description="Extra HTTP headers in 'Key: Value' format")
    cookie: Optional[str] = Field(default=None, description="HTTP Cookie header value")
    level: int = Field(default=1, ge=1, le=5, description="Test level (1-5). Higher = more tests")
    risk: int = Field(default=1, ge=1, le=3, description="Risk level (1-3). Higher = more dangerous tests. NEVER use 3 in POC mode")
    dbms: Optional[str] = Field(default=None, description="Force backend DBMS (e.g., mysql, postgresql, mssql)")
    technique: Optional[str] = Field(
        default=None,
        description="SQL injection techniques to use: B(oolean), E(rror), U(nion), S(tacked), T(ime), Q(uery). E.g., 'BEU'"
    )
    # Detection options
    string: Optional[str] = Field(default=None, description="String to match when query is True")
    not_string: Optional[str] = Field(default=None, description="String to match when query is False")
    # Enumeration (only used in full_compromise mode — agents must enforce this)
    dbs: bool = Field(default=False, description="Enumerate databases (full_compromise mode only)")
    tables: bool = Field(default=False, description="Enumerate tables (full_compromise mode only)")
    dump: bool = Field(default=False, description="Dump table entries (full_compromise mode only — NEVER dumps passwords without explicit approval)")
    dump_table: Optional[str] = Field(default=None, description="Specific table to dump (-T flag)")
    dump_db: Optional[str] = Field(default=None, description="Specific database to dump (-D flag)")
    exclude_sysdbs: bool = Field(default=True, description="Exclude system databases from enumeration")
    # Output control
    batch: bool = Field(default=True, description="Never ask for user input (always use default answers)")
    answers: Optional[str] = Field(default=None, description="Set pre-defined answers to prompts")
    output_dir: Optional[str] = Field(default=None, description="Custom output directory for results")
    forms: bool = Field(default=False, description="Parse and test forms on target URL")
    crawl: int = Field(default=0, ge=0, le=3, description="Crawl depth (0 = disabled)")
    threads: int = Field(default=10, ge=1, le=10, description="Number of concurrent HTTP requests (capped at 10 — sqlmap becomes unstable and highly detectable above this)")
    timeout: int = Field(default=30, description="Seconds to wait before timeout")
    max_time: int = Field(default=300, description="Maximum total execution time in seconds")
    random_agent: bool = Field(default=True, description="Use a random User-Agent")
    proxy: Optional[str] = Field(default=None, description="Proxy URL (e.g., http://127.0.0.1:8080)")
    tamper: Optional[str] = Field(default=None, description="Tamper script(s) to use (e.g., 'space2comment,between')")


class SqlmapTool(BaseTool):
    name = "run_sqlmap"
    description = (
        "Run sqlmap for automated SQL injection detection and exploitation. "
        "In POC mode: detection only (boolean/error/union based). "
        "In full_compromise mode: can enumerate databases and dump data. "
        "IMPORTANT: Never use risk=3 in POC mode. Never enable dump without explicit agent decision. "
        "Never modify or delete database records — read-only operations only."
    )
    input_model = SqlmapInput

    def run(self, data: SqlmapInput) -> ToolResult:
        cmd = [
            "sqlmap",
            "-u", data.url,
        ]

        if data.data:
            cmd += ["--data", data.data]

        if data.method:
            cmd += ["--method", data.method.upper()]

        if data.headers:
            for header in data.headers:
                cmd += ["-H", header]

        if data.cookie:
            cmd += ["--cookie", data.cookie]

        cmd += ["--level", str(data.level)]
        cmd += ["--risk", str(data.risk)]

        if data.dbms:
            cmd += ["--dbms", data.dbms]

        if data.technique:
            cmd += ["--technique", data.technique]

        if data.string:
            cmd += ["--string", data.string]

        if data.not_string:
            cmd += ["--not-string", data.not_string]

        # Enumeration flags
        if data.dbs:
            cmd.append("--dbs")

        if data.tables:
            cmd.append("--tables")

        if data.dump:
            cmd.append("--dump")
            # Safety: always exclude system databases when dumping
            if data.exclude_sysdbs:
                cmd.append("--exclude-sysdbs")

        if data.dump_table:
            cmd += ["-T", data.dump_table]

        if data.dump_db:
            cmd += ["-D", data.dump_db]

        if data.batch:
            cmd.append("--batch")

        if data.answers:
            cmd += ["--answers", data.answers]

        if data.output_dir:
            cmd += ["--output-dir", data.output_dir]

        if data.forms:
            cmd.append("--forms")

        if data.crawl > 0:
            cmd += ["--crawl", str(data.crawl)]

        cmd += ["--threads", str(data.threads)]
        cmd += ["--timeout", str(data.timeout)]

        if data.random_agent:
            cmd.append("--random-agent")

        if data.proxy:
            cmd += ["--proxy", data.proxy]

        if data.tamper:
            cmd += ["--tamper", data.tamper]

        # Disable update check and color for clean output
        cmd += ["--disable-coloring", "--no-logging"]

        try:
            code, out, err = run_command(cmd, timeout=data.max_time + 10)
        except Exception as e:
            return ToolResult(success=False, output=f"sqlmap execution error: {str(e)}")

        output = out if out else err
        if not output:
            return ToolResult(success=False, output="sqlmap returned no output")

        return ToolResult(success=True, output=output)
