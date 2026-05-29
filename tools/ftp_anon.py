"""
FTP anonymous-login check — a dumb, deterministic probe (no AI).

Attempts an anonymous FTP login (USER anonymous) against a single host's
port 21. If the login succeeds (FTP 230), optionally lists the anonymous
root for evidence. Read-only: never writes, deletes, or uploads.

A 30-second socket timeout bounds every step (connect + login + list); a
hang therefore resolves to "not allowed" rather than blocking the scan.

Returns a JSON document the FtpAnonAgent parses:
    {
      "host": ..., "port": 21,
      "anonymous_allowed": true|false,
      "banner": "...", "welcome": "230 ...", "login_code": "230",
      "dir_listing": ["..."], "error": ""
    }
"""

import ftplib
import json
import socket
from typing import Optional
from urllib.parse import urlparse

from pydantic import BaseModel, Field

from tools.base import BaseTool, ToolResult


class FtpAnonInput(BaseModel):
    host: str = Field(description="Target hostname or IP to test for anonymous FTP login")
    port: int = Field(default=21, description="FTP control port (default 21)")
    timeout: int = Field(default=30, description="Per-host socket timeout in seconds; a hang resolves to 'not allowed'")
    list_root: bool = Field(default=True, description="LIST the anonymous root for evidence when login succeeds")
    # Scope plumbing (injected by BaseAgent.call_mcp; accepted and ignored here)
    mcp_scopes: Optional[list[dict]] = Field(default=None, description="Scope rules (unused by this tool)")
    mcp_default_in_out: str = Field(default="in", description="Default in/out (unused by this tool)")


class FtpAnonTool(BaseTool):
    name = "run_ftp_anon_check"
    description = (
        "Deterministic check (no AI): attempt anonymous FTP login (username 'anonymous') "
        "on a host's port 21. Returns whether anonymous access is allowed, the server banner, "
        "and a read-only directory listing of the anonymous root. Read-only — never writes. "
        "30s timeout per host; a hang is treated as 'not allowed'."
    )
    input_model = FtpAnonInput

    def run(self, data: FtpAnonInput) -> ToolResult:
        host = (data.host or "").strip()
        # Normalize: accept a bare host, an ftp:// URL, or an http(s):// URL
        if "://" in host:
            host = urlparse(host).hostname or host
        # Strip any leftover path/port fragments
        host = host.split("/", 1)[0].split(":", 1)[0]

        result = {
            "host": host,
            "port": data.port,
            "anonymous_allowed": False,
            "banner": "",
            "welcome": "",
            "login_code": "",
            "dir_listing": [],
            "error": "",
        }

        if not host:
            result["error"] = "no host provided"
            return ToolResult(success=False, output=json.dumps(result, indent=2))

        ftp = ftplib.FTP()
        try:
            ftp.connect(host, data.port, timeout=data.timeout)
            result["banner"] = (ftp.getwelcome() or "").strip()

            # Anonymous login — ftplib defaults to user 'anonymous' when omitted,
            # but we pass an explicit conventional password for clarity.
            welcome = ftp.login(user="anonymous", passwd="anonymous@autopen.local")
            welcome = welcome.strip() if isinstance(welcome, str) else str(welcome)
            result["welcome"] = welcome
            result["login_code"] = welcome[:3]
            result["anonymous_allowed"] = True

            if data.list_root:
                listing: list[str] = []
                try:
                    ftp.retrlines("LIST", listing.append)
                except Exception:
                    try:
                        listing = ftp.nlst()
                    except Exception:
                        listing = []
                result["dir_listing"] = listing[:100]

            try:
                ftp.quit()
            except Exception:
                ftp.close()

        except ftplib.error_perm as exc:
            # Login refused (e.g. 530) — the expected, healthy result. Not vulnerable.
            result["error"] = f"login refused: {exc}"
            _safe_close(ftp)
        except (socket.timeout, TimeoutError):
            result["error"] = f"timeout after {data.timeout}s — evaluated as not allowed"
            _safe_close(ftp)
        except (socket.gaierror, ConnectionRefusedError, OSError) as exc:
            # No FTP service / unreachable / connection reset — not vulnerable.
            result["error"] = f"connection failed: {type(exc).__name__}: {exc}"
            _safe_close(ftp)
        except Exception as exc:
            result["error"] = f"{type(exc).__name__}: {exc}"
            _safe_close(ftp)

        # success=True means the probe ran to completion (regardless of verdict),
        # matching how the other MCP tools report. The verdict is in the JSON body.
        return ToolResult(success=True, output=json.dumps(result, indent=2))


def _safe_close(ftp: ftplib.FTP) -> None:
    try:
        ftp.close()
    except Exception:
        pass
