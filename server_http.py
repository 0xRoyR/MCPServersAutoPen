"""
MCP HTTP Server — port 5003

Exposes the MCP security tools as a REST API so the Python LangGraph
agent server can call them via HTTP instead of stdio.

Endpoints:
  GET  /tools?agent_id=<id>          — list tools allowed for agent
  POST /tools/call                    — call a specific tool
  GET  /health                        — health check

Auth: X-Internal-Key header (same shared secret used by backend ↔ agent server)

Future: Replace with per-agent server instances (Option A). See TODO.md #1.
"""

import argparse
import os
import sys
import time
from pathlib import Path
from typing import Any

# Make sure imports from the MCP server root work
sys.path.insert(0, str(Path(__file__).parent))

# ── CLI flags ──────────────────────────────────────────────────────────────────
# Parse --debug / --verbose before uvicorn starts so we can set env vars
# that runner.py reads at import time.
#
#   python server_http.py --debug          # full command + output logging
#   python server_http.py --debug --port 5003
#
_parser = argparse.ArgumentParser(description="AutoPen MCP HTTP Server", add_help=False)
_parser.add_argument("--debug", action="store_true", help="Enable verbose tool execution logging")
_parser.add_argument("--verbose", action="store_true", help="Alias for --debug")
_parser.add_argument("--port", type=int, default=None, help="Port to listen on (overrides MCP_HTTP_PORT env var)")
_args, _ = _parser.parse_known_args()

_DEBUG_MODE = _args.debug or _args.verbose
if _DEBUG_MODE:
    os.environ["MCP_DEBUG"] = "1"
    print("[MCP] Debug mode ON — tool commands, timing, and output will be logged to stdout", flush=True)

# Load .env — check MCPServersAutoPen/.env first, then AutoPenAgents/.env
from dotenv import load_dotenv
_here = Path(__file__).parent
load_dotenv(_here / ".env") or load_dotenv(_here.parent / "AutoPenAgents" / ".env")

from fastapi import FastAPI, HTTPException, Header, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel
import uvicorn

from registry import TOOLS
from permissions import is_tool_allowed, get_allowed_tools, SUPERUSER_AGENT_ID

# Build tool lookup dict
TOOLS_BY_NAME = {tool.name: tool for tool in TOOLS}
ALL_TOOL_NAMES = list(TOOLS_BY_NAME.keys())

app = FastAPI(
    title="AutoPen MCP HTTP Server",
    description="HTTP wrapper around the MCP security tools with per-agent permission enforcement",
    version="1.0.0",
)

INTERNAL_KEY = os.environ.get("INTERNAL_API_KEY", "change-me-internal-key")


def verify_internal_key(x_internal_key: str | None) -> None:
    if x_internal_key != INTERNAL_KEY:
        raise HTTPException(status_code=401, detail="Unauthorized: invalid internal key")


# ─── Health ──────────────────────────────────────────────────────────────────

@app.get("/health")
async def health():
    return {"status": "ok", "tools": ALL_TOOL_NAMES}


# ─── List Tools ──────────────────────────────────────────────────────────────

@app.get("/tools")
async def list_tools(
    agent_id: str,
    x_internal_key: str | None = Header(default=None),
):
    verify_internal_key(x_internal_key)

    if agent_id == SUPERUSER_AGENT_ID:
        allowed_names = ALL_TOOL_NAMES
    else:
        allowed_names = get_allowed_tools(agent_id)
        if allowed_names is None:
            raise HTTPException(status_code=403, detail=f"Unknown agent_id: {agent_id}")

    result = []
    for name in allowed_names:
        tool = TOOLS_BY_NAME.get(name)
        if tool:
            result.append({
                "name": tool.name,
                "description": tool.description,
                "inputSchema": tool.input_model.model_json_schema(),
            })

    return result


# ─── Call Tool ───────────────────────────────────────────────────────────────

class ToolCallRequest(BaseModel):
    agent_id: str
    tool_name: str
    arguments: dict[str, Any] = {}


@app.post("/tools/call")
async def call_tool(
    request: ToolCallRequest,
    x_internal_key: str | None = Header(default=None),
):
    verify_internal_key(x_internal_key)

    # Permission check
    if not is_tool_allowed(request.agent_id, request.tool_name, ALL_TOOL_NAMES):
        raise HTTPException(
            status_code=403,
            detail=f"Agent '{request.agent_id}' is not allowed to call tool '{request.tool_name}'"
        )

    tool = TOOLS_BY_NAME.get(request.tool_name)
    if not tool:
        raise HTTPException(status_code=404, detail=f"Tool not found: {request.tool_name}")

    # Always print a clean invocation header so the terminal shows what's running
    _sep = "─" * 60
    args_lines = "\n".join(
        f"  {k:<20} = {v}" for k, v in request.arguments.items()
    )
    print(
        f"\n{_sep}\n"
        f"\033[95m[MCP] {request.tool_name}\033[0m  ←  {request.agent_id}\n"
        f"{args_lines}\n"
        f"{_sep}",
        flush=True,
    )

    t0 = time.monotonic()
    try:
        input_data = tool.input_model(**request.arguments)
        result = tool.run(input_data)
    except Exception as e:
        elapsed = time.monotonic() - t0
        if _DEBUG_MODE:
            print(f"[MCP] ERROR tool={request.tool_name}  elapsed={elapsed:.2f}s  err={e}", flush=True)
        return JSONResponse(
            status_code=200,  # Return 200 even on tool failure — the result carries success=False
            content={
                "success": False,
                "output": f"Tool execution error: {str(e)}",
                "tool": request.tool_name,
                "agent_id": request.agent_id,
            }
        )

    elapsed = time.monotonic() - t0
    if _DEBUG_MODE:
        output_preview = (result.output or "")[:300].replace("\n", "↵")
        print(
            f"[MCP] DONE  tool={request.tool_name}  success={result.success}  "
            f"elapsed={elapsed:.2f}s  output_len={len(result.output or '')}  "
            f"preview={output_preview!r}",
            flush=True,
        )

    return {
        "success": result.success,
        "output": result.output,
        "tool": request.tool_name,
        "agent_id": request.agent_id,
    }


if __name__ == "__main__":
    port = _args.port or int(os.environ.get("MCP_HTTP_PORT", 5003))
    log_level = "debug" if _DEBUG_MODE else "info"
    print(f"[MCP HTTP Server] Starting on port {port}  debug={_DEBUG_MODE}")
    uvicorn.run(app, host="0.0.0.0", port=port, log_level=log_level)
