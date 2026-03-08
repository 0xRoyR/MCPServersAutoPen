"""
MCP Server Permission System (Option B - Single server with per-agent filtering)

Maps each agent ID to the set of tool names it is allowed to invoke.
The server enforces this at call time by checking the _agent_id field.

Future: Migrate to Option A (per-agent server instances) when deploying to cloud.
See TODO.md #1 in the root repo.
"""

AGENT_PERMISSIONS: dict[str, list[str]] = {
    # Pre-flight recon — runs before any LLM agent kicks in
    "recon_agent": [
        "run_subfinder",
        "run_whois",
        "run_nmap",
        "run_httpx",
        "run_gobuster",
        "run_waybackurls",
    ],

    # WAF detection + bypass profiling
    "waf_bypass_agent": [
        "run_curl",
        "run_httpx",
    ],

    # SQL Injection pipeline
    "sqli_recon_agent": [
        "run_curl",
        "run_httpx",
    ],
    "sqli_exploit_agent": [
        "run_curl",
        "run_sqlmap",
    ],

    # XSS pipeline
    "xss_recon_agent": [
        "run_curl",
        "run_httpx",
    ],
    "xss_exploit_agent": [
        "run_curl",
    ],

    # SSRF pipeline
    "ssrf_recon_agent": [
        "run_curl",
        "run_httpx",
    ],
    "ssrf_exploit_agent": [
        "run_curl",
    ],

    # Information Disclosure pipeline
    "info_disclosure_recon_agent": [
        "run_curl",
        "run_httpx",
        "run_gobuster",
    ],
    "info_disclosure_exploit_agent": [
        "run_curl",
    ],
}

# Special sentinel: if agent_id is this value, all tools are allowed.
# Used only by internal testing / admin — never exposed to LLM agents.
SUPERUSER_AGENT_ID = "superuser"


def get_allowed_tools(agent_id: str) -> list[str] | None:
    """
    Returns the list of allowed tool names for a given agent_id.
    Returns None if the agent_id is unrecognised (deny all).
    Returns all tool names if agent_id == SUPERUSER_AGENT_ID.
    """
    if agent_id == SUPERUSER_AGENT_ID:
        return None  # Caller should allow all

    return AGENT_PERMISSIONS.get(agent_id)


def is_tool_allowed(agent_id: str, tool_name: str, all_tool_names: list[str]) -> bool:
    """
    Returns True if the given agent is allowed to call the given tool.
    """
    if agent_id == SUPERUSER_AGENT_ID:
        return True

    allowed = AGENT_PERMISSIONS.get(agent_id)
    if allowed is None:
        return False  # Unknown agent — deny

    return tool_name in allowed
