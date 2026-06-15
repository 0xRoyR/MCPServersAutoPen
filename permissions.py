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
        "run_katana",
        "run_paramspider",
        "run_arjun",
        "run_ffuf",
        "run_nuclei",
        "run_retirejs",
        "run_browser",
    ],

    # Target profiling + account registration
    "profile_agent": [
        "run_curl",
        "run_httpx",
        "run_gobuster",
    ],

    # WAF detection + bypass profiling
    "waf_bypass_agent": [
        "run_curl",
        "run_httpx",
    ],

    # SQL Injection pipeline. sqli_agent also offers OS command injection (commix)
    # via HITL when a parameter looks like it reaches a shell.
    "sqli_agent": [
        "run_curl",
        "run_sqlmap",
        "run_commix",
        "run_browser",
    ],
    "sqli_recon_agent": [
        "run_curl",
        "run_httpx",
    ],
    "sqli_exploit_agent": [
        "run_curl",
        "run_sqlmap",
    ],

    # XSS pipeline. The runtime XSS agent is the single-phase "xss_agent"; the
    # *_recon/_exploit ids below are retained for the split-pipeline variant.
    "xss_agent": [
        "run_curl",
        "run_dalfox",
        "run_browser",
    ],
    "xss_recon_agent": [
        "run_curl",
        "run_httpx",
        "run_dalfox",
    ],
    "xss_exploit_agent": [
        "run_curl",
        "run_dalfox",
    ],

    # SSRF pipeline
    "ssrf_recon_agent": [
        "run_curl",
        "run_httpx",
    ],
    "ssrf_exploit_agent": [
        "run_curl",
    ],

    # Information Disclosure pipeline. The runtime agent is the single-phase
    # "info_disclosure_agent", which also runs templated (nuclei) and SCA
    # (retire.js) breadth scans and turns the matches into findings.
    "info_disclosure_agent": [
        "run_curl",
        "run_nuclei",
        "run_retirejs",
    ],
    "info_disclosure_recon_agent": [
        "run_curl",
        "run_httpx",
        "run_gobuster",
        "run_nuclei",
        "run_retirejs",
    ],
    "info_disclosure_exploit_agent": [
        "run_curl",
    ],

    # Auth Bypass (single-phase). run_browser lets it stream a live-theater frame
    # of the weaponized privileged action (class B — non-destructive render).
    "auth_bypass_agent": [
        "run_curl",
        "run_sqlmap",
        "run_browser",
    ],

    # Cookie / JWT manipulation (single-phase)
    "cookie_jwt_agent": [
        "run_curl",
        "run_browser",
    ],

    # Business Logic Errors (single-phase) — replays operator-approved
    # value-manipulation writes via curl; ffuf for endpoint/value fuzzing.
    "logic_errors_agent": [
        "run_curl",
        "run_ffuf",
        "run_browser",
    ],

    # Path Traversal / LFI pipeline
    "path_traversal_recon_agent": [
        "run_curl",
        "run_httpx",
    ],
    "path_traversal_exploit_agent": [
        "run_curl",
    ],

    # XXE pipeline
    "xxe_recon_agent": [
        "run_curl",
        "run_httpx",
    ],
    "xxe_exploit_agent": [
        "run_curl",
    ],

    # IDOR / BAC pipeline. The runtime IDOR agent is the single-phase "idor_agent",
    # which fuzzes for hidden object endpoints (ffuf) and replays operator-approved
    # cross-principal writes (curl); the *_recon/_exploit ids are the split variant.
    "idor_agent": [
        "run_curl",
        "run_ffuf",
        "run_browser",
    ],
    "idor_recon_agent": [
        "run_curl",
        "run_httpx",
        "run_gobuster",
        "run_ffuf",
    ],
    "idor_exploit_agent": [
        "run_curl",
    ],

    # Strategy agent — pure analysis + recon planning, delegates execution to recon_agent
    "strategy_agent": [
        "run_curl",
        "get_attack_surface",
        "get_endpoints",
        "get_http_services",
        "get_subdomains",
    ],

    # Queue agent — URL queue lifecycle + per-URL vector planning
    "queue_agent": [
        "run_curl",
        "get_attack_surface",
        "get_endpoints",
        "get_http_services",
        "get_subdomains",
    ],

    # Review agent — post-round review + escalation decisions (analysis only)
    "review_agent": [],

    # Master agent — legacy, superseded by strategy_agent (kept for backwards compat)
    "master_agent": [
        "run_whois",
        "run_subfinder",
        "run_nmap",
        "run_httpx",
        "run_gobuster",
        "run_waybackurls",
        "run_katana",
        "run_paramspider",
        "run_arjun",
        "run_curl",
        "get_attack_surface",
        "get_endpoints",
        "get_http_services",
        "get_subdomains",
    ],

    # Master web agent — legacy, superseded by queue_agent + review_agent
    "master_web_agent": [
        "run_curl",
        "run_httpx",
        "get_attack_surface",
        "get_endpoints",
        "get_http_services",
        "get_subdomains",
    ],

    # Authenticated re-recon — re-runs recon tools with privileged session
    "authenticated_recon_agent": [
        "run_curl",
        "run_gobuster",
        "run_httpx",
        "run_katana",
        "run_arjun",
    ],

    # FTP — non-AI network agent (Full Assessment, domain/IP only)
    "ftp_agent": [
        "run_ftp_anon_check",
    ],

    # Recheck agent — re-verifies a single finding on demand. Needs the FTP tool
    # to re-run anonymous-login checks for FTP findings (HTTP rechecks use local curl).
    "recheck_agent": [
        "run_ftp_anon_check",
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
