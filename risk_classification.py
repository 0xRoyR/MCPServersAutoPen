"""
MCP Server Risk Classification — Human-in-the-Loop gate

Classifies every tool invocation into a risk class and decides whether
human approval is required before the tool runs.

Risk classes:
  A — passive / read-only                 (no approval required)
  B — active probing, non-destructive     (no approval required)
  C — potentially disruptive or high-signal (approval required)
  D — destructive / irreversible          (approval required, stricter UX)

Classification is done entirely on the MCP side so the agent server cannot
bypass it. If an agent sends a request that resolves to class C or D, the
server refuses execution unless the request carries a valid approval_token
previously issued by the ApprovalManager.

See docs/risk_classes.md for the full matrix.
"""

from __future__ import annotations

import os
import re
from typing import Any


# ── Tool-level default classes ────────────────────────────────────────────────
# The per-argument rules below may bump a specific call up to a higher class.

_DEFAULT_TOOL_CLASS: dict[str, str] = {
    # Passive reconnaissance
    "run_whois":        "A",
    "run_subfinder":    "A",
    "run_waybackurls":  "A",
    "run_httpx":        "A",
    "get_attack_surface":   "A",
    "get_endpoints":        "A",
    "get_http_services":    "A",
    "get_subdomains":       "A",

    # Active probing, non-destructive
    "run_nmap":         "B",
    "run_gobuster":     "B",
    "run_katana":       "B",
    "run_paramspider":  "B",
    "run_arjun":        "B",
    "run_curl":         "B",

    # High-signal exploitation tooling — default C, escalates to D on mutation
    "run_sqlmap":       "C",
    "run_nosqlmap":     "C",
}


# ── sqlmap argument heuristics ────────────────────────────────────────────────
# sqlmap can be merely confirmatory (class C) or actively destructive (class D).
# These patterns are evaluated against the combined cmd/args string.

_SQLMAP_DESTRUCTIVE_FLAGS = (
    "--os-shell", "--os-pwn", "--os-cmd", "--os-bof",
    "--sql-shell", "--sql-query",
    "--file-write", "--file-dest",
    "--reg-add", "--reg-del",
    "--drop",
)

_SQLMAP_AGGRESSIVE_FLAGS = (
    "--risk=3", "--level=5", "--level=4",
    "--dump-all", "--all",
)


# ── curl / HTTP method heuristics ─────────────────────────────────────────────
# Write-methods against the target can mutate state and require approval.

_WRITE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}

_DESTRUCTIVE_PAYLOAD_FRAGMENTS = (
    "drop table", "truncate table", "delete from",
    "update ", "insert into",
    "rm -rf", "format c:",
)


def classify(tool_name: str, arguments: dict[str, Any]) -> str:
    """
    Return the risk class ('A' | 'B' | 'C' | 'D') for a specific tool call.

    The classifier is deterministic — the same (tool_name, arguments) always
    resolves to the same class. Unknown tools default to 'C' so new tools
    fail safely (prompting human review instead of silently executing).
    """
    base = _DEFAULT_TOOL_CLASS.get(tool_name, "C")

    if tool_name == "run_sqlmap":
        return _classify_sqlmap(arguments, base)

    if tool_name == "run_curl":
        return _classify_curl(arguments, base)

    return base


def _auto_approved_classes() -> frozenset[str]:
    """Risk classes the operator has opted out of HITL for, via env var.

    Set ``AUTOPEN_AUTO_APPROVE_CLASSES`` to a comma-separated list (e.g. "C"
    or "C,D") to bypass the human approval gate for those classes. Intended
    for unattended scans against authorized targets where stopping for
    interactive approval is impractical.

    SECURITY NOTE: class D covers destructive sqlmap flags (--os-shell,
    --file-write, etc.). Auto-approving D is supported but should be used
    only on disposable lab targets. The default is empty — full HITL enforced.
    """
    raw = os.environ.get("AUTOPEN_AUTO_APPROVE_CLASSES", "")
    if not raw.strip():
        return frozenset()
    return frozenset(
        part.strip().upper() for part in raw.split(",") if part.strip()
    )


def requires_approval(risk_class: str) -> bool:
    """C and D need human approval unless the operator opted out via env var."""
    if risk_class not in ("C", "D"):
        return False
    return risk_class not in _auto_approved_classes()


# ── Internal: per-tool classifiers ────────────────────────────────────────────

def _classify_sqlmap(arguments: dict[str, Any], base: str) -> str:
    """sqlmap — bump to D on destructive flags, keep at C on aggressive flags."""
    blob = _stringify_args(arguments).lower()

    for flag in _SQLMAP_DESTRUCTIVE_FLAGS:
        if flag in blob:
            return "D"

    for frag in _DESTRUCTIVE_PAYLOAD_FRAGMENTS:
        if frag in blob:
            return "D"

    for flag in _SQLMAP_AGGRESSIVE_FLAGS:
        if flag in blob:
            return "C"

    # Default sqlmap invocation with --risk=1/2 is still class C (its whole
    # purpose is confirming injection, which we want a human to approve).
    return base


def _classify_curl(arguments: dict[str, Any], base: str) -> str:
    """curl — write methods or destructive payloads bump the class."""
    method = str(arguments.get("method", "GET")).upper()
    data = arguments.get("data") or ""
    if not isinstance(data, str):
        data = str(data)
    data_lower = data.lower()

    for frag in _DESTRUCTIVE_PAYLOAD_FRAGMENTS:
        if frag in data_lower:
            return "D"

    if method in _WRITE_METHODS and data:
        # A real mutating request against the target — requires approval.
        return "C"

    return base


def _stringify_args(arguments: dict[str, Any]) -> str:
    """Flatten all argument values to a single searchable string."""
    parts: list[str] = []
    for key, value in arguments.items():
        if value is None:
            continue
        if isinstance(value, (list, tuple)):
            parts.append(" ".join(str(v) for v in value))
        else:
            parts.append(str(value))
    return " ".join(parts)


# ── Approval fingerprint — used to bind an approval to exact args ─────────────

def fingerprint(tool_name: str, arguments: dict[str, Any]) -> str:
    """
    Stable, order-independent fingerprint of a tool call.

    Used both by the agent server (to dedupe pending approvals) and by the
    MCP server (to verify an approval token was issued for THESE exact args,
    not a different variant the agent might try to slip through later).
    """
    import hashlib
    import json

    normalized = _normalize(arguments)
    payload = json.dumps({"tool": tool_name, "args": normalized}, sort_keys=True)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _normalize(value: Any) -> Any:
    """Recursively sort dict keys and collapse whitespace in strings."""
    if isinstance(value, dict):
        return {k: _normalize(value[k]) for k in sorted(value.keys())}
    if isinstance(value, list):
        return [_normalize(v) for v in value]
    if isinstance(value, str):
        return re.sub(r"\s+", " ", value).strip()
    return value
