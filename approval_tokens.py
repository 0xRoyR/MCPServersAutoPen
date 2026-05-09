"""
MCP Server Approval Token verification

When a human approves a class C / D action on the frontend, the backend
records it in the pending_approvals table and the agent server is handed
a single-use HMAC token. The agent attaches that token to the re-injected
tool call, and the MCP server verifies it here before running the tool.

Token format: base64url(hmac_sha256(INTERNAL_API_KEY, "<approval_id>|<fingerprint>|<issued_at>")).<approval_id>.<fingerprint>.<issued_at>

The token ties an approval to:
  - the specific approval row (approval_id)
  - the exact normalized arguments (fingerprint)
  - the time it was issued (issued_at, epoch seconds)

Single-use guarantee: the MCP server keeps a small in-memory set of
consumed tokens. A token that has already been used is rejected even if
the signature is valid — this prevents an agent bug (or a compromised
agent server) from replaying one approval for multiple tool calls.

If the MCP server process restarts the set is lost, but the approval row
in MySQL will have status='approved' + resolved_at set, so the agent
server can simply re-fetch the token after noticing the rejection.
"""

from __future__ import annotations

import base64
import hmac
import hashlib
import os
import time


# ── In-process single-use tracking ────────────────────────────────────────────
# Keyed by the raw token string. A time-ordered list lets us evict old entries
# so memory does not grow without bound across long scan sessions.

_consumed: set[str] = set()
_consumed_order: list[tuple[float, str]] = []
_MAX_TRACKED = 10_000


def _evict_old() -> None:
    """Trim the consumed-token bookkeeping when it grows past the cap."""
    if len(_consumed_order) <= _MAX_TRACKED:
        return
    drop = len(_consumed_order) - _MAX_TRACKED
    for _, token in _consumed_order[:drop]:
        _consumed.discard(token)
    del _consumed_order[:drop]


# ── Token verification ────────────────────────────────────────────────────────

def _shared_secret() -> bytes:
    return os.environ.get("INTERNAL_API_KEY", "change-me-internal-key").encode("utf-8")


def sign(approval_id: str, fingerprint_hex: str, issued_at: int | None = None) -> str:
    """
    Build a token for a given approval. Only used for local testing / tools —
    the real tokens are minted by the ApprovalManager in the agent server.
    """
    issued_at = issued_at or int(time.time())
    body = f"{approval_id}|{fingerprint_hex}|{issued_at}"
    mac = hmac.new(_shared_secret(), body.encode("utf-8"), hashlib.sha256).digest()
    mac_b64 = base64.urlsafe_b64encode(mac).decode("ascii").rstrip("=")
    return f"{mac_b64}.{approval_id}.{fingerprint_hex}.{issued_at}"


def verify(token: str, expected_fingerprint: str, max_age_seconds: int = 86_400) -> tuple[bool, str]:
    """
    Validate an approval token carried by a tool call.

    Returns (ok, reason).
      ok     — True if the token is valid and not yet consumed
      reason — short human-readable diagnostic ('' on success)

    On success the token is immediately marked consumed — a second verify()
    call with the same token will return (False, 'token_already_used').
    """
    if not token:
        return False, "token_missing"

    parts = token.split(".")
    if len(parts) != 4:
        return False, "token_malformed"

    mac_b64, approval_id, fingerprint_hex, issued_at_str = parts

    if fingerprint_hex != expected_fingerprint:
        return False, "fingerprint_mismatch"

    try:
        issued_at = int(issued_at_str)
    except ValueError:
        return False, "issued_at_malformed"

    if issued_at + max_age_seconds < int(time.time()):
        return False, "token_expired"

    body = f"{approval_id}|{fingerprint_hex}|{issued_at}"
    expected_mac = hmac.new(_shared_secret(), body.encode("utf-8"), hashlib.sha256).digest()
    padded = mac_b64 + "=" * (-len(mac_b64) % 4)
    try:
        actual_mac = base64.urlsafe_b64decode(padded.encode("ascii"))
    except Exception:
        return False, "token_malformed"

    if not hmac.compare_digest(expected_mac, actual_mac):
        return False, "signature_mismatch"

    if token in _consumed:
        return False, "token_already_used"

    _consumed.add(token)
    _consumed_order.append((time.time(), token))
    _evict_old()

    return True, ""
