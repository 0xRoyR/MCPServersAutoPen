"""
MCP-side scope filter — mirrors AutoPenAgents/graph/scope_policy.py.

Tools that persist subdomains/hosts/endpoints accept two extra arguments
in their input model:
    _scopes         : list[dict]   — list of scope rules
    _default_in_out : str          — "in" | "out" — default for unlisted assets

Before calling repo.upsert_*, the tool calls is_in_scope(asset, scopes, default).

Duplicating the matcher (rather than cross-importing) keeps the two services
deployable independently.
"""

import fnmatch
import re
from typing import Iterable, Sequence
from urllib.parse import urlparse


_DOMAIN_RE = re.compile(r"^[a-z0-9.-]+$")


def _normalize_rule(rule):
    if not isinstance(rule, dict):
        return None
    value = (rule.get("value") or "").strip().lower()
    rule_type = (rule.get("type") or "").strip().lower()
    in_out = (rule.get("in_out") or rule.get("inOut") or "").strip().lower()
    if not value or rule_type not in ("domain", "url") or in_out not in ("in", "out"):
        return None
    return {
        "value": value,
        "type": rule_type,
        "in_out": in_out,
        "is_implicit": bool(rule.get("is_implicit") or rule.get("isImplicit")),
    }


def _extract_host(asset):
    if not asset:
        return None
    asset = asset.strip()
    if "://" in asset:
        try:
            host = urlparse(asset).hostname
            return host.lower() if host else None
        except Exception:
            return None
    bare = asset.split("/", 1)[0].split(":", 1)[0].lower()
    if _DOMAIN_RE.match(bare):
        return bare
    return None


def _is_url(asset):
    return "://" in (asset or "")


def _domain_matches(rule_value, host):
    if not host:
        return False
    if rule_value.startswith("*."):
        suffix = rule_value[2:]
        return host.endswith("." + suffix) and host != suffix
    return host == rule_value


def _url_matches(rule_value, url):
    """See AutoPenAgents/graph/scope_policy.py:_url_matches for the spec.

    Wildcard URL  (`*` in pattern) — `*` spans `/`, matches zero or more chars.
    Exact URL     (no `*`)         — literal match, tolerant of trailing slash;
                                     no path-prefix matching.
    Query/fragment stripped from target before matching.
    """
    if not url:
        return False
    target = url.split("#", 1)[0].split("?", 1)[0].lower()
    pattern = rule_value.lower()
    if "*" in pattern:
        pattern_safe = pattern.replace("?", "[?]")
        return fnmatch.fnmatchcase(target, pattern_safe)
    return target == pattern or target == pattern.rstrip("/") or target.rstrip("/") == pattern


def _specificity(rule):
    v = rule["value"]
    return len(v) - v.count("*")


def is_in_scope(asset, scopes, default_in_out="in"):
    if not asset:
        return default_in_out != "out"
    rules = [r for r in (_normalize_rule(r) for r in (scopes or [])) if r]
    if not rules:
        return default_in_out != "out"

    host = _extract_host(asset)
    is_url = _is_url(asset)
    asset_lower = asset.strip().lower()

    matched = []
    for r in rules:
        if r["type"] == "domain":
            if host and _domain_matches(r["value"], host):
                matched.append(r)
        else:
            if is_url and _url_matches(r["value"], asset_lower):
                matched.append(r)

    if not matched:
        return default_in_out != "out"

    matched.sort(key=lambda r: (_specificity(r), 0 if r["in_out"] == "out" else 1), reverse=True)
    return matched[0]["in_out"] == "in"


def filter_in_scope(assets, scopes, default_in_out="in"):
    return [a for a in assets if is_in_scope(a, scopes, default_in_out)]
