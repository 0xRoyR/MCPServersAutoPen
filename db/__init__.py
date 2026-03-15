"""
MCP Server Database Module

Provides direct MySQL access for MCP tools to write reconnaissance results
without going through the TypeScript backend API. This is the primary write
path for all tool outputs.

Usage:
    from db.repositories import get_repo
    repo = get_repo()
    repo.upsert_subdomain(target_uuid, scan_uuid, domain, subdomain, source)
"""
from db.repositories import ReconRepository, get_repo

__all__ = ["ReconRepository", "get_repo"]
