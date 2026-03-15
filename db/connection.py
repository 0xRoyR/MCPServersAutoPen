"""
MySQL connection pool for the MCP server.

Reads connection details from environment variables:
    DB_HOST     (default: localhost)
    DB_PORT     (default: 3306)
    DB_USER     (default: autopen)
    DB_PASSWORD (default: autopen_secret)
    DB_NAME     (default: autopen)

Install dependency:
    pip install pymysql
"""
import os
import threading
from typing import Optional

import pymysql
import pymysql.cursors

# Connection configuration from environment
_DB_CONFIG = {
    "host":     os.environ.get("DB_HOST", "localhost"),
    "port":     int(os.environ.get("DB_PORT", "3306")),
    "user":     os.environ.get("DB_USER", "autopen"),
    "password": os.environ.get("DB_PASSWORD", "autopen_secret"),
    "database": os.environ.get("DB_NAME", "autopen"),
    "charset":  "utf8mb4",
    "cursorclass": pymysql.cursors.DictCursor,
    "autocommit": True,
    "connect_timeout": 10,
}

_local = threading.local()
_db_enabled: Optional[bool] = None
_lock = threading.Lock()


def _check_db_enabled() -> bool:
    """Check once whether the DB is reachable. Cache the result."""
    global _db_enabled
    if _db_enabled is not None:
        return _db_enabled
    with _lock:
        if _db_enabled is not None:
            return _db_enabled
        try:
            conn = pymysql.connect(**_DB_CONFIG)
            conn.close()
            _db_enabled = True
            print("[MCP DB] MySQL connection verified — direct DB writes enabled", flush=True)
        except Exception as exc:
            _db_enabled = False
            print(f"[MCP DB] MySQL not reachable ({exc}) — DB writes disabled, tools return raw output only", flush=True)
    return _db_enabled


def get_connection() -> Optional[pymysql.connections.Connection]:
    """
    Return a thread-local MySQL connection, reconnecting if needed.
    Returns None if DB is not configured or unreachable.
    """
    if not _check_db_enabled():
        return None

    conn = getattr(_local, "conn", None)
    if conn is None:
        try:
            conn = pymysql.connect(**_DB_CONFIG)
            _local.conn = conn
        except Exception as exc:
            print(f"[MCP DB] Connection error: {exc}", flush=True)
            return None

    # Ping to detect stale connections
    try:
        conn.ping(reconnect=True)
    except Exception:
        try:
            conn = pymysql.connect(**_DB_CONFIG)
            _local.conn = conn
        except Exception as exc:
            print(f"[MCP DB] Reconnect failed: {exc}", flush=True)
            return None

    return conn
