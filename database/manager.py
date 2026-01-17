"""
Database manager for the security tools MCP server.

Handles database initialization, connections, and common operations.
"""

import sqlite3
import uuid as uuid_lib
from pathlib import Path
from contextlib import contextmanager
from datetime import datetime

from database.schema import get_all_create_statements, SCHEMA


# Default database path
DEFAULT_DB_PATH = Path(__file__).parent.parent / "pentest_results.db"


class DatabaseManager:
    """Manages SQLite database connections and operations."""

    def __init__(self, db_path: str | Path = None):
        self.db_path = Path(db_path) if db_path else DEFAULT_DB_PATH
        self._initialized = False

    def initialize(self, force_recreate: bool = False):
        """Initialize the database with all required tables."""
        if self._initialized and not force_recreate:
            return

        with self.get_connection() as conn:
            cursor = conn.cursor()
            # Enable foreign keys
            cursor.execute("PRAGMA foreign_keys = ON")

            # If force_recreate, drop all tables first
            if force_recreate:
                # Get list of tables (in reverse order due to foreign keys)
                tables_to_drop = ['findings', 'directories', 'http_services', 'ports', 'subdomains', 'whois_results', 'targets']
                for table in tables_to_drop:
                    cursor.execute(f"DROP TABLE IF EXISTS {table}")

            for statement in get_all_create_statements():
                try:
                    cursor.execute(statement)
                except Exception as e:
                    print(f"Error executing: {statement[:100]}...")
                    raise

            conn.commit()

        self._initialized = True

    @contextmanager
    def get_connection(self):
        """Get a database connection as a context manager."""
        conn = sqlite3.connect(str(self.db_path))
        conn.row_factory = sqlite3.Row
        # Enable foreign keys for this connection
        conn.execute("PRAGMA foreign_keys = ON")
        try:
            yield conn
        finally:
            conn.close()

    def insert(self, table: str, data: dict) -> str:
        """Insert a row into a table. Returns the UUID."""
        if table not in SCHEMA:
            raise ValueError(f"Unknown table: {table}")

        columns = list(data.keys())
        placeholders = ["?" for _ in columns]

        sql = f"INSERT OR REPLACE INTO {table} ({', '.join(columns)}) VALUES ({', '.join(placeholders)})"

        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(sql, list(data.values()))
            conn.commit()

        return data.get("uuid", "")

    def insert_many(self, table: str, data_list: list[dict]) -> int:
        """Insert multiple rows into a table. Returns count of inserted rows."""
        if not data_list:
            return 0

        if table not in SCHEMA:
            raise ValueError(f"Unknown table: {table}")

        columns = list(data_list[0].keys())
        placeholders = ["?" for _ in columns]

        sql = f"INSERT OR REPLACE INTO {table} ({', '.join(columns)}) VALUES ({', '.join(placeholders)})"

        with self.get_connection() as conn:
            cursor = conn.cursor()
            for data in data_list:
                cursor.execute(sql, [data.get(col) for col in columns])
            conn.commit()

        return len(data_list)

    def query(self, table: str, where: dict = None, limit: int = None) -> list[dict]:
        """Query rows from a table."""
        if table not in SCHEMA:
            raise ValueError(f"Unknown table: {table}")

        sql = f"SELECT * FROM {table}"

        params = []
        if where:
            conditions = [f"{col} = ?" for col in where.keys()]
            sql += " WHERE " + " AND ".join(conditions)
            params = list(where.values())

        if limit:
            sql += f" LIMIT {limit}"

        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(sql, params)
            rows = cursor.fetchall()

        return [dict(row) for row in rows]

    def execute_sql(self, sql: str, params: list = None) -> list[dict]:
        """Execute raw SQL and return results."""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute(sql, params or [])
            if cursor.description:
                rows = cursor.fetchall()
                return [dict(row) for row in rows]
            conn.commit()
            return []

    # Target management methods
    def create_target(self, name: str, target_type: str) -> str:
        """Create a new target. Returns the target UUID."""
        target_uuid = str(uuid_lib.uuid4())
        self.insert("targets", {
            "uuid": target_uuid,
            "name": name.lower(),
            "type": target_type,
            "created_at": datetime.utcnow().isoformat(),
        })
        return target_uuid

    def get_target(self, name: str) -> dict | None:
        """Get a target by name."""
        results = self.query("targets", {"name": name.lower()})
        return results[0] if results else None

    def get_or_create_target(self, name: str, target_type: str = "domain") -> str:
        """Get existing target or create new one. Returns target UUID."""
        target = self.get_target(name)
        if target:
            return target["uuid"]
        return self.create_target(name, target_type)

    def get_all_targets(self) -> list[dict]:
        """Get all targets."""
        return self.query("targets")

    # Findings methods
    def add_finding(self, target_uuid: str, tool: str, title: str,
                    severity: str = "info", description: str = None,
                    affected_asset: str = None, evidence: str = None,
                    recommendation: str = None) -> str:
        """Add a security finding. Returns the finding UUID."""
        finding_uuid = str(uuid_lib.uuid4())
        self.insert("findings", {
            "uuid": finding_uuid,
            "target_uuid": target_uuid,
            "tool": tool,
            "severity": severity,
            "title": title,
            "description": description,
            "affected_asset": affected_asset,
            "evidence": evidence,
            "recommendation": recommendation,
            "found_at": datetime.utcnow().isoformat(),
        })
        return finding_uuid

    def get_findings_for_target(self, target_uuid: str) -> list[dict]:
        """Get all findings for a target."""
        return self.query("findings", {"target_uuid": target_uuid})

    def get_findings_by_severity(self, target_uuid: str = None) -> dict:
        """Get findings grouped by severity."""
        if target_uuid:
            findings = self.query("findings", {"target_uuid": target_uuid})
        else:
            findings = self.query("findings")

        grouped = {
            "critical": [],
            "high": [],
            "medium": [],
            "low": [],
            "info": [],
        }

        for finding in findings:
            severity = finding.get("severity", "info").lower()
            if severity in grouped:
                grouped[severity].append(finding)
            else:
                grouped["info"].append(finding)

        return grouped

    # Helper methods for tool results
    def get_subdomains_for_target(self, target_uuid: str) -> list[dict]:
        """Get all discovered subdomains for a target."""
        return self.query("subdomains", {"target_uuid": target_uuid})

    def get_ports_for_target(self, target_uuid: str) -> list[dict]:
        """Get all port scan results for a target."""
        return self.query("ports", {"target_uuid": target_uuid})

    def get_http_services_for_target(self, target_uuid: str) -> list[dict]:
        """Get all HTTP services for a target."""
        return self.query("http_services", {"target_uuid": target_uuid})

    def get_directories_for_target(self, target_uuid: str) -> list[dict]:
        """Get all discovered directories for a target."""
        return self.query("directories", {"target_uuid": target_uuid})

    def get_whois_for_target(self, target_uuid: str) -> dict | None:
        """Get WHOIS result for a target."""
        results = self.query("whois_results", {"target_uuid": target_uuid})
        return results[0] if results else None

    # Legacy methods (without target_uuid filter)
    def get_subdomains_for_domain(self, domain: str) -> list[str]:
        """Get all discovered subdomains for a domain."""
        results = self.query("subdomains", {"domain": domain})
        return [r["subdomain"] for r in results]

    def get_open_ports_for_host(self, host: str) -> list[dict]:
        """Get all open ports for a host."""
        results = self.query("ports", {"host": host})
        return [r for r in results if r.get("state") == "open"]

    def get_live_http_services(self, host: str = None) -> list[dict]:
        """Get all live HTTP services, optionally filtered by host."""
        if host:
            return self.query("http_services", {"host": host})
        return self.query("http_services")

    def get_statistics(self) -> dict:
        """Get statistics about the database contents."""
        stats = {}
        with self.get_connection() as conn:
            cursor = conn.cursor()
            for table in SCHEMA:
                try:
                    cursor.execute(f"SELECT COUNT(*) FROM {table}")
                    stats[table] = cursor.fetchone()[0]
                except sqlite3.OperationalError:
                    stats[table] = 0
        return stats

    def get_full_report_data(self, target_uuid: str) -> dict:
        """Get all data for a target for report generation."""
        target = self.query("targets", {"uuid": target_uuid})
        if not target:
            return {}

        return {
            "target": target[0],
            "whois": self.get_whois_for_target(target_uuid),
            "subdomains": self.get_subdomains_for_target(target_uuid),
            "ports": self.get_ports_for_target(target_uuid),
            "http_services": self.get_http_services_for_target(target_uuid),
            "directories": self.get_directories_for_target(target_uuid),
            "findings": self.get_findings_by_severity(target_uuid),
        }


# Global database manager instance
db_manager = DatabaseManager()


def get_db() -> DatabaseManager:
    """Get the global database manager instance."""
    if not db_manager._initialized:
        db_manager.initialize()
    return db_manager
