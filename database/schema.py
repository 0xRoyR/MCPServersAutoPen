"""
Database schema definitions for all security tools.

This module defines the SQLite table schemas and their relationships.
Each tool has its own table with a UUID primary key and a 'scanned_at' timestamp.

Tool Flow & Relationships:
1. Target -> Customer engagement target (domain or URL)
2. WHOIS -> Domain registration info (starting point for recon)
3. Subfinder -> Discovers subdomains (uses domain from WHOIS or user input)
4. Nmap -> Port scanning (runs on domains/subdomains)
5. Httpx -> HTTP probing (runs on domains/subdomains with open ports)
6. Gobuster -> Directory brute-force (runs on live HTTP services)
7. Findings -> Security findings discovered during assessment
"""

SCHEMA = {
    # Targets - customer engagement targets
    "targets": {
        "columns": {
            "uuid": "TEXT PRIMARY KEY",
            "name": "TEXT NOT NULL",  # Target name (e.g., example.com)
            "type": "TEXT NOT NULL",  # 'domain' or 'url'
            "created_at": "TIMESTAMP DEFAULT CURRENT_TIMESTAMP",
        },
        "indexes": ["name", "type"],
        "unique_constraints": ["name"],
        "description": "Stores customer engagement targets for penetration testing",
    },

    # WHOIS results - domain registration information
    "whois_results": {
        "columns": {
            "uuid": "TEXT PRIMARY KEY",
            "target_uuid": "TEXT NOT NULL",  # FK to targets table
            "domain": "TEXT NOT NULL",
            "registrar": "TEXT",
            "creation_date": "TEXT",
            "expiration_date": "TEXT",
            "name_servers": "TEXT",  # JSON array stored as text
            "registrant_name": "TEXT",
            "registrant_org": "TEXT",
            "registrant_country": "TEXT",
            "raw_output": "TEXT",
            "scanned_at": "TIMESTAMP DEFAULT CURRENT_TIMESTAMP",
        },
        "indexes": ["target_uuid", "domain"],
        "foreign_keys": [("target_uuid", "targets", "uuid")],
        "description": "Stores WHOIS lookup results for domains",
    },

    # Subfinder results - discovered subdomains
    "subdomains": {
        "columns": {
            "uuid": "TEXT PRIMARY KEY",
            "target_uuid": "TEXT NOT NULL",  # FK to targets table
            "domain": "TEXT NOT NULL",  # Parent domain
            "subdomain": "TEXT NOT NULL",  # Full subdomain (e.g., api.example.com)
            "source": "TEXT",  # Which source discovered it
            "scanned_at": "TIMESTAMP DEFAULT CURRENT_TIMESTAMP",
        },
        "indexes": ["target_uuid", "domain", "subdomain"],
        "unique_constraints": ["target_uuid, subdomain"],
        "foreign_keys": [("target_uuid", "targets", "uuid")],
        "description": "Stores discovered subdomains from subfinder",
    },

    # Nmap results - port scan information
    "ports": {
        "columns": {
            "uuid": "TEXT PRIMARY KEY",
            "target_uuid": "TEXT NOT NULL",  # FK to targets table
            "host": "TEXT NOT NULL",  # IP or hostname scanned
            "ip_address": "TEXT",
            "port": "INTEGER NOT NULL",
            "protocol": "TEXT DEFAULT 'tcp'",
            "state": "TEXT",  # open, closed, filtered
            "service": "TEXT",  # http, ssh, etc.
            "version": "TEXT",  # Service version info
            "scanned_at": "TIMESTAMP DEFAULT CURRENT_TIMESTAMP",
        },
        "indexes": ["target_uuid", "host", "port", "ip_address"],
        "unique_constraints": ["target_uuid, host, port, protocol"],
        "foreign_keys": [("target_uuid", "targets", "uuid")],
        "description": "Stores port scan results from nmap",
    },

    # Httpx results - HTTP probing information
    "http_services": {
        "columns": {
            "uuid": "TEXT PRIMARY KEY",
            "target_uuid": "TEXT NOT NULL",  # FK to targets table
            "host": "TEXT NOT NULL",  # Original target
            "url": "TEXT NOT NULL",  # Full URL probed
            "status_code": "INTEGER",
            "title": "TEXT",
            "webserver": "TEXT",
            "technologies": "TEXT",  # JSON array stored as text
            "content_length": "INTEGER",
            "content_type": "TEXT",
            "redirect_url": "TEXT",
            "scanned_at": "TIMESTAMP DEFAULT CURRENT_TIMESTAMP",
        },
        "indexes": ["target_uuid", "host", "url", "status_code"],
        "unique_constraints": ["target_uuid, url"],
        "foreign_keys": [("target_uuid", "targets", "uuid")],
        "description": "Stores HTTP probe results from httpx",
    },

    # Gobuster results - directory/file discovery
    "directories": {
        "columns": {
            "uuid": "TEXT PRIMARY KEY",
            "target_uuid": "TEXT NOT NULL",  # FK to targets table
            "host": "TEXT NOT NULL",  # Target host
            "url": "TEXT NOT NULL",  # Full URL of discovered path
            "path": "TEXT NOT NULL",  # Just the path portion
            "status_code": "INTEGER",
            "content_length": "INTEGER",
            "redirect_url": "TEXT",
            "scanned_at": "TIMESTAMP DEFAULT CURRENT_TIMESTAMP",
        },
        "indexes": ["target_uuid", "host", "path", "status_code"],
        "unique_constraints": ["target_uuid, url"],
        "foreign_keys": [("target_uuid", "targets", "uuid")],
        "description": "Stores directory/file discovery results from gobuster",
    },

    # JWT results - JWT decoding and attacking results
    "jwt_results": {
        "columns": {
            "uuid": "TEXT PRIMARY KEY",
            "target_uuid": "TEXT NOT NULL",  # FK to targets table
            "host": "TEXT NOT NULL",  # Original target/app where token was found
            "token": "TEXT NOT NULL",  # The original JWT string
            "algorithm": "TEXT",  # Token algorithm (e.g., HS256, RS256, none)
            "finding_type": "TEXT",  # info, cracked_secret, exploit_success
            "cracked_secret": "TEXT",  # Discovered secret via brute-force
            "tampered_token": "TEXT",  # Generated forged token via exploit
            "scanned_at": "TIMESTAMP DEFAULT CURRENT_TIMESTAMP",
        },
        "indexes": ["target_uuid", "host", "finding_type"],
        "foreign_keys": [("target_uuid", "targets", "uuid")],
        "description": "Stores JWT analysis, cracking, and exploitation results",
    },

    # Findings - security findings from the assessment
    "findings": {
        "columns": {
            "uuid": "TEXT PRIMARY KEY",
            "target_uuid": "TEXT NOT NULL",  # FK to targets table
            "tool": "TEXT NOT NULL",  # Tool that found the finding
            "severity": "TEXT",  # critical, high, medium, low, info
            "title": "TEXT NOT NULL",  # Short title of the finding
            "description": "TEXT",  # Detailed description
            "affected_asset": "TEXT",  # What asset is affected
            "evidence": "TEXT",  # Evidence/proof of the finding
            "recommendation": "TEXT",  # How to fix
            "found_at": "TIMESTAMP DEFAULT CURRENT_TIMESTAMP",
        },
        "indexes": ["target_uuid", "tool", "severity"],
        "foreign_keys": [("target_uuid", "targets", "uuid")],
        "description": "Stores security findings discovered during assessment",
    },
}


def get_create_table_sql(table_name: str) -> str:
    """Generate CREATE TABLE SQL for a given table."""
    if table_name not in SCHEMA:
        raise ValueError(f"Unknown table: {table_name}")

    table = SCHEMA[table_name]
    columns = table["columns"]

    col_defs = [f"    {name} {definition}" for name, definition in columns.items()]

    # Add unique constraints if any
    if "unique_constraints" in table:
        for constraint in table["unique_constraints"]:
            col_defs.append(f"    UNIQUE({constraint})")

    # Add foreign key constraints if any
    if "foreign_keys" in table:
        for fk in table["foreign_keys"]:
            col_name, ref_table, ref_col = fk
            col_defs.append(f"    FOREIGN KEY ({col_name}) REFERENCES {ref_table}({ref_col})")

    sql = f"CREATE TABLE IF NOT EXISTS {table_name} (\n"
    sql += ",\n".join(col_defs)
    sql += "\n);"

    return sql


def get_create_index_sql(table_name: str) -> list[str]:
    """Generate CREATE INDEX SQL statements for a given table."""
    if table_name not in SCHEMA:
        raise ValueError(f"Unknown table: {table_name}")

    table = SCHEMA[table_name]
    indexes = table.get("indexes", [])

    sql_statements = []
    for col in indexes:
        index_name = f"idx_{table_name}_{col}"
        sql_statements.append(
            f"CREATE INDEX IF NOT EXISTS {index_name} ON {table_name}({col});"
        )

    return sql_statements


def get_all_create_statements() -> list[str]:
    """Get all CREATE TABLE and CREATE INDEX statements."""
    statements = []

    # Create targets table first (referenced by others)
    statements.append(get_create_table_sql("targets"))
    statements.extend(get_create_index_sql("targets"))

    # Then create other tables
    for table_name in SCHEMA:
        if table_name != "targets":
            statements.append(get_create_table_sql(table_name))
            statements.extend(get_create_index_sql(table_name))

    return statements
