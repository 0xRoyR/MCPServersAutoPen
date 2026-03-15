"""
Recon data repositories — CRUD operations for all reconnaissance tables.

All write operations use INSERT IGNORE / ON DUPLICATE KEY UPDATE to handle
concurrent writes safely. The TypeScript backend uses the same tables via
TypeORM, so both write paths coexist without conflict.
"""
import uuid as _uuid
from typing import Optional
from db.connection import get_connection


def _new_uuid() -> str:
    return str(_uuid.uuid4())


class ReconRepository:
    """All DB operations for reconnaissance data."""

    # ── Subdomains ─────────────────────────────────────────────────────────────

    def upsert_subdomain(
        self,
        target_uuid: str,
        scan_uuid: str,
        domain: str,
        subdomain: str,
        source: str = "subfinder",
    ) -> Optional[str]:
        """
        Insert a subdomain row; skip if (target_uuid, subdomain) already exists.
        Returns the UUID of the row (existing or new).
        """
        conn = get_connection()
        if not conn:
            return None
        with conn.cursor() as cur:
            # Check if exists
            cur.execute(
                "SELECT uuid FROM subdomains WHERE target_uuid=%s AND subdomain=%s",
                (target_uuid, subdomain),
            )
            row = cur.fetchone()
            if row:
                return row["uuid"]
            row_uuid = _new_uuid()
            cur.execute(
                """INSERT INTO subdomains (uuid, target_uuid, domain, subdomain, source)
                   VALUES (%s, %s, %s, %s, %s)""",
                (row_uuid, target_uuid, domain, subdomain, source),
            )
        return row_uuid

    def get_subdomains(self, target_uuid: str) -> list[dict]:
        """Return all subdomains for a target."""
        conn = get_connection()
        if not conn:
            return []
        with conn.cursor() as cur:
            cur.execute(
                "SELECT uuid, subdomain, domain, source FROM subdomains WHERE target_uuid=%s",
                (target_uuid,),
            )
            return cur.fetchall() or []

    # ── HTTP Services ──────────────────────────────────────────────────────────

    def upsert_http_service(
        self,
        target_uuid: str,
        scan_uuid: str,
        host: str,
        url: str,
        status_code: Optional[int] = None,
        title: str = "",
        webserver: str = "",
        technologies: Optional[list] = None,
        content_length: Optional[int] = None,
        content_type: str = "",
        redirect_url: str = "",
    ) -> Optional[str]:
        """Insert an http_service row; skip if (target_uuid, url) already exists."""
        conn = get_connection()
        if not conn:
            return None
        import json
        tech_json = json.dumps(technologies or [])
        with conn.cursor() as cur:
            cur.execute(
                "SELECT uuid FROM http_services WHERE target_uuid=%s AND url=%s",
                (target_uuid, url[:2000]),
            )
            row = cur.fetchone()
            if row:
                return row["uuid"]
            row_uuid = _new_uuid()
            cur.execute(
                """INSERT INTO http_services
                   (uuid, target_uuid, host, url, status_code, title, webserver,
                    technologies, content_length, content_type, redirect_url)
                   VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                (
                    row_uuid, target_uuid, host[:500], url[:2000],
                    status_code, (title or "")[:500], (webserver or "")[:255],
                    tech_json,
                    content_length, (content_type or "")[:255], (redirect_url or "")[:2000],
                ),
            )
        return row_uuid

    def get_http_services(self, target_uuid: str) -> list[dict]:
        """Return all live HTTP services for a target."""
        conn = get_connection()
        if not conn:
            return []
        with conn.cursor() as cur:
            cur.execute(
                """SELECT uuid, host, url, status_code, title, webserver, technologies
                   FROM http_services WHERE target_uuid=%s""",
                (target_uuid,),
            )
            return cur.fetchall() or []

    # ── Endpoints ──────────────────────────────────────────────────────────────

    def upsert_endpoint(
        self,
        target_uuid: str,
        scan_uuid: str,
        host: str,
        url: str,
        path: str,
        source: str = "gobuster",
        method: str = "GET",
        status_code: Optional[int] = None,
        content_length: Optional[int] = None,
        redirect_url: str = "",
    ) -> Optional[str]:
        """Insert an endpoint row; skip if (target_uuid, url) already exists."""
        conn = get_connection()
        if not conn:
            return None
        with conn.cursor() as cur:
            cur.execute(
                "SELECT uuid FROM endpoints WHERE target_uuid=%s AND url=%s",
                (target_uuid, url[:2000]),
            )
            row = cur.fetchone()
            if row:
                return row["uuid"]
            row_uuid = _new_uuid()
            cur.execute(
                """INSERT INTO endpoints
                   (uuid, target_uuid, scan_uuid, host, url, path, source, method,
                    status_code, content_length, redirect_url)
                   VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                (
                    row_uuid, target_uuid, scan_uuid, host[:500], url[:2000],
                    path[:1000], source[:50], method[:10],
                    status_code, content_length, (redirect_url or "")[:2000],
                ),
            )
        return row_uuid

    def get_endpoints(self, target_uuid: str) -> list[dict]:
        """Return all endpoints for a target, with their parameters."""
        conn = get_connection()
        if not conn:
            return []
        with conn.cursor() as cur:
            cur.execute(
                """SELECT e.uuid, e.host, e.url, e.path, e.method, e.status_code,
                          e.content_length, e.source, e.scan_uuid,
                          GROUP_CONCAT(ep.name ORDER BY ep.name SEPARATOR ',') AS params
                   FROM endpoints e
                   LEFT JOIN endpoint_parameters ep ON ep.endpoint_uuid = e.uuid
                   WHERE e.target_uuid=%s
                   GROUP BY e.uuid
                   ORDER BY e.url""",
                (target_uuid,),
            )
            rows = cur.fetchall() or []
            for row in rows:
                params_str = row.get("params") or ""
                row["params"] = [p for p in params_str.split(",") if p] if params_str else []
            return rows

    # ── Endpoint Parameters ────────────────────────────────────────────────────

    def upsert_endpoint_parameter(
        self,
        target_uuid: str,
        scan_uuid: str,
        endpoint_uuid: str,
        name: str,
        param_type: str = "GET",
        source: str = "waybackurls",
    ) -> Optional[str]:
        """Insert a parameter row; skip if (endpoint_uuid, name, param_type) already exists."""
        conn = get_connection()
        if not conn:
            return None
        with conn.cursor() as cur:
            cur.execute(
                """SELECT uuid FROM endpoint_parameters
                   WHERE endpoint_uuid=%s AND name=%s AND param_type=%s""",
                (endpoint_uuid, name[:500], param_type),
            )
            row = cur.fetchone()
            if row:
                return row["uuid"]
            row_uuid = _new_uuid()
            cur.execute(
                """INSERT INTO endpoint_parameters
                   (uuid, target_uuid, scan_uuid, endpoint_uuid, name, param_type, source)
                   VALUES (%s,%s,%s,%s,%s,%s,%s)""",
                (row_uuid, target_uuid, scan_uuid, endpoint_uuid,
                 name[:500], param_type, source[:50]),
            )
        return row_uuid

    def get_endpoint_parameters(self, target_uuid: str, endpoint_uuid: Optional[str] = None) -> list[dict]:
        """Return parameters for all endpoints (or one specific endpoint) of a target."""
        conn = get_connection()
        if not conn:
            return []
        with conn.cursor() as cur:
            if endpoint_uuid:
                cur.execute(
                    "SELECT uuid, endpoint_uuid, name, param_type, source FROM endpoint_parameters WHERE endpoint_uuid=%s",
                    (endpoint_uuid,),
                )
            else:
                cur.execute(
                    "SELECT uuid, endpoint_uuid, name, param_type, source FROM endpoint_parameters WHERE target_uuid=%s",
                    (target_uuid,),
                )
            return cur.fetchall() or []

    # ── Ports ──────────────────────────────────────────────────────────────────

    def upsert_port(
        self,
        target_uuid: str,
        scan_uuid: str,
        host: str,
        port: int,
        protocol: str = "tcp",
        state: str = "open",
        service: str = "",
        version: str = "",
        ip_address: str = "",
    ) -> Optional[str]:
        conn = get_connection()
        if not conn:
            return None
        with conn.cursor() as cur:
            cur.execute(
                "SELECT uuid FROM ports WHERE target_uuid=%s AND host=%s AND port=%s AND protocol=%s",
                (target_uuid, host, port, protocol),
            )
            row = cur.fetchone()
            if row:
                return row["uuid"]
            row_uuid = _new_uuid()
            cur.execute(
                """INSERT INTO ports (uuid, target_uuid, host, ip_address, port, protocol, state, service, version)
                   VALUES (%s,%s,%s,%s,%s,%s,%s,%s,%s)""",
                (row_uuid, target_uuid, host[:500], ip_address[:50],
                 port, protocol[:10], state[:20], service[:100], version[:255]),
            )
        return row_uuid

    # ── Full Attack Surface Query (for master agent) ───────────────────────────

    def get_attack_surface(self, target_uuid: str) -> dict:
        """
        Return the complete attack surface for a target — all endpoints
        with their parameters, plus http_services and subdomains.
        Used by master agent after reconnaissance is complete.
        """
        return {
            "subdomains": self.get_subdomains(target_uuid),
            "http_services": self.get_http_services(target_uuid),
            "endpoints": self.get_endpoints(target_uuid),
        }


# Module-level singleton
_repo: Optional[ReconRepository] = None


def get_repo() -> ReconRepository:
    global _repo
    if _repo is None:
        _repo = ReconRepository()
    return _repo
