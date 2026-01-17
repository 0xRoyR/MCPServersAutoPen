"""
Populate the database with simulation data for testing and demonstration.

Run this script to create sample targets and findings:
    python populate_simulation_data.py
"""

import uuid
from datetime import datetime, timedelta
import random

from database import get_db


def create_simulation_data():
    """Create simulation data for demonstration purposes."""

    db = get_db()

    print("Creating simulation data...")

    # Create a sample target
    target_uuid = str(uuid.uuid4())
    db.insert("targets", {
        "uuid": target_uuid,
        "name": "example-corp.com",
        "type": "domain",
        "created_at": datetime.utcnow().isoformat(),
    })
    print(f"Created target: example-corp.com (UUID: {target_uuid})")

    # Simulation WHOIS data
    db.insert("whois_results", {
        "uuid": str(uuid.uuid4()),
        "target_uuid": target_uuid,
        "domain": "example-corp.com",
        "registrar": "GoDaddy.com, LLC",
        "creation_date": "2015-03-15",
        "expiration_date": "2025-03-15",
        "name_servers": '["ns1.example-corp.com", "ns2.example-corp.com"]',
        "registrant_name": "Domain Admin",
        "registrant_org": "Example Corporation",
        "registrant_country": "US",
        "raw_output": "Simulated WHOIS output...",
        "scanned_at": datetime.utcnow().isoformat(),
    })

    # Simulation subdomains
    subdomains = [
        "www.example-corp.com",
        "api.example-corp.com",
        "admin.example-corp.com",
        "mail.example-corp.com",
        "dev.example-corp.com",
        "staging.example-corp.com",
        "old.example-corp.com",
        "test.example-corp.com",
    ]

    for subdomain in subdomains:
        db.insert("subdomains", {
            "uuid": str(uuid.uuid4()),
            "target_uuid": target_uuid,
            "domain": "example-corp.com",
            "subdomain": subdomain,
            "source": "subfinder",
            "scanned_at": datetime.utcnow().isoformat(),
        })

    print(f"Created {len(subdomains)} subdomains")

    # Simulation ports
    ports_data = [
        ("www.example-corp.com", "93.184.216.34", 80, "tcp", "open", "http", "nginx 1.14.0"),
        ("www.example-corp.com", "93.184.216.34", 443, "tcp", "open", "https", "nginx 1.14.0"),
        ("api.example-corp.com", "93.184.216.35", 443, "tcp", "open", "https", "nginx 1.18.0"),
        ("api.example-corp.com", "93.184.216.35", 8080, "tcp", "open", "http-proxy", None),
        ("admin.example-corp.com", "93.184.216.36", 22, "tcp", "open", "ssh", "OpenSSH 7.4"),
        ("admin.example-corp.com", "93.184.216.36", 443, "tcp", "open", "https", "Apache 2.4.6"),
        ("mail.example-corp.com", "93.184.216.37", 25, "tcp", "open", "smtp", "Postfix"),
        ("mail.example-corp.com", "93.184.216.37", 587, "tcp", "open", "submission", "Postfix"),
        ("dev.example-corp.com", "93.184.216.38", 22, "tcp", "open", "ssh", "OpenSSH 8.0"),
        ("dev.example-corp.com", "93.184.216.38", 3306, "tcp", "open", "mysql", "MySQL 5.7.32"),
        ("dev.example-corp.com", "93.184.216.38", 6379, "tcp", "open", "redis", "Redis 5.0.7"),
    ]

    for host, ip, port, proto, state, service, version in ports_data:
        db.insert("ports", {
            "uuid": str(uuid.uuid4()),
            "target_uuid": target_uuid,
            "host": host,
            "ip_address": ip,
            "port": port,
            "protocol": proto,
            "state": state,
            "service": service,
            "version": version,
            "scanned_at": datetime.utcnow().isoformat(),
        })

    print(f"Created {len(ports_data)} port entries")

    # Simulation HTTP services
    http_services_data = [
        ("www.example-corp.com", "https://www.example-corp.com", 200, "Example Corp - Home", "nginx", '["nginx", "PHP"]'),
        ("api.example-corp.com", "https://api.example-corp.com", 200, "API Documentation", "nginx", '["nginx", "Node.js", "Express"]'),
        ("admin.example-corp.com", "https://admin.example-corp.com", 200, "Admin Panel", "Apache", '["Apache", "PHP", "WordPress"]'),
        ("dev.example-corp.com", "http://dev.example-corp.com:8080", 200, "Development Server", "nginx", '["nginx", "Python", "Django"]'),
    ]

    for host, url, status, title, webserver, tech in http_services_data:
        db.insert("http_services", {
            "uuid": str(uuid.uuid4()),
            "target_uuid": target_uuid,
            "host": host,
            "url": url,
            "status_code": status,
            "title": title,
            "webserver": webserver,
            "technologies": tech,
            "content_length": random.randint(5000, 50000),
            "content_type": "text/html",
            "redirect_url": None,
            "scanned_at": datetime.utcnow().isoformat(),
        })

    print(f"Created {len(http_services_data)} HTTP service entries")

    # Simulation directories
    directories_data = [
        ("admin.example-corp.com", "https://admin.example-corp.com/login", "/login", 200),
        ("admin.example-corp.com", "https://admin.example-corp.com/wp-admin", "/wp-admin", 302),
        ("admin.example-corp.com", "https://admin.example-corp.com/wp-login.php", "/wp-login.php", 200),
        ("admin.example-corp.com", "https://admin.example-corp.com/backup", "/backup", 403),
        ("api.example-corp.com", "https://api.example-corp.com/.git", "/.git", 200),
        ("api.example-corp.com", "https://api.example-corp.com/.env", "/.env", 200),
        ("api.example-corp.com", "https://api.example-corp.com/swagger", "/swagger", 200),
        ("api.example-corp.com", "https://api.example-corp.com/graphql", "/graphql", 200),
        ("dev.example-corp.com", "http://dev.example-corp.com:8080/debug", "/debug", 200),
        ("dev.example-corp.com", "http://dev.example-corp.com:8080/phpinfo.php", "/phpinfo.php", 200),
    ]

    for host, url, path, status in directories_data:
        db.insert("directories", {
            "uuid": str(uuid.uuid4()),
            "target_uuid": target_uuid,
            "host": host,
            "url": url,
            "path": path,
            "status_code": status,
            "content_length": random.randint(100, 10000),
            "redirect_url": None,
            "scanned_at": datetime.utcnow().isoformat(),
        })

    print(f"Created {len(directories_data)} directory entries")

    # Simulation findings
    findings_data = [
        # Critical findings
        {
            "severity": "critical",
            "tool": "gobuster",
            "title": "Exposed .git Directory",
            "description": "The .git directory is publicly accessible, potentially exposing source code, configuration files, and sensitive information including API keys and credentials.",
            "affected_asset": "https://api.example-corp.com/.git",
            "evidence": "HTTP 200 response with directory listing enabled. Git objects and refs are accessible.",
            "recommendation": "Immediately block access to .git directories using web server configuration. Review exposed repository for sensitive data leakage.",
        },
        {
            "severity": "critical",
            "tool": "gobuster",
            "title": "Exposed Environment Configuration File",
            "description": "The .env file containing environment variables is publicly accessible. This file typically contains database credentials, API keys, and other sensitive configuration.",
            "affected_asset": "https://api.example-corp.com/.env",
            "evidence": "HTTP 200 response returning environment variable contents including DB_PASSWORD and API_SECRET.",
            "recommendation": "Remove .env from public access immediately. Rotate all exposed credentials. Add .env to web server deny rules.",
        },
        # High findings
        {
            "severity": "high",
            "tool": "nmap",
            "title": "Exposed MySQL Database",
            "description": "MySQL database server is directly accessible from the internet on port 3306. This allows potential brute force attacks and exploitation of MySQL vulnerabilities.",
            "affected_asset": "dev.example-corp.com:3306",
            "evidence": "Nmap identified MySQL 5.7.32 responding on port 3306 from external scan.",
            "recommendation": "Restrict MySQL access to internal networks only using firewall rules. Use VPN or SSH tunneling for remote access.",
        },
        {
            "severity": "high",
            "tool": "nmap",
            "title": "Exposed Redis Instance Without Authentication",
            "description": "Redis server is accessible from the internet without authentication. This could allow unauthorized data access or server compromise via Redis commands.",
            "affected_asset": "dev.example-corp.com:6379",
            "evidence": "Nmap identified Redis 5.0.7 on port 6379. Connection test confirmed no authentication required.",
            "recommendation": "Enable Redis authentication with a strong password. Restrict access to internal networks. Consider using Redis ACLs.",
        },
        {
            "severity": "high",
            "tool": "httpx",
            "title": "Outdated Nginx Version with Known Vulnerabilities",
            "description": "The web server is running nginx 1.14.0 which has known security vulnerabilities including CVE-2019-20372 (HTTP request smuggling).",
            "affected_asset": "www.example-corp.com",
            "evidence": "Server header: nginx/1.14.0. Current stable version is 1.24.x.",
            "recommendation": "Update nginx to the latest stable version. Implement regular patching schedule.",
        },
        # Medium findings
        {
            "severity": "medium",
            "tool": "nmap",
            "title": "SSH Exposed on Administrative Subdomain",
            "description": "SSH service is accessible from the internet on the admin subdomain. While SSH is generally secure, exposure increases attack surface for brute force attempts.",
            "affected_asset": "admin.example-corp.com:22",
            "evidence": "OpenSSH 7.4 detected on port 22.",
            "recommendation": "Restrict SSH access to known IP addresses. Implement fail2ban. Consider using VPN for administrative access.",
        },
        {
            "severity": "medium",
            "tool": "gobuster",
            "title": "WordPress Admin Panel Exposed",
            "description": "WordPress admin login page is publicly accessible, making it a target for brute force attacks and exploitation of WordPress vulnerabilities.",
            "affected_asset": "https://admin.example-corp.com/wp-admin",
            "evidence": "HTTP 302 redirect to wp-login.php confirmed WordPress installation.",
            "recommendation": "Implement IP whitelisting for admin access. Enable two-factor authentication. Consider using a security plugin like Wordfence.",
        },
        {
            "severity": "medium",
            "tool": "gobuster",
            "title": "Debug Endpoint Exposed",
            "description": "A debug endpoint is accessible on the development server, potentially exposing sensitive application information and debug functionality.",
            "affected_asset": "http://dev.example-corp.com:8080/debug",
            "evidence": "HTTP 200 response with debug information including stack traces and configuration.",
            "recommendation": "Disable debug mode in production and staging environments. Restrict development server access to internal network.",
        },
        # Low findings
        {
            "severity": "low",
            "tool": "httpx",
            "title": "Server Version Disclosure",
            "description": "Web servers are disclosing version information in HTTP headers, which helps attackers identify potential vulnerabilities.",
            "affected_asset": "Multiple hosts",
            "evidence": "Server headers revealing: nginx/1.14.0, Apache/2.4.6",
            "recommendation": "Configure web servers to suppress version information in Server headers.",
        },
        {
            "severity": "low",
            "tool": "gobuster",
            "title": "Swagger API Documentation Exposed",
            "description": "API documentation is publicly accessible, providing detailed information about API endpoints that could aid attackers.",
            "affected_asset": "https://api.example-corp.com/swagger",
            "evidence": "Swagger UI accessible without authentication.",
            "recommendation": "Require authentication to access API documentation. Consider restricting to internal network.",
        },
        # Info findings
        {
            "severity": "info",
            "tool": "subfinder",
            "title": "Multiple Subdomains Discovered",
            "description": "Subdomain enumeration revealed 8 subdomains associated with the target domain.",
            "affected_asset": "example-corp.com",
            "evidence": "Subdomains found: www, api, admin, mail, dev, staging, old, test",
            "recommendation": "Review all subdomains to ensure they are intentionally exposed. Remove or restrict access to unused subdomains.",
        },
        {
            "severity": "info",
            "tool": "whois",
            "title": "Domain Registration Information",
            "description": "WHOIS lookup revealed domain registration details and nameserver configuration.",
            "affected_asset": "example-corp.com",
            "evidence": "Registrar: GoDaddy.com, LLC. Expiration: 2025-03-15",
            "recommendation": "Ensure domain registration is set to auto-renew. Consider domain privacy protection.",
        },
    ]

    for finding in findings_data:
        db.insert("findings", {
            "uuid": str(uuid.uuid4()),
            "target_uuid": target_uuid,
            "tool": finding["tool"],
            "severity": finding["severity"],
            "title": finding["title"],
            "description": finding["description"],
            "affected_asset": finding["affected_asset"],
            "evidence": finding["evidence"],
            "recommendation": finding["recommendation"],
            "found_at": (datetime.utcnow() - timedelta(hours=random.randint(1, 48))).isoformat(),
        })

    print(f"Created {len(findings_data)} findings")

    # Print summary
    print("\n" + "=" * 60)
    print("Simulation Data Summary")
    print("=" * 60)
    stats = db.get_statistics()
    for table, count in stats.items():
        print(f"  {table}: {count} rows")

    print(f"\nTarget UUID: {target_uuid}")
    print("Use this UUID for report generation.")

    return target_uuid


if __name__ == "__main__":
    target_uuid = create_simulation_data()
    print(f"\nTo generate a report, run:")
    print(f"  python generate_report.py {target_uuid}")
