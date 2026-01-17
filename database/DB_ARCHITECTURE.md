# Database Architecture

## Overview

The security tools MCP server uses a SQLite database (`pentest_results.db`) to store results from all reconnaissance tools. This enables persistent storage, cross-tool correlation, and progressive scanning.

## Database File

- **Location:** `pentest_results.db` (in the project root)
- **Engine:** SQLite3
- **Encoding:** UTF-8
- **Foreign Keys:** Enabled

---

## Tool Flow & Data Relationships

The tools are designed to be used in a specific order during reconnaissance:

```
┌─────────────────────────────────────────────────────────────────────────┐
│                          RECONNAISSANCE FLOW                            │
└─────────────────────────────────────────────────────────────────────────┘

    ┌──────────┐
    │  TARGET  │  Customer engagement target (domain/URL)
    └────┬─────┘
         │ target_uuid
         ▼
    ┌──────────┐
    │  WHOIS   │  Domain registration info
    └────┬─────┘
         │ domain
         ▼
    ┌──────────┐
    │SUBFINDER │  Discover subdomains
    └────┬─────┘
         │ subdomain
         ▼
    ┌──────────┐
    │   NMAP   │  Scan ports on domains/subdomains
    └────┬─────┘
         │ host, port
         ▼
    ┌──────────┐
    │  HTTPX   │  Probe HTTP services on open ports
    └────┬─────┘
         │ url, host
         ▼
    ┌──────────┐
    │ GOBUSTER │  Brute-force directories on live services
    └────┬─────┘
         │
         ▼
    ┌──────────┐
    │ FINDINGS │  Security findings from all tools
    └──────────┘
```

---

## Table Relationships

```
                              ┌─────────────────┐
                              │     targets     │
                              ├─────────────────┤
                              │ uuid (PK)       │
                              │ name            │
                              │ type            │
                              │ created_at      │
                              └────────┬────────┘
                                       │
          ┌────────────────────────────┼────────────────────────────┐
          │                            │                            │
          ▼                            ▼                            ▼
┌─────────────────┐          ┌─────────────────┐          ┌─────────────────┐
│  whois_results  │          │   subdomains    │          │    findings     │
├─────────────────┤          ├─────────────────┤          ├─────────────────┤
│ uuid (PK)       │          │ uuid (PK)       │          │ uuid (PK)       │
│ target_uuid(FK) │          │ target_uuid(FK) │          │ target_uuid(FK) │
│ domain          │          │ domain          │          │ tool            │
│ registrar       │          │ subdomain ──────┼───┐      │ severity        │
│ creation_date   │          │ source          │   │      │ title           │
│ expiration_date │          │ scanned_at      │   │      │ description     │
│ name_servers    │          └─────────────────┘   │      │ affected_asset  │
│ ...             │                                │      │ evidence        │
│ scanned_at      │                                │      │ recommendation  │
└─────────────────┘                                │      │ found_at        │
                                                   │      └─────────────────┘
          ┌────────────────────────────────────────┘
          │
          ▼
┌─────────────────┐          ┌─────────────────┐
│     ports       │          │  http_services  │
├─────────────────┤          ├─────────────────┤
│ uuid (PK)       │          │ uuid (PK)       │
│ target_uuid(FK) │          │ target_uuid(FK) │
│ host ◄──────────┼──────────┤ host            │
│ ip_address      │          │ url ────────────┼───┐
│ port ───────────┼──┐       │ status_code     │   │
│ protocol        │  │       │ title           │   │
│ state           │  │       │ webserver       │   │
│ service         │  │       │ technologies    │   │
│ version         │  │       │ scanned_at      │   │
│ scanned_at      │  │       └─────────────────┘   │
└─────────────────┘  │                             │
                     │                             │
    ┌────────────────┘                             │
    │  (port 80/443 → HTTP)                        │
    ▼                                              │
┌─────────────────┐                                │
│   directories   │◄───────────────────────────────┘
├─────────────────┤    (discovered on http_services)
│ uuid (PK)       │
│ target_uuid(FK) │
│ host            │
│ url             │
│ path            │
│ status_code     │
│ content_length  │
│ redirect_url    │
│ scanned_at      │
└─────────────────┘
```

---

## Relationship Descriptions

### 1. Targets → All Tables
- **Link:** `targets.uuid` → `*.target_uuid`
- **Type:** One-to-Many
- **Description:** Every record in the system belongs to a specific target engagement.

### 2. Targets → WHOIS
- **Link:** `targets.uuid` → `whois_results.target_uuid`
- **Type:** One-to-Many
- **Description:** A target can have multiple WHOIS lookups over time.

### 3. Targets → Subdomains
- **Link:** `targets.uuid` → `subdomains.target_uuid`
- **Type:** One-to-Many
- **Description:** A target can have many discovered subdomains.

### 4. Subdomains → Ports
- **Link:** `subdomains.subdomain` → `ports.host`
- **Type:** One-to-Many (logical)
- **Description:** Each subdomain can have multiple ports scanned.

### 5. Ports → HTTP Services
- **Link:** `ports.host` + `ports.port` → `http_services.host` + (port in URL)
- **Type:** One-to-Many (logical)
- **Description:** Open HTTP/HTTPS ports lead to HTTP service probing.

### 6. HTTP Services → Directories
- **Link:** `http_services.url` → `directories.host`
- **Type:** One-to-Many (logical)
- **Description:** Live HTTP services can be scanned for directories/files.

### 7. All Tools → Findings
- **Link:** Any tool can generate findings linked to `targets.uuid`
- **Type:** Many-to-One
- **Description:** Findings are generated from any tool's output and linked to the target.

---

## Findings Relationship

The `findings` table has a special relationship with all other tables:

```
┌─────────────┐     ┌─────────────┐     ┌─────────────┐
│   WHOIS     │     │  Subfinder  │     │    Nmap     │
└──────┬──────┘     └──────┬──────┘     └──────┬──────┘
       │                   │                   │
       │   ┌───────────────┼───────────────┐   │
       │   │               │               │   │
       ▼   ▼               ▼               ▼   ▼
┌──────────────────────────────────────────────────┐
│                    FINDINGS                       │
│  - Exposed registration info (from WHOIS)        │
│  - Subdomain takeover possibilities (Subfinder)  │
│  - Open sensitive ports (from Nmap)              │
│  - Outdated software versions (from Httpx)       │
│  - Exposed admin panels (from Gobuster)          │
└──────────────────────────────────────────────────┘
       ▲   ▲               ▲
       │   │               │
       │   └───────────────┼───────────────┐
       │                   │               │
┌──────┴──────┐     ┌──────┴──────┐     ┌──┴──────────┐
│    Httpx    │     │  Gobuster   │     │ Future Tool │
└─────────────┘     └─────────────┘     └─────────────┘
```

---

## Common Queries

### Get all data for a target
```sql
-- Get target info
SELECT * FROM targets WHERE name = 'example.com';

-- Get WHOIS info for target
SELECT * FROM whois_results WHERE target_uuid = '<target_uuid>';

-- Get all subdomains
SELECT * FROM subdomains WHERE target_uuid = '<target_uuid>';

-- Get all ports for target
SELECT * FROM ports WHERE target_uuid = '<target_uuid>';

-- Get all live HTTP services
SELECT * FROM http_services WHERE target_uuid = '<target_uuid>';

-- Get all discovered directories
SELECT * FROM directories WHERE target_uuid = '<target_uuid>';

-- Get all findings
SELECT * FROM findings WHERE target_uuid = '<target_uuid>' ORDER BY severity;
```

### Find interesting findings
```sql
-- Get critical and high severity findings
SELECT * FROM findings
WHERE target_uuid = '<target_uuid>'
AND severity IN ('critical', 'high')
ORDER BY found_at DESC;

-- Get findings by tool
SELECT * FROM findings
WHERE tool = 'nmap'
ORDER BY severity, found_at DESC;

-- Summary count by severity
SELECT severity, COUNT(*) as count
FROM findings
WHERE target_uuid = '<target_uuid>'
GROUP BY severity;
```

### Cross-table queries
```sql
-- Find subdomains with open HTTP ports
SELECT DISTINCT s.subdomain, p.port, p.service
FROM subdomains s
JOIN ports p ON p.host = s.subdomain AND p.target_uuid = s.target_uuid
WHERE s.target_uuid = '<target_uuid>'
AND p.state = 'open'
AND p.service LIKE '%http%';

-- Find directories on specific subdomain
SELECT d.* FROM directories d
JOIN http_services h ON d.host = h.host AND d.target_uuid = h.target_uuid
WHERE d.target_uuid = '<target_uuid>'
AND h.host LIKE '%admin%';
```

---

## Data Flow Example

1. **Customer engagement starts with target: `example.com`**
   - Creates entry in `targets` table with UUID

2. **WHOIS** → Stores domain info in `whois_results`
   - Links to target via `target_uuid`
   - `example.com` → registrar, dates, nameservers
   - May generate findings: "Domain expires in 30 days"

3. **Subfinder** → Discovers and stores in `subdomains`
   - All linked to same `target_uuid`
   - `api.example.com`, `www.example.com`, `admin.example.com`
   - May generate findings: "Subdomain takeover possible on old.example.com"

4. **Nmap** → Scans each subdomain, stores in `ports`
   - `api.example.com:80` (open, http)
   - `admin.example.com:22` (open, ssh)
   - May generate findings: "SSH exposed on admin subdomain"

5. **Httpx** → Probes HTTP services, stores in `http_services`
   - `https://api.example.com` [200] [API Server] [Nginx 1.14]
   - May generate findings: "Outdated Nginx version detected"

6. **Gobuster** → Brute-forces directories, stores in `directories`
   - `https://admin.example.com/login` (200)
   - `https://api.example.com/.git/` (200)
   - May generate findings: "Exposed .git directory"

7. **Report Generation** → Queries all tables for target
   - Generates PDF with all findings grouped by severity

---

## Timestamps

Every table includes timestamp columns:
- `targets.created_at` - When engagement started
- `*.scanned_at` - When each scan was performed
- `findings.found_at` - When finding was discovered

This enables:
- **Freshness checks:** Know if data is stale
- **Delta comparisons:** Compare results between scans
- **Audit trail:** Track when reconnaissance was performed
- **Reporting:** Show timeline of discovery
