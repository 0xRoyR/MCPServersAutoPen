# Table Schemas

This document describes the SQLite database table schemas for the penetration testing MCP server.

---

## targets

Stores customer engagement targets for penetration testing.

| Column | Type | Description |
|--------|------|-------------|
| uuid | TEXT PRIMARY KEY | Unique identifier for the target |
| name | TEXT NOT NULL | Target name (e.g., example.com) |
| type | TEXT NOT NULL | Target type: 'domain' or 'url' |
| created_at | TIMESTAMP | When the target was created |

**Indexes:** name, type
**Unique Constraint:** (name)

---

## whois_results

Stores WHOIS lookup results for domains.

| Column | Type | Description |
|--------|------|-------------|
| uuid | TEXT PRIMARY KEY | Unique identifier for the record |
| target_uuid | TEXT NOT NULL | FK to targets table |
| domain | TEXT NOT NULL | The domain that was queried |
| registrar | TEXT | Domain registrar name |
| creation_date | TEXT | Domain creation date |
| expiration_date | TEXT | Domain expiration date |
| name_servers | TEXT | JSON array of name servers |
| registrant_name | TEXT | Registrant name |
| registrant_org | TEXT | Registrant organization |
| registrant_country | TEXT | Registrant country |
| raw_output | TEXT | Full raw WHOIS output |
| scanned_at | TIMESTAMP | When the scan was performed |

**Indexes:** target_uuid, domain
**Foreign Key:** target_uuid -> targets(uuid)

---

## subdomains

Stores discovered subdomains from subfinder.

| Column | Type | Description |
|--------|------|-------------|
| uuid | TEXT PRIMARY KEY | Unique identifier for the record |
| target_uuid | TEXT NOT NULL | FK to targets table |
| domain | TEXT NOT NULL | Parent domain (e.g., example.com) |
| subdomain | TEXT NOT NULL | Full subdomain (e.g., api.example.com) |
| source | TEXT | Discovery source (e.g., subfinder) |
| scanned_at | TIMESTAMP | When the scan was performed |

**Indexes:** target_uuid, domain, subdomain
**Unique Constraint:** (target_uuid, subdomain)
**Foreign Key:** target_uuid -> targets(uuid)

---

## ports

Stores port scan results from nmap.

| Column | Type | Description |
|--------|------|-------------|
| uuid | TEXT PRIMARY KEY | Unique identifier for the record |
| target_uuid | TEXT NOT NULL | FK to targets table |
| host | TEXT NOT NULL | Hostname or IP that was scanned |
| ip_address | TEXT | Resolved IP address |
| port | INTEGER NOT NULL | Port number |
| protocol | TEXT | Protocol (tcp/udp), default 'tcp' |
| state | TEXT | Port state (open, closed, filtered) |
| service | TEXT | Service name (http, ssh, etc.) |
| version | TEXT | Service version information |
| scanned_at | TIMESTAMP | When the scan was performed |

**Indexes:** target_uuid, host, port, ip_address
**Unique Constraint:** (target_uuid, host, port, protocol)
**Foreign Key:** target_uuid -> targets(uuid)

---

## http_services

Stores HTTP probe results from httpx.

| Column | Type | Description |
|--------|------|-------------|
| uuid | TEXT PRIMARY KEY | Unique identifier for the record |
| target_uuid | TEXT NOT NULL | FK to targets table |
| host | TEXT NOT NULL | Original target host |
| url | TEXT NOT NULL | Full URL that was probed |
| status_code | INTEGER | HTTP response status code |
| title | TEXT | Page title |
| webserver | TEXT | Web server software |
| technologies | TEXT | JSON array of detected technologies |
| content_length | INTEGER | Response content length |
| content_type | TEXT | Response content type |
| redirect_url | TEXT | Redirect destination if applicable |
| scanned_at | TIMESTAMP | When the scan was performed |

**Indexes:** target_uuid, host, url, status_code
**Unique Constraint:** (target_uuid, url)
**Foreign Key:** target_uuid -> targets(uuid)

---

## directories

Stores directory/file discovery results from gobuster.

| Column | Type | Description |
|--------|------|-------------|
| uuid | TEXT PRIMARY KEY | Unique identifier for the record |
| target_uuid | TEXT NOT NULL | FK to targets table |
| host | TEXT NOT NULL | Target host |
| url | TEXT NOT NULL | Full URL of discovered path |
| path | TEXT NOT NULL | Just the path portion (e.g., /admin) |
| status_code | INTEGER | HTTP response status code |
| content_length | INTEGER | Response content length |
| redirect_url | TEXT | Redirect destination if applicable |
| scanned_at | TIMESTAMP | When the scan was performed |

**Indexes:** target_uuid, host, path, status_code
**Unique Constraint:** (target_uuid, url)
**Foreign Key:** target_uuid -> targets(uuid)

---

## findings

Stores security findings discovered during the assessment.

| Column | Type | Description |
|--------|------|-------------|
| uuid | TEXT PRIMARY KEY | Unique identifier for the finding |
| target_uuid | TEXT NOT NULL | FK to targets table |
| tool | TEXT NOT NULL | Tool that discovered the finding |
| severity | TEXT | Severity level: critical, high, medium, low, info |
| title | TEXT NOT NULL | Short title of the finding |
| description | TEXT | Detailed description of the finding |
| affected_asset | TEXT | What asset is affected |
| evidence | TEXT | Evidence/proof of the finding |
| recommendation | TEXT | Remediation recommendation |
| found_at | TIMESTAMP | When the finding was discovered |

**Indexes:** target_uuid, tool, severity
**Foreign Key:** target_uuid -> targets(uuid)
