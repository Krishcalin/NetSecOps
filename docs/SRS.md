# NetSecOps — Software Requirements Specification (SRS)

**Product:** NetSecOps — Network Configuration & Vulnerability Assessment Platform
**Document version:** 1.0 (Draft)
**Date:** 13 September 2026
**Status:** Baseline for development
**Intended reader:** Development team / AI coding agent (Claude Code), QA, security reviewers

---

## 0. How to use this document (instructions for the coding agent)

1. Treat every requirement with an ID (`FR-`, `NFR-`, `SEC-`, `DATA-`, `IF-`) as a testable obligation. Each shall map to at least one automated test.
2. **The read-only guarantee (Section 8) is a hard constraint that overrides every other requirement.** If any feature would require pushing a change to a target device, do not implement it — raise it as an open question instead.
3. Build in the phase order given in Section 12. Do not start Phase N+1 before Phase N acceptance criteria pass.
4. Where this document says "SHALL", it is mandatory for v1.0. "SHOULD" is expected but may be deferred with a documented reason. "MAY" is optional.
5. Keep all vendor-specific logic inside the vendor adapter packages (Section 4.4). Core services must be vendor-agnostic.
6. When a vendor command or API path is uncertain, consult the vendor documentation and record the source in `docs/vendor-notes/<vendor>.md` rather than guessing.

---

## 1. Introduction

### 1.1 Purpose
This SRS defines the functional, non-functional, interface, data and security requirements for **NetSecOps**, a web-based, client–server platform that performs **read-only** configuration assessment and vulnerability assessment of network and security infrastructure devices.

### 1.2 Scope
NetSecOps will:

- Maintain an inventory of network devices identified by IP address (and optionally hostname), with vendor/platform metadata and assigned credentials.
- Authenticate to those devices over SSH and/or vendor HTTPS APIs, and **extract** running configuration, version/inventory data and operational state using only read/show-type operations.
- Parse and normalise the extracted data into a vendor-neutral model.
- Evaluate configuration against a library of security checks (hardening/benchmark checks, firewall policy hygiene, AAA/RADIUS/TACACS+ checks, crypto/protocol checks).
- Correlate software versions and features against published vulnerabilities (CVE/NVD, vendor PSIRT advisories) and end-of-life data.
- Track configuration changes over time (drift detection, diff, baselines).
- Present results in a React dashboard and produce exportable reports.
- Integrate with SIEM / ticketing / notification channels.

NetSecOps will **not**:

- Modify, push, commit, reload, or otherwise alter any target device (see Section 8).
- Perform active exploitation, password brute-forcing, or traffic-based vulnerability scanning (Nmap/Nessus-style port and service scanning). Discovery is limited to lightweight reachability and fingerprinting probes (Section 3.4).
- Act as a configuration backup/restore or change-management tool (it stores configs for assessment and diff only).

### 1.3 Target device classes and vendors (v1.0)

| Device class | Cisco | Palo Alto Networks | Fortinet | Check Point |
|---|---|---|---|---|
| Next-gen firewall | ASA, Firepower/FTD (via FMC/FDM API) | PAN-OS firewalls, Panorama | FortiGate, FortiManager | Security Gateway (Gaia), Security Management Server / Multi-Domain (Management API) |
| Switches | IOS, IOS-XE, NX-OS | — | FortiSwitch (via FortiGate/FortiLink or direct REST/SSH) | — |
| Routers | IOS, IOS-XE, IOS-XR | — | FortiGate (routing features) | — |
| Wireless access points | Managed via WLC (AireOS) / Catalyst 9800; standalone Aironet/Catalyst AP (IOS-based) | — | FortiAP (via FortiGate) | — |
| Wireless controllers | WLC AireOS (5520/8540/vWLC), Catalyst 9800 (IOS-XE) | — | FortiGate as WLC, FortiWLC (Meru) | — |
| RADIUS / TACACS+ configuration | (a) AAA client config on every device above; (b) Cisco ISE (ERS/OpenAPI) | (a) Authentication profiles / server profiles on PAN-OS | (a) AAA client config; (b) FortiAuthenticator (REST) | (a) RADIUS/TACACS objects & authentication settings in Management API and Gaia |
| Generic AAA servers | FreeRADIUS, tac_plus / tac_plus-ng on Linux (via SSH, read config files) — **SHOULD** | | | |

### 1.4 Definitions and acronyms

| Term | Meaning |
|---|---|
| Target / Device | A network or security device being assessed |
| Adapter / Collector | Vendor-specific module that knows how to connect to and read from a device family |
| Collection | One authenticated read session against a device producing raw artefacts |
| Artefact | Raw output of a command/API call (text, XML, JSON), stored immutably |
| Normalised Config Model (NCM) | Vendor-neutral JSON representation of a device configuration |
| Check | A single security rule evaluated against the NCM or raw artefacts |
| Finding | Result of a failed/informational check, or a matched vulnerability, on a specific device |
| Assessment / Scan Job | A scheduled or on-demand run of collection + evaluation across a set of devices |
| Baseline | A pinned configuration snapshot used as the reference for drift detection |
| PSIRT | Vendor Product Security Incident Response Team advisories |
| NVD / CPE / CVSS | NIST vulnerability database, product identifier scheme, severity scoring |
| CIS Benchmark | Center for Internet Security hardening benchmark |
| RBAC | Role-Based Access Control |

### 1.5 References
- IEEE 29148 (requirements engineering) — structure of this document
- CIS Benchmarks: Cisco IOS/IOS-XE, Cisco NX-OS, Cisco ASA, Palo Alto PAN-OS, Fortinet FortiGate, Check Point Firewall
- NIST SP 800-53 Rev.5, NIST SP 800-41 (firewall policy), NIST SP 800-115 (technical assessment)
- OWASP ASVS 4.0 (security requirements for the NetSecOps application itself)
- NIST NVD API 2.0; Cisco PSIRT openVuln API; Palo Alto Networks Security Advisories; Fortinet PSIRT; Check Point Security Advisories / SecureKnowledge
- Vendor API docs: PAN-OS XML/REST API, FortiOS REST API, FortiManager JSON-RPC, Check Point Management API, Cisco FMC REST API, Cisco ISE ERS & OpenAPI
- Optional regulatory mapping packs: PCI DSS 4.0, ISO/IEC 27001:2022 Annex A, CERT-In directions (India), CEA Cyber Security in Power Sector Regulations (India)

---

## 2. Overall description

### 2.1 Product perspective
NetSecOps is a self-hosted, three-tier web application:

```
┌───────────────────────────────┐
│ React + TypeScript SPA (Vite) │  ← Browser (HTTPS)
└──────────────┬────────────────┘
               │ REST/JSON (OpenAPI 3.1), WebSocket for live job status
┌──────────────▼────────────────┐
│ FastAPI application (Python 3.12)                       │
│  - Auth/RBAC  - Inventory  - Jobs API  - Reports API    │
└──────────────┬────────────────┘
               │ SQLAlchemy 2.x (async) / Alembic
┌──────────────▼────────────────┐        ┌─────────────────────────────┐
│ PostgreSQL 16                 │◄──────►│ Worker pool (Python)         │
│  - relational data            │  queue │  - Collectors (SSH/API)      │
│  - JSONB (NCM, artefacts)     │        │  - Parsers/normalisers       │
│  - job queue tables           │        │  - Check engine, Vuln matcher│
└───────────────────────────────┘        └──────────┬──────────────────┘
                                                    │ SSH (22) / HTTPS (443) / SNMP (161, optional)
                                         ┌──────────▼──────────────────┐
                                         │ Target devices (read-only)   │
                                         └─────────────────────────────┘
```

### 2.2 Technology stack (fixed)

| Layer | Choice | Notes |
|---|---|---|
| Language | Python 3.12+ | Type hints everywhere; `mypy --strict` clean |
| API | FastAPI (Pydantic v2) | Auto OpenAPI; async endpoints |
| ORM / migrations | SQLAlchemy 2.x (async, `asyncpg`) + Alembic | |
| Database | PostgreSQL 16 | JSONB for configs/artefacts; `pgcrypto` not used for secrets (app-level encryption instead) |
| Background jobs | **Procrastinate** (PostgreSQL-backed task queue) — default, keeps stack to PostgreSQL only | Alternative if throughput requires: Celery + Redis. Decision recorded in ADR-001 |
| Device access | `scrapli` (async SSH, Cisco/Junos-style CLIs) with `netmiko` fallback; `asyncssh` for Linux/Gaia; `httpx` for REST/XML APIs; `pan-os-python` optional for PAN-OS | Adapters must not depend on vendor SDKs that require write scope |
| Config parsing | `ciscoconfparse2`, `ttp` (templates), `lxml`, native JSON | |
| Frontend | React 18+, TypeScript 5+, Vite, React Router, TanStack Query, plain CSS (CSS Modules + CSS variables) — no Tailwind/UI kit unless approved | Charts: Recharts or ECharts |
| Reports | WeasyPrint or ReportLab for PDF; `openpyxl` for XLSX; CSV/JSON native | |
| Auth | JWT (access + refresh, httpOnly cookies), Argon2id password hashing, TOTP MFA, optional OIDC/SAML SSO | |
| Secrets | Envelope encryption: AES-256-GCM data keys wrapped by a master key from env/KMS/HashiCorp Vault | |
| Containerisation | Docker + Docker Compose (dev/prod), optional Helm chart | |
| Testing | `pytest`, `pytest-asyncio`, `httpx.AsyncClient`, `factory_boy`; frontend `vitest` + React Testing Library; E2E `Playwright` | |
| Quality | `ruff`, `mypy`, `bandit`, `pip-audit`; `eslint`, `prettier`, `npm audit`; pre-commit hooks | |

### 2.3 User classes

| Role | Description | Typical actions |
|---|---|---|
| **Super Admin** | Platform owner | Manage users/roles, global settings, credential vault policy, integrations, licence/feature flags |
| **Security Analyst** | Primary user | Manage inventory, run/schedule assessments, review findings, accept risk, generate reports |
| **Network Engineer** | Device owner | View findings and config for devices in assigned groups; export configs; cannot change checks or credentials |
| **Auditor / Read-only** | Compliance / management | View dashboards, reports, audit trail; no execution or edits |
| **API Service Account** | Machine user | Scoped API token for SIEM/ITSM integrations |

### 2.4 Operating environment
- Server: Linux x86_64 (Ubuntu 22.04/24.04 LTS or RHEL 9 compatible), Docker 24+. Minimum 4 vCPU / 8 GB RAM for up to 500 devices; sizing guide in `docs/deployment.md`.
- Database: PostgreSQL 16 (can be external/managed).
- Client: Latest two major versions of Chrome, Edge, Firefox; Safari 16+. Minimum resolution 1366×768.
- Network: Outbound from workers to devices on TCP/22 and TCP/443 (plus optional UDP/161 and ICMP for discovery). Outbound HTTPS to NVD/PSIRT feeds (may be air-gapped — see FR-VUL-08).

### 2.5 Design and implementation constraints
- C-1: All device interactions are read-only (Section 8).
- C-2: No secrets in logs, URLs, error messages or frontend state.
- C-3: Single codebase, monorepo (`/backend`, `/frontend`, `/deploy`, `/docs`).
- C-4: All API endpoints versioned under `/api/v1`.
- C-5: Every DB schema change via Alembic migration; no manual DDL.
- C-6: Vendor adapters expose one common Python interface (Section 4.4); no vendor conditionals outside adapters and parsers.
- C-7: Application must run fully offline (air-gapped) with vulnerability feeds imported manually.

### 2.6 Assumptions and dependencies
- A-1: Customers will provision **read-only** device accounts (e.g., Cisco privilege 15 is acceptable only if command allow-listing is enforced by NetSecOps; preferred privilege 1 + `show` authorisation; PAN-OS `superreader`; FortiOS read-only admin profile; Check Point Read Only role).
- A-2: Devices are reachable from the worker network segment without NAT ambiguity, or via a jump host (FR-COL-09).
- A-3: Vendor API schemas may change; adapters carry a `supported_versions` matrix and gracefully degrade.

---

## 3. Functional requirements

Requirement ID format: `FR-<MODULE>-<NN>`. Priority: **M** = Must (v1.0), **S** = Should, **C** = Could.

### 3.1 Authentication, authorisation and user management (FR-AUTH)

| ID | Requirement | Pri |
|---|---|---|
| FR-AUTH-01 | The system SHALL support local username/password authentication with Argon2id hashing and configurable password policy (min length 12, complexity, history 5, max age). | M |
| FR-AUTH-02 | The system SHALL issue short-lived JWT access tokens (≤15 min) and rotating refresh tokens (≤8 h, revocable) delivered as `Secure; HttpOnly; SameSite=Strict` cookies. | M |
| FR-AUTH-03 | The system SHALL support TOTP-based MFA (RFC 6238) per user, enforceable per role by Super Admin. | M |
| FR-AUTH-04 | The system SHOULD support OIDC (Authorization Code + PKCE) SSO with group-to-role mapping; SAML 2.0 MAY be supported. | S |
| FR-AUTH-05 | The system SHALL implement RBAC with the five roles in §2.3 and object-level scoping by **Device Group** for Network Engineer and Auditor roles. | M |
| FR-AUTH-06 | The system SHALL lock an account after 5 consecutive failed logins for 15 minutes and log the event. | M |
| FR-AUTH-07 | The system SHALL allow creation of scoped API tokens (read-only or read/execute), with expiry and revocation. | M |
| FR-AUTH-08 | All privileged actions SHALL be recorded in the audit log (FR-AUD). | M |

### 3.2 Inventory and asset management (FR-INV)

| ID | Requirement | Pri |
|---|---|---|
| FR-INV-01 | Users SHALL be able to create, edit, archive and delete devices with: management IP (IPv4/IPv6), optional hostname/FQDN, vendor, platform/OS family, device class, site, device group(s), tags, owner, criticality (Critical/High/Medium/Low), and assigned credential set(s). | M |
| FR-INV-02 | The system SHALL support bulk import of devices via CSV/XLSX with validation and a dry-run preview. | M |
| FR-INV-03 | The system SHALL support hierarchical Device Groups (e.g., Site → Zone → Function) and free-form tags; a device may belong to multiple groups. | M |
| FR-INV-04 | Manager-type systems (Panorama, FortiManager, Check Point SMS/MDS, Cisco FMC, ISE, Cisco WLC) SHALL be modelled as devices that can **enumerate managed children** and auto-populate the inventory (with user approval). | M |
| FR-INV-05 | After each successful collection the system SHALL auto-update device facts: hostname, model, serial(s), OS version, uptime, HA role/peer, interfaces summary, last-seen. | M |
| FR-INV-06 | The system SHALL detect duplicates (same serial or same IP) and prompt for merge. | S |
| FR-INV-07 | Device pages SHALL show: facts, latest findings summary, risk score, config history, collection history, assigned credentials (name only), and neighbours (CDP/LLDP) where collected. | M |
| FR-INV-08 | The system SHALL expose full inventory search/filter by any field, tag and finding severity, with saved filters. | M |

### 3.3 Credential vault (FR-CRED)

| ID | Requirement | Pri |
|---|---|---|
| FR-CRED-01 | The system SHALL store device credentials of types: SSH password, SSH private key (+passphrase), enable/secret, API key/token, API username/password, SNMPv2c community, SNMPv3 (user, auth/priv protocols & keys), Check Point API session credentials, jump-host credentials. | M |
| FR-CRED-02 | All secret material SHALL be encrypted at rest using AES-256-GCM with per-record data keys wrapped by a master key (env var, file, HashiCorp Vault Transit, or AWS/Azure/GCP KMS). Master key rotation SHALL be supported via re-wrap job. | M |
| FR-CRED-03 | Secrets SHALL never be returned by any API after creation; only name, type, metadata and last-used/last-tested timestamp. | M |
| FR-CRED-04 | Credentials SHALL be assignable to devices individually or to Device Groups (inheritance with device-level override) and ordered as a fallback list. | M |
| FR-CRED-05 | The system SHALL provide "Test credential" against a device performing only a login + trivial read (e.g., `show version`, API `system/info`). | M |
| FR-CRED-06 | The system SHOULD integrate with external secret managers (HashiCorp Vault KV, CyberArk CCP, Azure Key Vault) to fetch credentials at runtime without storing them locally. | S |
| FR-CRED-07 | The system SHALL record every credential use (device, job, user/schedule, outcome) in the audit log without recording the secret. | M |

### 3.4 Discovery (FR-DISC)

| ID | Requirement | Pri |
|---|---|---|
| FR-DISC-01 | Users SHALL be able to define discovery scopes as IP ranges/CIDRs/lists with exclusions. | M |
| FR-DISC-02 | Discovery SHALL perform only: ICMP echo, TCP connect to 22/443 (configurable list), SSH banner grab, HTTPS server certificate & header retrieval, and optional SNMP `sysDescr`/`sysObjectID` GET. No port sweeps beyond the configured list; no service exploitation. | M |
| FR-DISC-03 | The system SHALL fingerprint vendor/platform from SSH banner, TLS certificate subject, HTTP headers/login page markers and SNMP sysObjectID, with a confidence score. | M |
| FR-DISC-04 | Discovered hosts SHALL land in a "Pending review" queue; users approve/assign credentials/reject. Nothing is assessed automatically without approval unless a scope is flagged "auto-onboard". | M |
| FR-DISC-05 | Discovery SHALL be rate-limited (default 50 hosts/s, configurable) and schedulable. | M |
| FR-DISC-06 | The system SHALL enumerate managed devices from managers (FR-INV-04) as a discovery source. | M |

### 3.5 Collection (FR-COL)

| ID | Requirement | Pri |
|---|---|---|
| FR-COL-01 | The system SHALL collect from each device using its adapter: (a) running/effective configuration, (b) version/inventory/HA state, (c) operational data required by checks (interfaces, neighbours, users/sessions, policy hit counts where available), (d) certificate and crypto details. | M |
| FR-COL-02 | Collection SHALL support SSH (password, key, keyboard-interactive), HTTPS REST/XML API with basic/token/API-key auth, and Check Point Management API session-based auth. | M |
| FR-COL-03 | Each command/API call and its raw response SHALL be stored as an immutable, hashed (SHA-256) artefact linked to the collection run, with timestamps and duration. | M |
| FR-COL-04 | The system SHALL enforce the read-only command allow-list (Section 8) before any command is sent; violations abort the collection and raise a critical internal alert. | M |
| FR-COL-05 | Collection SHALL handle paging disable (`terminal length 0`, `terminal pager 0`, `config paging disable`, `set cli pager off`), prompt detection, enable-mode entry (Cisco), and timeouts (connect 15 s, command 60 s default; configurable per device). | M |
| FR-COL-06 | Concurrency SHALL be configurable globally (default 20 parallel devices) and per device group; per-device serialisation (never two sessions to one device). | M |
| FR-COL-07 | Failures SHALL be classified (unreachable, auth failed, authz denied for command, timeout, parser error, unsupported version) and retried per policy (default 2 retries, exponential backoff). | M |
| FR-COL-08 | Partial collections SHALL be stored and assessed with checks marked "Not evaluated — missing data". | M |
| FR-COL-09 | The system SHALL support SSH jump hosts / bastions (ProxyJump semantics) per device or group. | M |
| FR-COL-10 | The system SHALL verify device SSH host keys and TLS certificates with policy options: strict (pin on first use, alert on change), or accept-and-record. Host key/cert changes SHALL generate a finding. | M |
| FR-COL-11 | Users SHALL be able to upload configuration files offline (text/XML/JSON exports) for assessment without live access (air-gapped or pre-onboarding use). | M |
| FR-COL-12 | Live job progress (per device status, log tail without secrets) SHALL stream to the UI via WebSocket. | M |
| FR-COL-13 | Config artefacts SHALL be redacted for display (passwords, shared secrets, keys, communities masked) while the original is retained encrypted for diff/hash purposes. | M |

### 3.6 Parsing and normalisation (FR-PARSE)

| ID | Requirement | Pri |
|---|---|---|
| FR-PARSE-01 | Each adapter SHALL produce a **Normalised Config Model (NCM)** JSON document conforming to a versioned JSON Schema (`schemas/ncm/v1.json`). | M |
| FR-PARSE-02 | NCM SHALL cover at minimum: `system` (hostname, domain, version, model, serial, uptime, ha), `management` (services enabled: ssh/telnet/http/https/snmp/netconf/restconf, ACLs on mgmt, ssh version/ciphers/kex, TLS versions/ciphers, session timeouts, banners), `users` (local accounts, privilege, password type/strength indicators, keys), `aaa` (authentication/authorization/accounting method lists, RADIUS/TACACS+ servers, ports, timeouts, key configured yes/no, source interface, fallback to local, dead-time), `logging` (syslog targets, levels, facilities, buffered, timestamps, archive), `ntp` (servers, auth), `snmp` (versions, communities, v3 users & security levels, views, ACLs, traps), `interfaces` (name, description, admin/oper state, IPs, vlan, mode, security features: port-security, bpduguard, dhcp snooping, arp inspection, storm control), `l2` (vlans, stp mode/guards, vtp), `routing` (protocols, authentication, redistribution), `acls`, `firewall` (zones, address/service objects, security rules with order/action/log/profiles/hit-count/last-hit, NAT rules, security profiles: AV/IPS/URL/DNS/file-blocking/decryption), `vpn` (IKE/IPsec proposals, PSK usage, DH groups), `wireless` (SSIDs/WLANs, security type WPA2/WPA3/Open, PSK vs 802.1X, PMF, fast transition, radius mapping, AP list, rogue detection, client isolation), `certificates` (subject, issuer, expiry, key size, sig algo, self-signed), `features` (enabled feature flags relevant to checks). | M |
| FR-PARSE-03 | Parsing SHALL be tolerant: unknown stanzas are retained under `raw_unparsed[]` and never cause collection failure. | M |
| FR-PARSE-04 | Every NCM field SHALL carry provenance (artefact id + line range or JSON path) so findings can show the offending config lines. | M |
| FR-PARSE-05 | Parsers SHALL be unit-tested against a fixture corpus (`tests/fixtures/<vendor>/<platform>/<version>/`) with anonymised real-world configs; target ≥90% branch coverage per parser. | M |

### 3.7 Configuration assessment — check engine (FR-CHK)

| ID | Requirement | Pri |
|---|---|---|
| FR-CHK-01 | Checks SHALL be defined declaratively in YAML (`checks/<vendor-or-common>/<id>.yaml`) with: id, title, description, rationale, severity (Critical/High/Medium/Low/Info), applicability (vendor, platform, version range, device class), logic (JSONPath/JMESPath expressions over NCM, regex over raw artefact, or reference to a Python check function), remediation guidance (text, **never executed**), references (CIS section, NIST control, CVE, vendor doc), tags. | M |
| FR-CHK-02 | The engine SHALL support Python-implemented checks for complex logic (firewall rule analysis) registered via entry points, with the same metadata schema. | M |
| FR-CHK-03 | Each check result SHALL be one of: Pass, Fail, Warning, Not Applicable, Not Evaluated (missing data), Error; with evidence (matched NCM path/values and config line excerpts). | M |
| FR-CHK-04 | The system SHALL ship a **baseline check library** covering at minimum the areas in Appendix B (≥150 checks across vendors at v1.0). | M |
| FR-CHK-05 | Checks SHALL be groupable into **Policies** (e.g., "CIS Cisco IOS L1", "Internal Hardening Standard v3", "PCI DSS Network"); a policy is assigned to device groups. Framework mapping (CIS/NIST/PCI/ISO/CERT-In/CEA) SHALL be attributes of checks so compliance views can be pivoted by framework. | M |
| FR-CHK-06 | Users with Analyst+ role SHALL be able to create custom checks in the UI (form-based YAML editor with validation and a "test against device" dry run) and enable/disable/override severity of built-in checks per policy. | M |
| FR-CHK-07 | Users SHALL be able to add **exceptions**: suppress a finding for a device/group/check with justification, expiry date and approver; expired exceptions re-open findings. | M |
| FR-CHK-08 | Check library updates SHALL be importable as signed bundles (tar + detached signature) and versioned; results record which check version produced them. | S |
| FR-CHK-09 | The engine SHALL compute a per-device **risk score** (0–100) from weighted finding severities and device criticality, and roll up to group/site/organisation. Formula documented and configurable. | M |

### 3.8 Firewall policy analysis (FR-FW)

Applies to Cisco ASA/FTD, PAN-OS, FortiGate, Check Point.

| ID | Requirement | Pri |
|---|---|---|
| FR-FW-01 | The system SHALL normalise security rules to a common tuple (order, name, src zones/addresses, dst zones/addresses, applications/services, users, action, logging, profiles, schedule, enabled, hit-count/last-hit if available). | M |
| FR-FW-02 | The system SHALL detect: any/any/any permit rules; overly broad sources or services (any service, large CIDRs, wide port ranges) with configurable thresholds; rules without logging; disabled rules; rules with no hits for N days (when hit-counts collected); expired schedules; rules lacking security profiles (IPS/AV/URL/DNS) on permit; permit rules above a deny for the same traffic; rules using deprecated/insecure services (telnet, ftp, snmp v1/2, smbv1, rdp from any). | M |
| FR-FW-03 | The system SHALL perform **rule relationship analysis**: fully shadowed rules, redundant rules, partially overlapping/correlated rules, and generalisation (a broader rule follows a specific one), using set semantics over address/service objects with object-group expansion. | M |
| FR-FW-04 | The system SHALL analyse NAT rules for exposed services (inbound NAT to internal hosts with management ports open) and inconsistent NAT/security pairing. | S |
| FR-FW-05 | The system SHALL analyse object hygiene: unused objects/groups, duplicate objects (same value, different names), nested group depth. | M |
| FR-FW-06 | The system SHALL provide a **rule query**: given src IP, dst IP, protocol/port (and optional zone/app), show which rule would match on a selected device and config version (offline simulation over the normalised rulebase; documented limitations for app-id/user-id). | S |
| FR-FW-07 | Results SHALL be presented in a rulebase viewer with highlighting, filters and export. | M |

### 3.8a Topology and path analysis (FR-TOPO)

> **Added 2026-09-18, after the 1.0 baseline.** These requirements were not in the SRS
> as issued; they were added at the product owner's direction following a competitive
> analysis which found that multi-device reasoning is the single capability separating
> this product from the established firewall-policy-management tools, and that four of
> the five identified gaps collapse into it. They extend FR-FW-06, which answers "which
> rule matches on *this* device" — the question an operator actually asks is "can this
> host reach that one, and what decides".
>
> Nothing here requires a new data source. A topology is built from the forwarding
> tables already present in collected configurations, which is how the commercial tools
> build theirs: no probing, no traceroute, no CDP/LLDP walk, no agents. This stays
> inside §8 — the read-only guarantee is untouched.

| ID | Requirement | Pri |
|---|---|---|
| FR-TOPO-01 | The system SHALL normalise each device's forwarding table into the NCM: destination prefix, next hop, egress interface, protocol by which the route was learned, administrative distance, metric, and VRF. Connected routes SHALL be derived from interface addressing. | M |
| FR-TOPO-02 | The system SHALL assemble the per-device tables into a single layer-3 graph, keyed by prefix, with VRFs treated as separate forwarding domains. | M |
| FR-TOPO-03 | The system SHALL answer a path query — given source IP, destination IP, protocol and port — by walking that graph and evaluating each traversed device's rulebase via FR-FW-06. | M |
| FR-TOPO-04 | A path result SHALL report **routing confidence and policy verdict as two separate axes**. Routing: `unreachable`, `same-zone`, `routed`, `partially-routed`, `unknown`. Policy: `allowed`, `blocked`, `partially-allowed`, `not-routed`. A bare "allowed" that conceals a lost path is a dangerous answer and SHALL NOT be produced. | M |
| FR-TOPO-05 | Where a path leaves the managed estate — a next hop belonging to no inventoried device, or a snapshot predating route collection — the result SHALL be `unknown` and SHALL name the prefix and next hop at which analysis stopped. It SHALL NOT be reported as unreachable. | M |
| FR-TOPO-06 | The system SHALL produce a **ranked missing-device report**: the unmanaged next hops that terminate the most path analyses, ordered by how much reachability they obscure, so that onboarding effort can be spent where it buys the most coverage. | S |
| FR-TOPO-07 | Route tables SHALL be bounded per device, and any truncation SHALL be recorded on the snapshot so that a path falling beyond the stored table resolves to `unknown` rather than `unreachable`. | M |

### 3.9 AAA / RADIUS / TACACS+ assessment (FR-AAA)

| ID | Requirement | Pri |
|---|---|---|
| FR-AAA-01 | For every device the system SHALL assess client-side AAA: centralised authentication enabled for login/enable/console/vty/http; authorisation for commands; accounting for exec/commands; local fallback only; shared secret configured; multiple servers configured; server reachability from device (via `show` state, not by sending test packets); timeouts/dead-time; source interface; TACACS+ preferred for device administration where supported; RADIUS for 802.1X/wireless; use of RadSec/TLS where supported. | M |
| FR-AAA-02 | The system SHALL collect from **Cisco ISE** (ERS/OpenAPI, read-only): network devices, network device groups, admin users & roles, internal users, identity sources, policy sets (authentication/authorisation rules), allowed protocols (detect PAP/CHAP/MS-CHAPv1/EAP-MD5/LEAP), certificates (EAP/admin), TACACS command sets & profiles, guest settings, repository/backup config, admin access settings (session timeout, password policy, MFA). | M |
| FR-AAA-03 | The system SHALL collect from **FortiAuthenticator** (REST): RADIUS clients, policies, EAP settings, local users/groups, LDAP/AD remote auth servers, certificates, admin profiles. | S |
| FR-AAA-04 | The system SHOULD collect from **FreeRADIUS** and **tac_plus/tac_plus-ng** hosts over SSH by reading configuration files (`/etc/freeradius/3.0/**`, `/etc/tac_plus/**`) read-only, and assess: clients with weak/default secrets, PAP/CHAP allowed, EAP methods & TLS versions/ciphers, cert expiry, logging, privilege/command authorisation definitions. | S |
| FR-AAA-05 | The system SHALL cross-correlate: every network device's configured AAA server IPs vs AAA servers in inventory; devices configured on ISE/FortiAuthenticator as clients but not in inventory (and vice-versa); shared-secret reuse indicators (same hash across many devices when exposable — otherwise flagged as "unknown"). | M |
| FR-AAA-06 | AAA findings SHALL appear both per device and in an **AAA posture** dashboard (coverage %, protocols in use, orphaned clients, cert expiry timeline). | M |

### 3.10 Vulnerability assessment (FR-VUL)

| ID | Requirement | Pri |
|---|---|---|
| FR-VUL-01 | The system SHALL build a CPE 2.3 identifier per device from vendor/platform/version (and hardware model) and match against NVD CVE data (JSON 2.0 feed / API) using version-range matching. | M |
| FR-VUL-02 | The system SHALL ingest vendor advisories: Cisco PSIRT openVuln API (by OS version — IOS, IOS-XE, NX-OS, ASA, FTD/FMC, WLC, ISE), Palo Alto Networks Security Advisories (JSON/CSAF), Fortinet PSIRT (RSS/CSAF), Check Point advisories (SecureKnowledge / CSAF where available). CSAF 2.0 parsing SHALL be the preferred ingestion format. | M |
| FR-VUL-03 | Matching SHALL be **feature-aware** where advisories specify conditions: e.g., a CVE affecting only devices with HTTP server enabled, or a specific feature configured — the engine uses NCM `features`/`management` to set confidence: Confirmed (version + feature match), Likely (version match, feature unknown), Not Affected (feature disabled), with explanation. | M |
| FR-VUL-04 | Each vulnerability finding SHALL show: CVE id, vendor advisory id, CVSS v3.1/v4 base score & vector, EPSS score, CISA KEV flag, published/updated dates, affected/fixed versions, workaround text (informational), links. | M |
| FR-VUL-05 | The system SHALL detect **End-of-Life / End-of-Support** hardware and software using a maintained EoL dataset (vendor bulletins, `endoflife.date` API where available) and raise findings. | M |
| FR-VUL-06 | The system SHALL detect default/weak configuration-exposed vulnerabilities from config (e.g., known default SNMP communities, default credentials present in config hashes where identifiable, insecure protocols) — implemented as checks, but surfaced in the vulnerability view with CWE tags. | M |
| FR-VUL-07 | Feed synchronisation SHALL be schedulable (default daily) with status, last-sync, record counts, and error surfacing. | M |
| FR-VUL-08 | For air-gapped deployments the system SHALL support offline import of NVD/CSAF/EoL bundles via file upload or CLI, with integrity check. | M |
| FR-VUL-09 | Users SHALL be able to mark vulnerabilities as: Open, In Progress, Risk Accepted (with expiry), Mitigated (with evidence note), False Positive (with justification). State changes are audited. | M |
| FR-VUL-10 | The system SHOULD provide a "What would fixing X upgrade eliminate?" view: for a device, list CVEs closed by upgrading to each candidate fixed release. | S |

### 3.11 Configuration history, drift and baselines (FR-DRIFT)

| ID | Requirement | Pri |
|---|---|---|
| FR-DRIFT-01 | Every collection SHALL store a configuration snapshot; identical configs (same hash, ignoring volatile lines such as timestamps/`ntp clock-period`) SHALL be de-duplicated with a pointer. | M |
| FR-DRIFT-02 | The system SHALL present a side-by-side and unified diff between any two snapshots, with redaction, and semantic diff over NCM (e.g., "rule 42 action changed allow→deny"). | M |
| FR-DRIFT-03 | Users SHALL be able to pin a snapshot as **Baseline** per device; subsequent collections that differ SHALL create a Drift finding (severity configurable) with the diff attached. | M |
| FR-DRIFT-04 | The system SHALL support "golden config" templates per platform (regex/line blocks that MUST/MUST NOT be present) as a check type. | S |
| FR-DRIFT-05 | Change events SHALL be correlatable to syslog/ITSM change tickets via free-text change reference on the drift finding. | C |

### 3.12 Scheduling and job management (FR-JOB)

| ID | Requirement | Pri |
|---|---|---|
| FR-JOB-01 | Users SHALL be able to run on-demand assessments for a device, group, tag selection or saved filter, choosing scope: Collect only, Collect + Assess, Assess only (re-run checks on latest snapshot), Vulnerability re-match only. | M |
| FR-JOB-02 | Schedules SHALL support cron expressions and presets (daily/weekly/monthly), maintenance windows/blackout periods, and time zone. | M |
| FR-JOB-03 | Jobs SHALL be pausable, cancellable (graceful — finish current device, no new sessions) and re-runnable for failed devices only. | M |
| FR-JOB-04 | Job history SHALL retain per-device outcomes, durations, error classes and links to artefacts. | M |
| FR-JOB-05 | The worker SHALL be horizontally scalable (multiple worker containers) with at-least-once task semantics and idempotent task handlers. | M |
| FR-JOB-06 | The system SHALL expose health/metrics endpoints (`/healthz`, `/readyz`, Prometheus `/metrics`) including queue depth, active sessions, collection success rate. | M |

### 3.13 Findings management (FR-FIND)

| ID | Requirement | Pri |
|---|---|---|
| FR-FIND-01 | Findings SHALL be de-duplicated by (device, check/CVE, key evidence) across runs with first-seen, last-seen, occurrence count and lifecycle status: New, Open, Reopened, Resolved (auto when check passes), Risk Accepted, False Positive. | M |
| FR-FIND-02 | Users SHALL be able to assign findings to users, add comments, attach files and set due dates. | M |
| FR-FIND-03 | Findings list SHALL support filtering/sorting by severity, status, vendor, group, check, framework control, age, assignee; bulk actions; saved views. | M |
| FR-FIND-04 | Each finding detail SHALL show description, rationale, evidence with config excerpt and provenance, remediation guidance (text only), references, history and related findings. | M |
| FR-FIND-05 | The system SHALL provide trend data (open findings by severity over time, MTTR, new vs resolved) per group/org. | M |

### 3.14 Dashboards and reporting (FR-RPT)

| ID | Requirement | Pri |
|---|---|---|
| FR-RPT-01 | Home dashboard SHALL show: overall risk score & trend, devices by vendor/class, findings by severity, top 10 riskiest devices, vulnerability summary (KEV, Critical, EoL), compliance % per policy/framework, recent job status, AAA posture summary, certificate expiry timeline. Widgets configurable per user. | M |
| FR-RPT-02 | Report templates SHALL include: Executive Summary, Device Detail (per device), Group/Site Compliance, Firewall Rulebase Review, Vulnerability Report, AAA/RADIUS/TACACS Review, Configuration Change (drift) Report, Exceptions Register, Trend Report. | M |
| FR-RPT-03 | Reports SHALL export to PDF, XLSX, CSV, JSON; PDF SHALL include cover, TOC, charts, and be brandable (logo, colours, classification label, prepared-by). | M |
| FR-RPT-04 | Reports SHALL be schedulable with e-mail delivery (password-protected ZIP option) and stored with retention policy. | M |
| FR-RPT-05 | Compliance view SHALL map check results to framework controls (CIS section, NIST 800-53 control id, PCI req id, ISO 27001 control, CERT-In/CEA clause) and show pass/fail/NA percentages per control. | M |

### 3.15 Notifications and integrations (FR-INT)

| ID | Requirement | Pri |
|---|---|---|
| FR-INT-01 | The system SHALL send notifications on: job completion/failure, new Critical/High findings, KEV vulnerability match, drift detected, host key/cert change, credential failure, feed sync failure, expiring exceptions. Channels: e-mail (SMTP/TLS), webhook (JSON, HMAC-signed), Slack/Teams incoming webhooks. | M |
| FR-INT-02 | The system SHALL forward findings and audit events to SIEM via syslog (RFC 5424, TLS) in CEF and JSON formats. | M |
| FR-INT-03 | The system SHOULD create/update tickets in ServiceNow and Jira for findings (configurable templates) and sync status back. | S |
| FR-INT-04 | The full REST API SHALL be available to service accounts with the same RBAC constraints; OpenAPI spec published at `/api/v1/openapi.json`. | M |

### 3.16 Audit and system administration (FR-AUD, FR-ADM)

| ID | Requirement | Pri |
|---|---|---|
| FR-AUD-01 | The system SHALL keep an append-only audit log of: logins/logouts/failures, user & role changes, credential create/update/delete/use, device changes, job start/stop, every command/API call sent to a device (device, command text, timestamp, result code — never the response body containing secrets), finding state changes, exceptions, settings changes, report generation/downloads. | M |
| FR-AUD-02 | Audit records SHALL be tamper-evident (hash chain) and exportable; retention configurable (default 2 years). | M |
| FR-ADM-01 | Super Admin SHALL manage: SMTP, syslog, proxy settings, feed sources, retention (snapshots, artefacts, jobs, reports), concurrency limits, session/security settings, branding, feature flags, licence info. | M |
| FR-ADM-02 | The system SHALL provide backup/restore guidance and a `netsecops-cli` for DB backup, key rotation, feed import, user reset, health checks. | M |

---

## 4. External interface requirements

### 4.1 User interface (React SPA)
- IF-UI-01: Responsive layout, left navigation (Dashboard, Inventory, Assessments/Jobs, Findings, Vulnerabilities, Firewall Analysis, AAA Posture, Compliance, Reports, Integrations, Administration).
- IF-UI-02: Accessibility WCAG 2.1 AA (keyboard navigation, ARIA, contrast). Light and dark themes via CSS variables.
- IF-UI-03: Data tables with server-side pagination, sort, filter, column chooser, CSV export.
- IF-UI-04: Config viewer with syntax highlighting, line numbers, search, redaction toggle (permission-gated), and jump-to-line from finding evidence.
- IF-UI-05: Diff viewer (side-by-side/unified) and rulebase viewer components.
- IF-UI-06: Live job console via WebSocket.
- IF-UI-07: All destructive actions require confirmation; forms use optimistic validation mirroring backend Pydantic schemas (generated TS types from OpenAPI via `openapi-typescript`).

### 4.2 REST API (FastAPI) — resource map (all under `/api/v1`)

| Resource | Methods | Notes |
|---|---|---|
| `/auth/login`, `/auth/refresh`, `/auth/logout`, `/auth/mfa/*`, `/auth/oidc/*` | POST/GET | |
| `/users`, `/roles`, `/api-tokens` | CRUD | Admin |
| `/devices`, `/devices/{id}`, `/devices/import`, `/devices/{id}/facts`, `/devices/{id}/snapshots`, `/devices/{id}/findings`, `/devices/{id}/neighbors` | CRUD/GET | |
| `/device-groups`, `/tags`, `/sites` | CRUD | |
| `/credentials`, `/credentials/{id}/test` | CRUD/POST | Secrets write-only |
| `/discovery/scopes`, `/discovery/runs`, `/discovery/pending` | CRUD/POST | |
| `/jobs`, `/jobs/{id}`, `/jobs/{id}/cancel`, `/jobs/{id}/rerun-failed`, `/schedules` | CRUD/POST | |
| `/snapshots/{id}`, `/snapshots/{id}/raw` (redacted by default, `?unredacted=true` permission-gated), `/snapshots/diff?a=&b=`, `/devices/{id}/baseline` | GET/PUT | |
| `/artifacts/{id}` | GET | |
| `/checks`, `/checks/{id}`, `/checks/validate`, `/checks/dry-run`, `/policies`, `/policies/{id}/assign` | CRUD/POST | |
| `/findings`, `/findings/{id}`, `/findings/bulk`, `/findings/{id}/comments`, `/exceptions` | CRUD/PATCH | |
| `/vulnerabilities`, `/vulnerabilities/{cve}`, `/vulnerabilities/feeds`, `/vulnerabilities/feeds/sync`, `/vulnerabilities/feeds/import` | GET/POST | |
| `/firewall/{device_id}/rulebase`, `/firewall/{device_id}/analysis`, `/firewall/{device_id}/query` | GET/POST | |
| `/aaa/posture`, `/aaa/servers`, `/aaa/correlation` | GET | |
| `/compliance/frameworks`, `/compliance/{framework}/summary` | GET | |
| `/reports/templates`, `/reports`, `/reports/{id}/download`, `/report-schedules` | CRUD/GET | |
| `/integrations/*`, `/settings/*`, `/audit-log`, `/healthz`, `/readyz`, `/metrics` | | |
| `/ws/jobs/{id}` | WebSocket | Job progress |

Conventions: JSON:API-like envelopes `{data, meta, errors}`; RFC 7807 problem details for errors; cursor pagination; ETags on snapshots; idempotency keys on job creation.

### 4.3 Device interfaces (protocols)
- SSH v2 only (no SSHv1, no telnet). Preferred KEX/ciphers modern; legacy ciphers enabled per device only when flagged (and this itself yields a finding).
- HTTPS APIs: TLS 1.2+; certificate verification per FR-COL-10.
- SNMP v2c/v3 GET only (discovery/fingerprint & optional inventory), never SET.
- Optional NETCONF/RESTCONF `get-config` (Cisco IOS-XE) — **C**ould.

### 4.4 Adapter interface (internal contract)

```python
class DeviceAdapter(Protocol):
    vendor: str                 # "cisco" | "paloalto" | "fortinet" | "checkpoint" | "linux"
    platform: str               # "ios" | "iosxe" | "nxos" | "asa" | "ftd_fmc" | "wlc_aireos" | "wlc_9800" | "ise" |
                                # "panos" | "panorama" | "fortios" | "fortimanager" | "fortiauthenticator" |
                                # "gaia" | "cp_mgmt" | "freeradius" | "tacplus"
    transport: Literal["ssh", "https", "hybrid"]
    supported_versions: VersionMatrix
    read_only_allowlist: CommandAllowList          # see Section 8

    async def probe(self, target, creds) -> ProbeResult          # login + trivial read
    async def collect(self, target, creds, profile) -> Collection # returns artefacts
    def parse(self, collection) -> NormalisedConfig              # NCM v1
    async def enumerate_children(self, target, creds) -> list[ChildDevice]  # managers only
```

Adapters live in `backend/netsecops/adapters/<vendor>/<platform>.py`; parsers in `backend/netsecops/parsers/<vendor>/`. Adding a vendor must not require changes outside these packages plus a registry entry.

---

## 5. Data requirements

### 5.1 Core entities (PostgreSQL 16)

| Table | Key columns (abridged) |
|---|---|
| `users`, `roles`, `user_roles`, `api_tokens`, `mfa_secrets` | standard; `api_tokens.hash`, scopes JSONB, expiry |
| `sites`, `device_groups` (ltree path), `tags`, `device_tags`, `device_group_members` | |
| `devices` | id, mgmt_ip inet, hostname, vendor, platform, device_class, criticality, site_id, owner_id, parent_device_id (manager), status, facts JSONB, last_collected_at, host_key_fingerprint, tls_cert_fingerprint, created/updated |
| `credentials` | id, name, type, encrypted_blob bytea, key_id, metadata JSONB, created_by, last_used_at, last_tested_at |
| `credential_assignments` | credential_id, device_id / group_id, priority |
| `discovery_scopes`, `discovery_runs`, `discovered_hosts` | fingerprint JSONB, confidence, status |
| `jobs` | id, type, scope JSONB, status, requested_by / schedule_id, started/finished, stats JSONB |
| `job_devices` | job_id, device_id, status, error_class, error_msg, started/finished, retries |
| `schedules` | cron, tz, scope, job_type, blackout JSONB, enabled |
| `collections` | id, job_device_id, device_id, adapter, adapter_version, started/finished, partial bool |
| `artifacts` | id, collection_id, kind (command/api), request_text, response_encrypted bytea, response_redacted text, sha256, size, duration_ms, ordinal |
| `snapshots` | id, device_id, collection_id, config_hash, normalized_hash, ncm JSONB (jsonb_path_ops GIN), raw_config_ref, is_baseline, created_at |
| `checks` | id (string, e.g. `CISCO-IOS-SSH-001`), version, yaml JSONB, severity_default, vendor, platform, applicability JSONB, frameworks JSONB, builtin bool, enabled |
| `policies`, `policy_checks` (severity override, enabled), `policy_assignments` (group_id) | |
| `check_results` | id, snapshot_id, check_id, check_version, result, evidence JSONB |
| `findings` | id, device_id, kind (config/vuln/drift/hostkey), check_id / cve_id, fingerprint (unique per device), severity, status, first_seen, last_seen, occurrences, assignee_id, due_at, risk_score_contrib |
| `finding_comments`, `finding_attachments`, `exceptions` (scope, justification, approver, expires_at) | |
| `vuln_cves` | cve_id, cvss31 JSONB, cvss40 JSONB, epss, kev bool, published, modified, description, cwe[] , refs JSONB |
| `vuln_advisories` | vendor, advisory_id, cve_ids[], affected JSONB (version ranges, conditions), fixed JSONB, csaf JSONB, url |
| `vuln_matches` | device_id, snapshot_id, cve_id, advisory_id, confidence, reasoning JSONB, status |
| `eol_records` | vendor, product, version/model, eos_date, eol_date, source |
| `feed_syncs` | feed, started/finished, status, counts, error |
| `reports`, `report_schedules`, `report_templates` | file_ref, params JSONB, classification |
| `integrations`, `notification_rules`, `notification_log` | |
| `audit_log` | id bigserial, ts, actor_id/token_id, action, object_type, object_id, details JSONB, ip, prev_hash, hash |
| `settings` | key, value JSONB, updated_by |

### 5.2 Data rules
- DATA-01: Secrets only in `credentials.encrypted_blob` and `artifacts.response_encrypted`; both AES-256-GCM with AAD = row id.
- DATA-02: Retention jobs purge artefacts/snapshots/jobs per settings but never findings history or audit log (audit archived instead).
- DATA-03: All timestamps `timestamptz` UTC. IPs as `inet`. Config text stored compressed (`pglz` default; consider `lz4` toast).
- DATA-04: Multi-tenancy is out of scope for v1.0 but every table carries `org_id` (default 1) to avoid a future rewrite.

---

## 6. Non-functional requirements

| ID | Requirement |
|---|---|
| NFR-PERF-01 | Assess 500 devices (mixed) in ≤ 60 minutes with 20 workers on the reference hardware; 2,000 devices in ≤ 4 hours with horizontal scaling. |
| NFR-PERF-02 | UI list/detail API p95 ≤ 500 ms for 10k findings; dashboards use materialised views refreshed after each job. |
| NFR-PERF-03 | Rule analysis (FR-FW-03) for a 5,000-rule rulebase ≤ 2 minutes. |
| NFR-SCALE-01 | Stateless API and workers; scale by replicas. Single PostgreSQL primary with optional read replica for reporting. |
| NFR-AVAIL-01 | Target 99.5% availability; graceful degradation when feeds/integrations are down. |
| NFR-REL-01 | Job engine survives worker crash: in-flight device tasks re-queued; no duplicate sessions to a device. |
| NFR-MAINT-01 | ≥ 85% backend line coverage overall; parsers ≥ 90%; typed end-to-end; ADRs in `docs/adr/`. |
| NFR-PORT-01 | Runs in Docker Compose (single host) and Kubernetes (Helm); no host-OS specific dependencies. |
| NFR-USAB-01 | A new analyst can onboard a device and read its first findings within 10 minutes using in-app guidance. |
| NFR-I18N-01 | UI strings externalised (English v1.0); dates shown in user time zone. |
| NFR-LOG-01 | Structured JSON logs (`structlog`), correlation ids across API→job→device; secrets scrubbed by a central filter. |
| NFR-OBS-01 | Prometheus metrics + OpenTelemetry traces (optional exporter). |

---

## 7. Security requirements for the NetSecOps application itself

| ID | Requirement |
|---|---|
| SEC-01 | Conform to OWASP ASVS 4.0 Level 2. Include ZAP/Nuclei baseline scan in CI. |
| SEC-02 | TLS 1.2+ only on the web tier (reverse proxy: Caddy/Nginx in `deploy/`); HSTS, CSP (no inline scripts), X-Frame-Options DENY, Referrer-Policy strict. |
| SEC-03 | CSRF protection for cookie-based sessions (double-submit token); SameSite=Strict. |
| SEC-04 | Input validation via Pydantic for every endpoint; output encoding in React; parameterised queries only; no raw SQL string formatting. |
| SEC-05 | Rate limiting on auth and expensive endpoints; request size limits; upload type/size validation with content sniffing. |
| SEC-06 | Least-privilege DB role for app (no superuser); separate migration role. |
| SEC-07 | Dependency scanning (`pip-audit`, `npm audit`, Trivy on images) in CI; SBOM (CycloneDX) generated per release. |
| SEC-08 | Secrets never in repo/images; `.env.example` only; runtime via env/secret mounts. |
| SEC-09 | Unredacted config view and artefact download require an explicit permission (`config:view_unredacted`) and are audited. |
| SEC-10 | Worker containers run as non-root, read-only root filesystem, minimal egress (device networks + feed endpoints). |
| SEC-11 | Security headers, cookies and auth flows covered by automated tests. |

---

## 8. Read-only guarantee (hard constraint)

### 8.1 Principles
1. **Allow-list, not deny-list.** Every adapter declares the exact set of commands / API operations it may issue. Anything not on the list is rejected before transmission (`ReadOnlyViolation` exception → collection aborted → critical internal finding + alert).
2. **Defence in depth with a deny-list.** A global regex deny-list additionally blocks obvious write verbs even if an allow-list entry is mis-specified: `^(conf(igure)?( t(erminal)?)?|write|wr|copy|reload|erase|delete|format|install|upgrade|set |unset |edit |commit|rollback|clear |debug |monitor |request |test |ping|traceroute|exec |execute |diagnose (?!sys|hardware)|no |shutdown|boot|end$)` (platform-scoped; `set cli pager off`, `set cli scripting-mode on` on PAN-OS and `terminal length 0` are explicitly allowed exceptions because they affect only the CLI session).
3. **HTTP method restriction.** REST adapters may use `GET` only; POST is permitted solely for (a) authentication/login/logout/keepalive, (b) Check Point Management API `show-*` and `login/logout/publish-free` calls (the API is POST-only — the command name must start with `show-`, `login`, `logout`, `keepalive`), (c) FortiManager JSON-RPC with `method: "get"` only, (d) PAN-OS XML API with `type` ∈ {`keygen`, `op`(show commands only), `config` with `action=show`/`get`, `export` with `category=configuration`/`certificate` (public)}, (e) Cisco FMC/ISE token generation.
4. **Privilege.** Adapters SHALL use the least privilege that still yields the required data and SHALL document the recommended read-only account per platform in `docs/device-accounts.md`. Where a platform requires elevated mode for `show running-config` (Cisco `enable`), entering enable mode is allowed; entering configuration mode is not.
5. **No side effects.** Adapters SHALL NOT: send test packets from the device (`ping`, `test aaa`, `test radius`), trigger backups to external servers, initiate log exports that write files on the device, or use `debug`. Reading existing state only.
6. **Session hygiene.** Sessions are closed/logged out cleanly; API sessions (Check Point, PAN-OS keys) are discarded; no `publish`/`commit` ever.
7. **Verification.** The test suite SHALL include a **transcript replay test** for every adapter that asserts all emitted commands/API calls are on the allow-list; CI fails otherwise. A `netsecops-cli audit-commands` command prints the effective allow-list per adapter for customer review.
8. **Transparency.** Every command sent is recorded in the audit log (FR-AUD-01); the UI shows customers exactly what NetSecOps executed on each device.

### 8.2 Vendor read-only command / API matrix (initial allow-lists)

**Cisco IOS / IOS-XE (routers, switches, Catalyst 9800 WLC, IOS APs)**
`terminal length 0`, `terminal width 512`, `enable`, `show version`, `show running-config [all]`, `show inventory`, `show ip interface brief`, `show interfaces status`, `show interfaces description`, `show cdp neighbors detail`, `show lldp neighbors detail`, `show vlan brief`, `show spanning-tree summary`, `show ip route summary`, `show ip ssh`, `show ssh`, `show crypto key mypubkey rsa`, `show snmp community`, `show snmp user`, `show aaa servers`, `show tacacs`, `show radius server-group all`, `show ntp status`, `show ntp associations`, `show logging | include (Trap|Buffer|Logging to)`, `show users`, `show access-lists`, `show ip access-lists`, `show line`, `show clock`, `show archive`, `show ip http server status`, `show crypto pki certificates`, `show boot`, `show redundancy`, `show stackwise-virtual`, `show switch`, `show port-security`, `show ip dhcp snooping`, `show ip arp inspection`, `show errdisable recovery`, `show wireless summary`, `show wlan summary`, `show wlan all`, `show ap summary`, `show ap config general`, `show wireless profile policy summary`, `show aaa method-lists all`.

**Cisco NX-OS**
`terminal length 0`, `show version`, `show running-config [all]`, `show inventory`, `show interface brief`, `show cdp neighbors detail`, `show vlan brief`, `show vpc`, `show feature`, `show ssh server`, `show snmp community`, `show snmp user`, `show aaa authentication`, `show aaa authorization`, `show tacacs-server`, `show radius-server`, `show ntp peers`, `show logging server`, `show user-account`, `show role`, `show access-lists`, `show hardware`, `show system resources`.

**Cisco IOS-XR**
`terminal length 0`, `show version`, `show running-config`, `show inventory`, `show ipv4 interface brief`, `show ssh`, `show aaa`, `show tacacs`, `show radius`, `show ntp associations`, `show logging`, `show user`, `show install active summary`.

**Cisco ASA**
`terminal pager 0`, `enable`, `show version`, `show running-config [all]`, `show inventory`, `show interface ip brief`, `show nameif`, `show access-list`, `show nat`, `show ssh`, `show ssh sessions`, `show snmp-server statistics`, `show aaa-server`, `show ntp associations`, `show logging`, `show crypto ca certificates`, `show crypto ikev1 sa`, `show crypto ikev2 sa`, `show failover`, `show context`, `show local-host` (bounded), `show run access-group`, `show run object`, `show run object-group`, `show run service-policy`, `show run policy-map`, `show run class-map`, `show run http`, `show run ssh`, `show run username`.

**Cisco FTD via FMC REST API (GET only)**
`POST /api/fmc_platform/v1/auth/generatetoken` (auth only), `GET /api/fmc_platform/v1/info/serverversion`, `GET /api/fmc_config/v1/domain/{uuid}/devices/devicerecords`, `.../policy/accesspolicies` + `/accessrules`, `.../policy/prefilterpolicies`, `.../policy/ftdnatpolicies`, `.../object/{networks,hosts,networkgroups,ports,portobjectgroups,urls,...}`, `.../policy/intrusionpolicies`, `.../policy/filepolicies`, `.../devices/devicerecords/{id}/{physicalinterfaces,routing/...}`, `.../object/realms`, `.../integration/...` (read). FDM (device-managed) MAY be supported via `GET /api/fdm/v6/...`.

**Cisco WLC AireOS**
`config paging disable` (session-only; allowed exception), `show sysinfo`, `show run-config` (full), `show run-config commands`, `show wlan summary`, `show wlan <id>`, `show ap summary`, `show ap config general <name>`, `show radius summary`, `show tacacs summary`, `show mgmtuser`, `show network summary`, `show snmpcommunity`, `show snmpv3user`, `show certificate summary`, `show rogue ap summary`, `show interface summary`, `show time`, `show logging`, `show local-auth config`, `show wps summary`.

**Cisco ISE (ERS + OpenAPI, GET only)**
`GET /ers/config/networkdevice`, `/ers/config/networkdevicegroup`, `/ers/config/adminuser`, `/ers/config/internaluser`, `/ers/config/identitygroup`, `/ers/config/idstoresequence`, `/ers/config/allowedprotocols`, `/ers/config/tacacscommandsets`, `/ers/config/tacacsprofile`, `/ers/config/tacacsexternalservers`, `/ers/config/radiusserversequence`, `/ers/config/certificatetemplate`, `/ers/config/portal`, `/ers/config/node`, `/api/v1/policy/network-access/policy-set` (+ authentication/authorization rules), `/api/v1/policy/device-admin/policy-set` (+ rules), `/api/v1/certs/system-certificate/{host}`, `/api/v1/certs/trusted-certificate`, `/api/v1/deployment/node`, `/api/v1/repository`, `/api/v1/system-settings/*`, `/api/v1/backup-restore/config/last-backup-status`, `/api/v1/patch`, `/api/v1/hotpatch`.

**Palo Alto PAN-OS / Panorama (XML API; REST API GET)**
`type=keygen` (auth), `type=op cmd=<show><system><info/></system></show>`, `<show><system><software><status/>...`, `<show><interface>all</interface></show>`, `<show><running><security-policy/></running></show>`, `<show><running><nat-policy/></running></show>`, `<show><high-availability><state/></high-availability></show>`, `<show><ntp/></show>`, `<show><config><running/></config></show>`, `<show><clock/></show>`, `<show><admins/></show>`, `<show><certificate>...` (list), `<show><devices><all/></devices></show>` (Panorama), `<request><license><info/></license></request>` (read-only despite `request` verb — explicit exception), `type=config action=show xpath=/config`, `type=config action=get xpath=...`, `type=export category=configuration`, `type=export category=certificate` (public only), `type=op cmd=<show><rule-hit-count>...` (if licensed). REST: `GET /restapi/v{ver}/Policies/SecurityRules`, `/Objects/*`, `/Network/*`, `/Device/*`.

**Fortinet FortiGate (REST API GET; SSH show/get)**
REST: `GET /api/v2/monitor/system/status`, `/monitor/system/ha-peer`, `/monitor/system/firmware`, `/monitor/system/config/backup?scope=global` (read of config), `/monitor/firewall/policy` (hit counts), `/monitor/wifi/managed_ap`, `/monitor/switch-controller/managed-switch`, `/cmdb/system/global`, `/cmdb/system/admin`, `/cmdb/system/accprofile`, `/cmdb/system/interface`, `/cmdb/system/ntp`, `/cmdb/system/snmp/*`, `/cmdb/log.syslogd/setting`, `/cmdb/firewall/policy`, `/cmdb/firewall/address`, `/cmdb/firewall/addrgrp`, `/cmdb/firewall.service/custom`, `/cmdb/firewall.service/group`, `/cmdb/firewall/vip`, `/cmdb/firewall/ippool`, `/cmdb/user/radius`, `/cmdb/user/tacacs+`, `/cmdb/user/ldap`, `/cmdb/user/local`, `/cmdb/user/group`, `/cmdb/system/password-policy`, `/cmdb/vpn.ipsec/phase1-interface`, `/cmdb/vpn.ipsec/phase2-interface`, `/cmdb/vpn.certificate/local`, `/cmdb/wireless-controller/vap`, `/cmdb/wireless-controller/wtp-profile`, `/cmdb/ips/sensor`, `/cmdb/antivirus/profile`, `/cmdb/webfilter/profile`, `/cmdb/dnsfilter/profile`, `/cmdb/firewall/ssl-ssh-profile`, `/cmdb/system/fortiguard`, `/cmdb/system/central-management`, `/cmdb/system/ha`. SSH: `config system console` is **not** allowed (it is config mode); use `show full-configuration`, `show`, `get system status`, `get system ha status`, `get system performance status`, `get system interface physical`, `get router info routing-table all`, `get user radius`, `get system admin list`, `diagnose sys top` (read, bounded) — and pass `| grep` never. Paging: the API is preferred; for SSH, the account's `set output standard` must be pre-set by the customer.

**Fortinet FortiManager (JSON-RPC, `method: "get"` only)**
`exec` is allowed **only** for `/sys/login/user` and `/sys/logout`. `get` on `/dvmdb/adom`, `/dvmdb/device`, `/pm/config/adom/{adom}/pkg`, `/pm/config/adom/{adom}/pkg/{pkg}/firewall/policy`, `/pm/config/adom/{adom}/obj/firewall/*`, `/cli/global/system/admin/user`, `/cli/global/system/global`.

**Fortinet FortiAuthenticator (REST GET)**
`GET /api/v1/radiusclients/`, `/api/v1/localusers/`, `/api/v1/usergroups/`, `/api/v1/ldapservers/`, `/api/v1/certificates/`, `/api/v1/system/`, `/api/v1/adminprofiles/`.

**Check Point Management Server / MDS (Management API, POST with `show-*` only)**
`login`, `logout`, `keepalive`, `show-api-versions`, `show-session`, `show-domains` (MDS), `show-gateways-and-servers`, `show-simple-gateways`, `show-simple-clusters`, `show-packages`, `show-access-layers`, `show-access-rulebase`, `show-nat-rulebase`, `show-threat-rulebase`, `show-https-rulebase`, `show-hosts`, `show-networks`, `show-groups`, `show-address-ranges`, `show-services-tcp`, `show-services-udp`, `show-service-groups`, `show-application-sites`, `show-vpn-communities-*`, `show-administrators`, `show-api-settings`, `show-radius-servers` / `show-tacacs-servers` (via `show-objects` type filter), `show-objects`, `show-unused-objects`, `show-changes`, `show-tasks`, `show-global-properties`, `show-trusted-clients`, `show-ips-protection-extended-attribute`, `show-threat-profiles`, `show-checkpoint-host`. Never `publish`, `install-policy`, `set-*`, `add-*`, `delete-*`, `run-script`.

**Check Point Gaia (gateway / management OS via SSH clish; Gaia REST API GET)**
`set clienv rows 0` (session-only exception), `show configuration`, `show version all`, `show asset all`, `show interfaces all`, `show hostname`, `show ntp servers`, `show snmp *`, `show aaa *`, `show user *`, `show users`, `show password-controls all`, `show syslog all`, `show clock`, `show route`, `show cluster state` (via `cphaprob state` in expert only if expert mode permitted — default **off**), `cpstat os -f all`, `cpinfo -y all`, `fw ver`, `fw stat`, `enabled_blades`, `cplic print`, `cpconfig` is **forbidden**, `expert` mode permitted only when device flag `allow_expert=true`, and then only whitelisted read commands (`cat $FWDIR/conf/fwauthd.conf`, `fw ctl pstat`, `cphaprob -a if`).

**Linux AAA hosts (FreeRADIUS / tac_plus) via SSH**
`cat`, `ls -la`, `stat`, `find <dir> -type f` restricted to `/etc/freeradius`, `/etc/raddb`, `/etc/tac_plus*`, `/etc/ssl`, `/etc/os-release`; `freeradius -v`, `radiusd -v`, `tac_plus -v`, `openssl x509 -in <path> -noout -text`, `systemctl is-active <svc>`, `ss -lntup`. No `sudo` unless `allow_sudo_read=true` (then `sudo -n cat ...` only).

---

## 9. Deployment

- `deploy/docker-compose.yml`: services `db` (postgres:16), `api`, `worker` (scaled), `scheduler`, `frontend` (static, served by `proxy`), `proxy` (Caddy with automatic TLS or provided certs), optional `vault`.
- `deploy/helm/netsecops/` chart with values for replicas, external DB, secrets, ingress.
- Single command bootstrap: `make up` → migrations → seed checks & frameworks → create initial admin (prompt) → print URL.
- Backups: `pg_dump` cron sidecar; document restore. Master key backup procedure emphasised.
- Upgrade path: Alembic migrations run on `api` start with advisory lock; check library seed is idempotent.

---

## 10. Testing and acceptance

| ID | Requirement |
|---|---|
| TEST-01 | Unit tests for all parsers using fixture corpus; property tests for the firewall set-algebra (shadowing/redundancy) using `hypothesis`. |
| TEST-02 | Adapter tests use recorded transcripts (SSH via `scrapli-replay`/fake server; HTTP via `respx`/`vcrpy`) — no live devices in CI. |
| TEST-03 | **Read-only conformance test**: for every adapter, every emitted command/request is asserted against allow-list and deny-list; build fails on violation. |
| TEST-04 | API contract tests generated from OpenAPI (`schemathesis`). |
| TEST-05 | Frontend: component tests (vitest/RTL) and Playwright E2E for onboarding → assess → finding → report happy path. |
| TEST-06 | Security tests: authz matrix (every endpoint × every role), secret-leak scan on logs/API responses, ZAP baseline. |
| TEST-07 | Performance test harness with a simulated device farm (containerised fake SSH/API endpoints) to validate NFR-PERF-01. |
| TEST-08 | Acceptance: v1.0 accepted when all M requirements have passing tests, coverage targets met, and a lab of at least one real device per platform in §1.3 (Cisco IOS-XE switch, ASA, WLC, ISE; PAN-OS; FortiGate; Check Point Gaia+SMS) completes Collect+Assess with zero read-only violations and zero config changes verified by pre/post config hash on the device. |

---

## 11. Repository layout (target)

```
netsecops/
├─ backend/
│  ├─ netsecops/
│  │  ├─ api/            # FastAPI routers, deps, schemas (pydantic)
│  │  ├─ core/           # config, security, crypto (envelope), logging, rbac
│  │  ├─ db/             # models, session, alembic/
│  │  ├─ services/       # inventory, credentials, jobs, findings, reports, vuln, compliance
│  │  ├─ adapters/       # cisco/, paloalto/, fortinet/, checkpoint/, linux/, base.py, registry.py, readonly.py
│  │  ├─ parsers/        # per vendor → NCM
│  │  ├─ ncm/            # schema, models, provenance
│  │  ├─ checks/         # engine, loaders, builtin python checks, firewall/ (set algebra)
│  │  ├─ vuln/           # nvd, csaf, cisco_psirt, panw, fortinet, checkpoint, eol, matcher
│  │  ├─ workers/        # task definitions (procrastinate), scheduler
│  │  ├─ integrations/   # smtp, webhook, syslog_cef, slack, teams, servicenow, jira
│  │  └─ cli.py
│  ├─ checks/            # YAML check library (common/, cisco/, paloalto/, fortinet/, checkpoint/)
│  ├─ frameworks/        # control mappings (cis, nist80053, pci, iso27001, certin, cea)
│  ├─ schemas/ncm/v1.json
│  ├─ tests/             # unit, integration, fixtures/, transcripts/
│  └─ pyproject.toml
├─ frontend/             # Vite + React + TS, src/{app,features,components,api(generated),styles}
├─ deploy/               # docker-compose.yml, Dockerfiles, helm/, caddy/
├─ docs/                 # SRS.md (this), adr/, vendor-notes/, device-accounts.md, deployment.md, api.md
└─ Makefile
```

---

## 12. Development phases (execution plan for the coding agent)

> **Ordering departure, recorded 2026-09-15.** Phase 7 was started at the product
> owner's direction while Phase 6 was still open, so §0's "no phase starts before the
> previous one's acceptance criteria pass" does not hold for this pair. Phase 6 stands
> at version parsing, CPE construction, operational-artefact collection and CSAF
> ingestion on `phase-6-vulnerability`; its acceptance criterion — known-vulnerable
> fixture versions producing expected CVEs — is **not** met, and the feature-aware
> matcher, NVD/EoL ingestion, feed sync and vulnerability UI are outstanding. Phase 7
> work begins with discovery, which does not depend on any of that. Reporting's
> vulnerability templates and the TEST-08 acceptance do, and cannot close until Phase 6
> does.

**Phase 0 — Foundation (week 1–2)**
Monorepo scaffold; FastAPI app with health, settings, structured logging; PostgreSQL + Alembic; users/roles/JWT/MFA; RBAC middleware; audit log; React shell with auth flow; CI (lint, type, test, security scans); Docker Compose. *Acceptance:* login/MFA works, authz matrix tests pass, `make up` boots.

**Phase 1 — Inventory, credentials, jobs (week 3–4)**
Devices/groups/tags/sites CRUD + CSV import; credential vault with envelope encryption + external KMS abstraction; job engine (Procrastinate) with scheduler, cancel, retries, WebSocket progress; read-only enforcement framework (`readonly.py`, allow/deny lists, conformance test harness). *Acceptance:* create device → test credential (against fake SSH server) → job history recorded → audit shows commands.

**Phase 2 — Cisco IOS/IOS-XE + NX-OS + ASA collection & parsing (week 5–7)**
Adapters, parsers → NCM v1, fixture corpus, redaction, snapshots, diff, baselines/drift. *Acceptance:* parser coverage ≥90%; drift finding generated on changed fixture.

**Phase 3 — Check engine + baseline library (week 8–10)**
YAML engine, Python checks, policies, frameworks mapping, exceptions, findings lifecycle, risk score; ≥60 Cisco checks + common checks; findings UI. *Acceptance:* CIS Cisco IOS L1 policy runs end-to-end with evidence and line provenance.

**Phase 4 — Palo Alto, Fortinet, Check Point firewalls + firewall analysis (week 11–15)**
PAN-OS/Panorama, FortiGate/FortiManager, Check Point Mgmt/Gaia adapters & parsers; manager child enumeration; rulebase normalisation; shadow/redundancy/any-any/no-log/no-profile analysis; rulebase viewer; ≥90 vendor checks added. *Acceptance:* 5,000-rule synthetic rulebase analysed ≤2 min; property tests pass.

**Phase 5 — Wireless + AAA (week 16–18)**
WLC AireOS, Catalyst 9800 wireless parsing, FortiGate WLC; Cisco ISE, FortiAuthenticator, FreeRADIUS/tac_plus adapters; AAA correlation & posture dashboard; wireless & AAA checks. *Acceptance:* AAA coverage report correct against fixture lab.

**Phase 6 — Vulnerability assessment (week 19–21)**
NVD/CSAF/PSIRT/EoL ingestion (online + offline import), CPE builder, feature-aware matcher, KEV/EPSS, vuln UI & states. *Acceptance:* known-vulnerable fixture versions produce expected CVEs with correct confidence.

**Phase 7 — Discovery, reporting, integrations, hardening (week 22–25)**
Discovery & fingerprinting; PDF/XLSX reports & scheduling; dashboards; SMTP/webhook/Slack/Teams/syslog-CEF; ServiceNow/Jira (S); Helm chart; performance harness; ASVS review; docs. *Acceptance:* TEST-08.

**Phase 8 — Topology and path analysis (added 2026-09-18)**
Forwarding-table normalisation into the NCM; the layer-3 graph; path query with the
two-axis result; the ranked missing-device report; API and console surface. Covers
FR-TOPO-01 … FR-TOPO-07. *Acceptance:* over a fixture estate of five devices, a path
query across three of them returns the correct traversed-device list and rule verdicts,
and a query whose next hop is not in inventory returns `unknown` naming that next hop
rather than `unreachable`.

> **Scope departure, recorded 2026-09-18.** This phase was not in the SRS as issued.
> It was added at the product owner's direction after a competitive analysis, on the
> finding that multi-device reasoning is the one capability separating this product
> from the established tools in its category. Phase 7 is not closed when Phase 8
> begins: scheduling (FR-DISC-05's second half, FR-JOB-02, FR-RPT-04) and the whole of
> integrations (FR-INT-01/02/03) remain open, so §0's ordering rule does not hold for
> this pair either. Phase 8 depends on neither — it builds on Phase 2 parsing and the
> Phase 4 rule query, both of which are complete.

---

## Appendix A — NCM v1 (abridged JSON Schema outline)

```json
{
  "ncm_version": "1.0",
  "device": {"vendor": "", "platform": "", "version": "", "model": "", "serials": [], "hostname": "", "uptime_s": 0, "ha": {"enabled": false, "role": "", "peer": ""}},
  "management": {"services": {"ssh": {"enabled": true, "version": 2, "ciphers": [], "kex": [], "macs": [], "timeout_s": 0, "acl": ""}, "telnet": {"enabled": false}, "http": {"enabled": false}, "https": {"enabled": true, "tls_versions": [], "ciphers": [], "acl": ""}, "snmp": {}, "netconf": {}, "restconf": {}}, "banners": {"login": "", "motd": "", "exec": ""}, "session": {"exec_timeout_s": 0, "console_timeout_s": 0}, "password_policy": {}},
  "users": [{"name": "", "privilege": 0, "secret_type": "", "weak_hash": false, "ssh_keys": [], "role": ""}],
  "aaa": {"new_model": true, "authentication": [], "authorization": [], "accounting": [], "servers": [{"type": "tacacs|radius", "host": "", "auth_port": 0, "acct_port": 0, "key_configured": true, "key_type": "", "timeout_s": 0, "source_interface": "", "group": ""}], "local_fallback": true, "radsec": false},
  "logging": {"syslog_servers": [], "level": "", "buffered": {}, "timestamps": "", "source_interface": ""},
  "ntp": {"servers": [], "authenticated": false},
  "snmp": {"v1v2c_communities": [{"name_masked": "", "acl": "", "rw": false}], "v3_users": [{"name": "", "level": "noAuthNoPriv|authNoPriv|authPriv", "auth": "", "priv": ""}], "traps": []},
  "interfaces": [], "l2": {}, "routing": {}, "acls": [],
  "firewall": {"zones": [], "address_objects": [], "address_groups": [], "service_objects": [], "service_groups": [], "security_rules": [{"order": 0, "name": "", "enabled": true, "src_zones": [], "src": [], "dst_zones": [], "dst": [], "services": [], "applications": [], "users": [], "action": "allow|deny|drop|reset", "log_start": false, "log_end": false, "profiles": {}, "schedule": "", "hit_count": null, "last_hit": null, "provenance": {}}], "nat_rules": [], "profiles": {}},
  "vpn": {"ike": [], "ipsec": []},
  "wireless": {"wlans": [{"ssid": "", "security": "open|wpa2-psk|wpa2-ent|wpa3-sae|wpa3-ent|owe", "pmf": "", "ft": false, "radius_group": "", "broadcast": true, "client_isolation": false}], "aps": [], "rogue_detection": {}},
  "certificates": [{"name": "", "subject": "", "issuer": "", "not_after": "", "key_bits": 0, "sig_alg": "", "self_signed": false, "usage": []}],
  "features": {"http_server": false, "cdp": true, "lldp": true, "ip_source_routing": false, "smart_install": false, "...": ""},
  "raw_unparsed": []
}
```

## Appendix B — Baseline check library scope (v1.0 minimum)

| Area | Examples (all vendors unless noted) |
|---|---|
| Management plane | Telnet/HTTP disabled; SSHv2 only; weak SSH ciphers/KEX/MAC; TLS <1.2; management ACL present; exec/console timeouts; login banner; SNMPv1/v2c present, default/weak communities, RW communities, SNMPv3 not authPriv; NETCONF/RESTCONF exposure |
| Accounts & passwords | Local users beyond break-glass; Cisco type 0/7 secrets; `service password-encryption` missing; `enable password` vs `enable secret`; password policy; default usernames (admin/cisco); PAN-OS admin without role/profile; FortiOS admin trusthosts missing; Check Point administrators without expiry |
| AAA | Per FR-AAA-01 list; ISE allowed protocols weak; tac_plus/FreeRADIUS PAP/CHAP/EAP-MD5; cert expiry <30/90 days |
| Logging & time | No syslog server; logging level too low/high; no timestamps; buffered logging off; no NTP / unauthenticated NTP; wrong time zone/clock |
| Control plane hardening (Cisco) | CDP/LLDP on untrusted ports; IP source routing; directed broadcast; proxy-ARP; ICMP redirects/unreachables; Smart Install; `no ip domain-lookup`; BOOTP server; TCP/UDP small servers; finger; PAD; unused interfaces not shutdown; native VLAN 1; DTP auto; port-security/BPDU guard/DHCP snooping/DAI absence on access ports; routing protocol authentication (OSPF/EIGRP/BGP MD5/keychain); VTP without password |
| Firewall policy | Per FR-FW-02/03/05; decryption profile weaknesses; default deny at end; intrazone default; logging to external; security profile groups missing; PAN-OS `application any` with `service any`; FortiOS policies with `all/all/ALL`; Check Point cleanup rule missing / stealth rule missing |
| VPN | IKEv1 aggressive mode; DH groups <14; 3DES/MD5/SHA1; PSK; weak PFS |
| Wireless | Open/WEP/WPA1/WPA2-TKIP SSIDs; PSK on enterprise SSID; PMF disabled; no client isolation on guest; management over wireless; rogue AP detection off; default SSID names; WLC HTTP mgmt; AP console/telnet enabled; broadcast SSID on hidden-intent networks |
| Certificates | Self-signed on management/EAP; expiring/expired; RSA <2048; SHA-1 |
| Version & lifecycle | EoS/EoL hardware/software; unsupported major release; HA version mismatch |
| Vendor-specific | PAN-OS: master key default, `api key lifetime`, min password complexity, `syslog to Panorama`; FortiOS: `admin-sport 443` default, `strong-crypto` off, `admin-lockout`, FortiGuard anycast, `set admin-https-redirect`; Check Point: implied rules logging, `fw ctl multik`, SIC status, Gaia password-controls, expert password set; Cisco WLC: WebAuth cert, `config network secureweb`, CAPWAP AP auth, `config network rf-network-name` default; ISE: admin session timeout, MFA, repository credentials, PxGrid TLS |

## Appendix C — Environment variables (abridged)

`NETSECOPS_ENV`, `DATABASE_URL`, `SECRET_KEY` (JWT), `MASTER_KEY_PROVIDER` (`env|file|vault|awskms|azurekv|gcpkms`), `MASTER_KEY`/`MASTER_KEY_PATH`/`VAULT_ADDR`/`VAULT_TOKEN`/..., `WORKER_CONCURRENCY`, `DEVICE_CONNECT_TIMEOUT`, `DEVICE_COMMAND_TIMEOUT`, `ALLOW_LEGACY_SSH_CIPHERS` (default false), `FEEDS_OFFLINE_MODE`, `NVD_API_KEY`, `CISCO_PSIRT_CLIENT_ID/SECRET`, `SMTP_*`, `SYSLOG_*`, `CORS_ORIGINS`, `LOG_LEVEL`.

## Appendix D — Open questions to resolve before Phase 4

**All five are resolved as of 2026-09-13.** Answers are recorded here as they were given,
with the original question kept alongside each so this reads as a decision history rather
than a to-do list. The reasoning for anything non-obvious is in the linked ADR.

1. ~~Confirm licensing/availability of Cisco PSIRT openVuln API credentials for the deployment.~~
   **Resolved 2026-09-13.** Credentials will be obtained from the Cisco API Console as a
   Service application using the Client Credentials grant. `CISCO_PSIRT_CLIENT_ID` and
   `CISCO_PSIRT_CLIENT_SECRET` are wired through `.env`, compose and `Settings`; both
   remain optional so an air-gapped installation still runs from imported bundles
   (FR-VUL-08). Consumed in Phase 6.
2. ~~Confirm whether expert-mode read access on Check Point Gaia will be permitted (default off).~~
   **Resolved 2026-09-13: permitted, per-device opt-in.** See
   [ADR-002](adr/ADR-002-checkpoint-expert-mode.md). `allow_expert` stays false until an
   operator sets it on a named device.
3. ~~Decide on Procrastinate vs Celery/Redis after Phase 1 load test (ADR-001).~~
   **Resolved 2026-09-13: Procrastinate, confirmed by measurement.** The load test
   ([ADR-001](adr/ADR-001-job-queue.md), `pytest -m performance`) measured 20 workers
   sustaining ~14 device-claims per second against the 0.139/s NFR-PERF-01 implies —
   about 100× headroom, with queue coordination consuming roughly 1% of the 60-minute
   budget for 500 devices. The remaining 99% is SSH, which no queue choice affects.
4. ~~Confirm branding/report classification labels and which regulatory framework packs ship enabled by default.~~
   **Resolved 2026-09-13.** See
   [ADR-004](adr/ADR-004-report-branding-and-default-frameworks.md): reports carry a
   configurable classification banner defaulting to `CONFIDENTIAL`; the customer's name
   and logo appear alongside the product's rather than replacing it, because a report is
   evidence and evidence should name its source; CIS ships enabled, with NIST 800-53,
   PCI DSS and ISO 27001 mapped but not enabled.
5. ~~Confirm whether FortiSwitch/FortiAP data should be pulled via the parent FortiGate only (default) or also directly.~~
   **Resolved 2026-09-13: via the parent FortiGate only.** See
   [ADR-003](adr/ADR-003-fortiswitch-fortiap-collection.md). NetSecOps stores no
   credential for a managed unit and never opens a session to one.

---
*End of document.*
