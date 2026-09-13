"""Normalised Config Model v1 (FR-PARSE-01, FR-PARSE-02, SRS Appendix A).

The NCM is the vendor-neutral shape every parser targets and every check reads. Its
whole purpose is that a check like "is Telnet enabled?" is written once, not once per
vendor — so the model describes *what a device does*, never how a particular vendor
spells it.

Two design points worth stating:

**Provenance is separate, not embedded.** FR-PARSE-04 requires every field to be
traceable back to the configuration lines it came from. Wrapping each value in a
``{value, provenance}`` object would make the model unreadable and every check more
verbose. Instead a parallel :class:`ProvenanceMap` is keyed by JSON path, so a finding
can say "line 412 of artefact X" without the model paying for it.

**Absent is not the same as false.** A field left ``None`` means the parser did not
find the information, and a check must report *Not Evaluated* rather than *Fail*
(FR-CHK-03). Booleans that genuinely default on a platform are set explicitly by the
parser, so the distinction survives.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

NCM_VERSION = "1.0"


class NcmBase(BaseModel):
    """Shared config: unknown keys are rejected so a parser typo fails loudly."""

    model_config = ConfigDict(extra="forbid")


# ──────────────────────────────── provenance ────────────────────────────────


class Provenance(NcmBase):
    """Where one NCM value came from (FR-PARSE-04)."""

    #: The artefact (raw command output) the value was parsed from.
    artifact_id: str | None = None
    #: The command that produced that artefact, for display without a lookup.
    command: str | None = None
    #: 1-based, inclusive. Operators count configuration lines from one.
    line_start: int | None = None
    line_end: int | None = None
    #: The configuration text itself, so a finding can show the offending lines
    #: without re-fetching the artefact. Redacted before display (FR-COL-13).
    excerpt: str | None = None

    @property
    def line_range(self) -> str:
        if self.line_start is None:
            return ""
        if self.line_end is None or self.line_end == self.line_start:
            return str(self.line_start)
        return f"{self.line_start}-{self.line_end}"


class ProvenanceMap(NcmBase):
    """JSON path → provenance, e.g. ``management.services.ssh.version``."""

    entries: dict[str, Provenance] = Field(default_factory=dict)

    def record(self, path: str, provenance: Provenance) -> None:
        self.entries[path] = provenance

    def get(self, path: str) -> Provenance | None:
        return self.entries.get(path)


# ──────────────────────────────── system ────────────────────────────────────


class HighAvailability(NcmBase):
    enabled: bool | None = None
    role: str | None = None
    peer: str | None = None
    #: HA pairs running different releases are a real and common finding.
    peer_version: str | None = None


class DeviceFacts(NcmBase):
    vendor: str = ""
    platform: str = ""
    version: str | None = None
    model: str | None = None
    serials: list[str] = Field(default_factory=list)
    hostname: str | None = None
    domain_name: str | None = None
    uptime_s: int | None = None
    ha: HighAvailability = Field(default_factory=HighAvailability)


# ────────────────────────────── management ──────────────────────────────────


class SshConfig(NcmBase):
    enabled: bool | None = None
    version: int | None = None
    ciphers: list[str] = Field(default_factory=list)
    kex: list[str] = Field(default_factory=list)
    macs: list[str] = Field(default_factory=list)
    timeout_s: int | None = None
    authentication_retries: int | None = None
    #: Access class restricting which sources may connect.
    acl: str | None = None
    #: Key size matters: a 768-bit RSA host key is a finding on its own.
    host_key_bits: int | None = None


class ServiceState(NcmBase):
    enabled: bool | None = None
    port: int | None = None
    acl: str | None = None


class HttpsConfig(ServiceState):
    tls_versions: list[str] = Field(default_factory=list)
    ciphers: list[str] = Field(default_factory=list)
    #: True when plain HTTP redirects to HTTPS rather than serving.
    redirect_from_http: bool | None = None


class ManagementServices(NcmBase):
    ssh: SshConfig = Field(default_factory=SshConfig)
    telnet: ServiceState = Field(default_factory=ServiceState)
    http: ServiceState = Field(default_factory=ServiceState)
    https: HttpsConfig = Field(default_factory=HttpsConfig)
    snmp: ServiceState = Field(default_factory=ServiceState)
    netconf: ServiceState = Field(default_factory=ServiceState)
    restconf: ServiceState = Field(default_factory=ServiceState)


class Banners(NcmBase):
    login: str | None = None
    motd: str | None = None
    exec: str | None = None


class SessionLimits(NcmBase):
    exec_timeout_s: int | None = None
    console_timeout_s: int | None = None
    #: Concurrent session cap, where the platform supports one.
    max_sessions: int | None = None


class PasswordPolicy(NcmBase):
    min_length: int | None = None
    complexity_required: bool | None = None
    max_age_days: int | None = None
    history: int | None = None
    lockout_threshold: int | None = None
    #: IOS `service password-encryption`. Type 7 is reversible, so this is weak
    #: obfuscation rather than encryption — but its absence is worse.
    encryption_enabled: bool | None = None


class Management(NcmBase):
    services: ManagementServices = Field(default_factory=ManagementServices)
    banners: Banners = Field(default_factory=Banners)
    session: SessionLimits = Field(default_factory=SessionLimits)
    password_policy: PasswordPolicy = Field(default_factory=PasswordPolicy)
    #: Named ACLs applied to management access, by service.
    management_acls: dict[str, str] = Field(default_factory=dict)


# ─────────────────────────────── identity ───────────────────────────────────


class LocalUser(NcmBase):
    name: str
    privilege: int | None = None
    #: Cisco secret types: 0 plaintext, 7 reversible, 5 MD5, 8 PBKDF2, 9 scrypt.
    secret_type: str | None = None
    #: True for storage that is plaintext or trivially reversible.
    weak_hash: bool | None = None
    ssh_keys: list[str] = Field(default_factory=list)
    role: str | None = None


class AaaServer(NcmBase):
    type: Literal["tacacs", "radius", "ldap", "unknown"] = "unknown"
    host: str
    auth_port: int | None = None
    acct_port: int | None = None
    #: Whether a shared secret is configured — never the secret itself (C-2).
    key_configured: bool | None = None
    key_type: str | None = None
    timeout_s: int | None = None
    source_interface: str | None = None
    group: str | None = None
    #: RadSec / TACACS-over-TLS, where supported.
    tls: bool | None = None


class AaaMethodList(NcmBase):
    name: str
    purpose: str
    methods: list[str] = Field(default_factory=list)

    @property
    def falls_back_to_local(self) -> bool:
        return any(m.startswith("local") for m in self.methods)

    @property
    def uses_none(self) -> bool:
        """`none` as a method means authentication can be skipped entirely."""
        return "none" in self.methods


class Aaa(NcmBase):
    new_model: bool | None = None
    authentication: list[AaaMethodList] = Field(default_factory=list)
    authorization: list[AaaMethodList] = Field(default_factory=list)
    accounting: list[AaaMethodList] = Field(default_factory=list)
    servers: list[AaaServer] = Field(default_factory=list)
    local_fallback: bool | None = None
    radsec: bool | None = None


# ───────────────────────── logging, time, SNMP ──────────────────────────────


class SyslogServer(NcmBase):
    host: str
    port: int | None = None
    transport: str | None = None
    facility: str | None = None
    severity: str | None = None


class BufferedLogging(NcmBase):
    enabled: bool | None = None
    size_bytes: int | None = None
    severity: str | None = None


class Logging(NcmBase):
    syslog_servers: list[SyslogServer] = Field(default_factory=list)
    level: str | None = None
    buffered: BufferedLogging = Field(default_factory=BufferedLogging)
    console_severity: str | None = None
    #: Without timestamps a log is much harder to correlate during an incident.
    timestamps: str | None = None
    source_interface: str | None = None
    #: IOS `archive log config` — records who changed what on the device.
    config_change_logging: bool | None = None


class NtpServer(NcmBase):
    host: str
    authenticated: bool | None = None
    key_id: int | None = None
    prefer: bool | None = None


class Ntp(NcmBase):
    servers: list[NtpServer] = Field(default_factory=list)
    authenticated: bool | None = None
    source_interface: str | None = None
    timezone: str | None = None


class SnmpCommunity(NcmBase):
    #: The community string is a credential, so only a masked form is ever stored.
    name_masked: str
    #: True when the string matches a well-known default such as public/private.
    is_default: bool | None = None
    rw: bool | None = None
    acl: str | None = None
    view: str | None = None


class SnmpV3User(NcmBase):
    name: str
    level: Literal["noAuthNoPriv", "authNoPriv", "authPriv", "unknown"] = "unknown"
    auth: str | None = None
    priv: str | None = None
    group: str | None = None


class SnmpTrapTarget(NcmBase):
    host: str
    version: str | None = None
    traps: list[str] = Field(default_factory=list)


class Snmp(NcmBase):
    v1v2c_communities: list[SnmpCommunity] = Field(default_factory=list)
    v3_users: list[SnmpV3User] = Field(default_factory=list)
    traps: list[SnmpTrapTarget] = Field(default_factory=list)
    #: Explicitly recorded: "no v1/v2c configured" is a pass, "not parsed" is not.
    v1v2c_enabled: bool | None = None
    location: str | None = None
    contact: str | None = None


# ───────────────────────── interfaces and layer 2 ───────────────────────────


class InterfaceSecurity(NcmBase):
    """Access-port protections. Absence on a user-facing port is the finding."""

    port_security: bool | None = None
    port_security_max: int | None = None
    bpduguard: bool | None = None
    bpdufilter: bool | None = None
    root_guard: bool | None = None
    dhcp_snooping_trust: bool | None = None
    arp_inspection_trust: bool | None = None
    storm_control: bool | None = None
    ip_source_guard: bool | None = None
    dot1x: bool | None = None


class Interface(NcmBase):
    name: str
    description: str | None = None
    admin_up: bool | None = None
    oper_up: bool | None = None
    ip_addresses: list[str] = Field(default_factory=list)
    vlan: int | None = None
    mode: str | None = None
    #: Dynamic trunking on a user port lets an attacker negotiate a trunk.
    dtp_mode: str | None = None
    native_vlan: int | None = None
    is_management: bool | None = None
    zone: str | None = None
    security: InterfaceSecurity = Field(default_factory=InterfaceSecurity)
    #: Per-interface control-plane settings that are findings when left on.
    proxy_arp: bool | None = None
    ip_redirects: bool | None = None
    ip_unreachables: bool | None = None
    directed_broadcast: bool | None = None


class Vlan(NcmBase):
    id: int
    name: str | None = None
    active: bool | None = None


class SpanningTree(NcmBase):
    mode: str | None = None
    bpduguard_default: bool | None = None
    loopguard_default: bool | None = None
    portfast_default: bool | None = None


class Layer2(NcmBase):
    vlans: list[Vlan] = Field(default_factory=list)
    spanning_tree: SpanningTree = Field(default_factory=SpanningTree)
    vtp_mode: str | None = None
    vtp_password_set: bool | None = None
    dhcp_snooping_enabled: bool | None = None
    arp_inspection_enabled: bool | None = None


# ─────────────────────────────── routing ────────────────────────────────────


class RoutingProtocol(NcmBase):
    name: str
    instance: str | None = None
    #: Unauthenticated routing adjacencies allow route injection.
    authentication: bool | None = None
    authentication_type: str | None = None
    redistributes: list[str] = Field(default_factory=list)
    passive_default: bool | None = None


class Routing(NcmBase):
    protocols: list[RoutingProtocol] = Field(default_factory=list)
    static_routes: int | None = None
    #: Source routing lets a sender dictate the path; long deprecated.
    ip_source_routing: bool | None = None


# ───────────────────────────────── ACLs ─────────────────────────────────────


class AclEntry(NcmBase):
    sequence: int | None = None
    action: str
    protocol: str | None = None
    source: str | None = None
    destination: str | None = None
    ports: str | None = None
    log: bool | None = None
    raw: str = ""


class Acl(NcmBase):
    name: str
    type: str | None = None
    entries: list[AclEntry] = Field(default_factory=list)
    applied_to: list[str] = Field(default_factory=list)


# ──────────────────────── firewall (Phase 4 populates) ──────────────────────


class NetworkObject(NcmBase):
    name: str
    type: str | None = None
    value: str | None = None
    members: list[str] = Field(default_factory=list)


class SecurityRule(NcmBase):
    order: int = 0
    name: str | None = None
    enabled: bool = True
    src_zones: list[str] = Field(default_factory=list)
    src: list[str] = Field(default_factory=list)
    dst_zones: list[str] = Field(default_factory=list)
    dst: list[str] = Field(default_factory=list)
    services: list[str] = Field(default_factory=list)
    applications: list[str] = Field(default_factory=list)
    users: list[str] = Field(default_factory=list)
    action: str = "allow"
    log_start: bool | None = None
    log_end: bool | None = None
    profiles: dict[str, str] = Field(default_factory=dict)
    schedule: str | None = None
    hit_count: int | None = None
    last_hit: str | None = None


class NatRule(NcmBase):
    order: int = 0
    name: str | None = None
    original: str | None = None
    translated: str | None = None
    service: str | None = None
    direction: str | None = None
    raw: str = ""


class Firewall(NcmBase):
    zones: list[str] = Field(default_factory=list)
    address_objects: list[NetworkObject] = Field(default_factory=list)
    address_groups: list[NetworkObject] = Field(default_factory=list)
    service_objects: list[NetworkObject] = Field(default_factory=list)
    service_groups: list[NetworkObject] = Field(default_factory=list)
    security_rules: list[SecurityRule] = Field(default_factory=list)
    nat_rules: list[NatRule] = Field(default_factory=list)
    profiles: dict[str, Any] = Field(default_factory=dict)


# ─────────────────────────── VPN and certificates ───────────────────────────


class IkeProposal(NcmBase):
    name: str | None = None
    version: int | None = None
    encryption: str | None = None
    hash: str | None = None
    dh_group: int | None = None
    lifetime_s: int | None = None
    authentication: str | None = None
    aggressive_mode: bool | None = None


class IpsecProposal(NcmBase):
    name: str | None = None
    encryption: str | None = None
    hash: str | None = None
    pfs_group: int | None = None
    lifetime_s: int | None = None


class Vpn(NcmBase):
    ike: list[IkeProposal] = Field(default_factory=list)
    ipsec: list[IpsecProposal] = Field(default_factory=list)


class Certificate(NcmBase):
    name: str | None = None
    subject: str | None = None
    issuer: str | None = None
    not_before: str | None = None
    not_after: str | None = None
    key_bits: int | None = None
    sig_alg: str | None = None
    self_signed: bool | None = None
    usage: list[str] = Field(default_factory=list)


# ──────────────────────── wireless (Phase 5 populates) ──────────────────────


class Wlan(NcmBase):
    ssid: str
    enabled: bool | None = None
    security: str | None = None
    pmf: str | None = None
    fast_transition: bool | None = None
    radius_group: str | None = None
    broadcast: bool | None = None
    client_isolation: bool | None = None
    vlan: int | None = None


class AccessPoint(NcmBase):
    name: str
    model: str | None = None
    ip: str | None = None
    serial: str | None = None


class Wireless(NcmBase):
    wlans: list[Wlan] = Field(default_factory=list)
    aps: list[AccessPoint] = Field(default_factory=list)
    rogue_detection: dict[str, Any] = Field(default_factory=dict)


# ─────────────────────────────── features ───────────────────────────────────


class Features(NcmBase):
    """Feature flags checks and the vulnerability matcher both read.

    FR-VUL-03 makes matching feature-aware: a CVE that only affects devices with the
    HTTP server enabled should not be reported against one that has it off. That only
    works if the parser records these explicitly.
    """

    http_server: bool | None = None
    https_server: bool | None = None
    cdp: bool | None = None
    lldp: bool | None = None
    ip_source_routing: bool | None = None
    smart_install: bool | None = None
    bootp_server: bool | None = None
    tcp_small_servers: bool | None = None
    udp_small_servers: bool | None = None
    finger: bool | None = None
    pad: bool | None = None
    domain_lookup: bool | None = None
    ip_gratuitous_arps: bool | None = None
    service_config: bool | None = None
    #: Anything else the parser recognised but the model has no field for yet.
    extra: dict[str, bool] = Field(default_factory=dict)


# ────────────────────────────── the model ───────────────────────────────────


class NormalisedConfig(NcmBase):
    """One device's configuration, in vendor-neutral form (FR-PARSE-01)."""

    ncm_version: str = NCM_VERSION

    device: DeviceFacts = Field(default_factory=DeviceFacts)
    management: Management = Field(default_factory=Management)
    users: list[LocalUser] = Field(default_factory=list)
    aaa: Aaa = Field(default_factory=Aaa)
    logging: Logging = Field(default_factory=Logging)
    ntp: Ntp = Field(default_factory=Ntp)
    snmp: Snmp = Field(default_factory=Snmp)
    interfaces: list[Interface] = Field(default_factory=list)
    l2: Layer2 = Field(default_factory=Layer2)
    routing: Routing = Field(default_factory=Routing)
    acls: list[Acl] = Field(default_factory=list)
    firewall: Firewall = Field(default_factory=Firewall)
    vpn: Vpn = Field(default_factory=Vpn)
    wireless: Wireless = Field(default_factory=Wireless)
    certificates: list[Certificate] = Field(default_factory=list)
    features: Features = Field(default_factory=Features)

    #: Stanzas the parser did not recognise (FR-PARSE-03). Never empty in practice,
    #: and deliberately so: silently dropping configuration would hide what we missed.
    raw_unparsed: list[str] = Field(default_factory=list)

    #: JSON path → where the value came from (FR-PARSE-04).
    provenance: ProvenanceMap = Field(default_factory=ProvenanceMap)

    def to_storage(self) -> dict[str, Any]:
        """JSONB-ready form. Provenance travels with the document."""
        return self.model_dump(mode="json", exclude_none=False)

    @classmethod
    def from_storage(cls, data: dict[str, Any]) -> NormalisedConfig:
        return cls.model_validate(data)


__all__ = [
    "NCM_VERSION",
    "Aaa",
    "AaaMethodList",
    "AaaServer",
    "Acl",
    "AclEntry",
    "Certificate",
    "DeviceFacts",
    "Features",
    "Firewall",
    "Interface",
    "InterfaceSecurity",
    "Layer2",
    "LocalUser",
    "Logging",
    "Management",
    "NormalisedConfig",
    "Ntp",
    "NtpServer",
    "Provenance",
    "ProvenanceMap",
    "Routing",
    "RoutingProtocol",
    "Snmp",
    "SnmpCommunity",
    "SnmpV3User",
    "SshConfig",
    "SyslogServer",
    "Vlan",
    "Vpn",
    "Wireless",
]
