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

#: Bumped 1.0 → 1.1 when `routing.routes` arrived (FR-TOPO-01).
#:
#: Additive, so nothing that reads a 1.0 snapshot breaks — but the bump is not
#: ceremony. A 1.0 snapshot has an empty route list because no parser ever filled it,
#: and a 1.1 snapshot has an empty one because the device really had no routes. Those
#: are opposite facts and `ncm_version` is the only thing that distinguishes them, so a
#: path walk over an old snapshot must answer Unknown rather than Unreachable. Same
#: discipline as absent-is-not-false in the check engine.
NCM_VERSION = "1.1"


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


class AsyncLine(NcmBase):
    """An auxiliary or numbered TTY line (FR-PARSE-01).

    Kept apart from VTY and console rather than folded into `SessionLimits`, because the
    question asked of it is a different one. A VTY line is *meant* to accept logins and
    the question is how well; an AUX port is meant to be dead, and the finding is that it
    answers at all. On an access server the numbered lines are reverse-telnet paths to
    whatever is cabled to them, which is the same question again.
    """

    #: `aux 0`, `2`, `0/0/0 0/0/12` — as written, since the range matters.
    name: str
    #: True when `no exec` is present, which is what actually disables the line.
    exec_disabled: bool | None = None
    #: Seconds. 0 means "never time out", which is the weakest possible setting and
    #: is stored as 0 rather than None — None means the line did not say.
    exec_timeout_s: int | None = None
    #: What `transport input` permits. Empty list means `transport input none`, which is
    #: the hardened state; None means the line did not say, and on IOS the default is
    #: permissive. Those are opposite facts, so they must not share a representation.
    transport_input: list[str] | None = None
    transport_output: list[str] | None = None
    #: A password or login method configured on the line.
    login_configured: bool | None = None


class SessionLimits(NcmBase):
    exec_timeout_s: int | None = None
    console_timeout_s: int | None = None
    #: Concurrent session cap, where the platform supports one.
    max_sessions: int | None = None
    #: AUX and numbered TTY lines, which nothing read until the parser corpus showed
    #: them carrying `exec-timeout 0 0` and reaching no field. An unsecured AUX port is
    #: a CIS Cisco IOS benchmark item and could not be assessed while this was absent.
    async_lines: list[AsyncLine] = Field(default_factory=list)
    #: How many `line vty` blocks the configuration declares. None when it declares
    #: none, which on a real IOS device means the configuration is partial rather than
    #: that the device has no remote access — every switch shows `line vty 0 4` even
    #: at defaults. Checks on vty settings guard on this so a truncated capture reports
    #: Not Evaluated instead of a confident finding about lines nobody saw.
    vty_lines: int | None = None
    #: Outbound transports the vty lines permit — `transport output`, which governs
    #: connections *from* the device rather than to it, and is the pivot path Cisco's
    #: Management Plane Protection guidance is about.
    #:
    #: An empty list means every vty block explicitly says `none`. None means at least
    #: one block does not state it at all, and those are opposite facts that must not
    #: collapse: IOS's default here is version-dependent and Cisco documents no value
    #: for it, so an unstated line cannot be resolved to a protocol set. Recording the
    #: union across blocks rather than the first, because a device is only as
    #: restricted as its most permissive line.
    vty_transport_output: list[str] | None = None


class PasswordPolicy(NcmBase):
    min_length: int | None = None
    complexity_required: bool | None = None
    max_age_days: int | None = None
    history: int | None = None
    #: Failed login attempts before an account is locked.
    lockout_threshold: int | None = None
    #: Whether the failed-login lockout is switched on at all.
    #:
    #: Separate from the threshold because the two fail independently: Gaia stores
    #: `deny-on-fail failures-allowed 5` whether or not `deny-on-fail enable` is on, so a
    #: threshold alone says a lockout is *configured*, not that it *applies*.
    lockout_enabled: bool | None = None
    #: Days of non-use before an account is locked — a dormant-account control, and a
    #: different thing from `lockout_threshold`. An account nobody has touched in a year
    #: is a credential nobody would notice being used.
    dormant_lockout_days: int | None = None
    #: How stored passwords are hashed, where the platform says. Gaia reports SHA256 or
    #: SHA512; Cisco's type digit is carried on `LocalUser.secret_type` instead, because
    #: there it is per-account rather than a policy.
    hash_algorithm: str | None = None
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
    #: Server groups by name, each listing its member server hosts. IOS binds a method
    #: list to a *group*, not to a server, so without this the chain from "which method
    #: list does VTY use" to "which RADIUS server answers it" cannot be followed.
    server_groups: dict[str, list[str]] = Field(default_factory=dict)


# ─────────────────── AAA as a *server* (FR-AAA-02 … FR-AAA-05) ──────────────
#
# Everything above describes a device as an AAA *client*. The blocks below describe a
# device that *is* the AAA service — Cisco ISE, FortiAuthenticator, a FreeRADIUS or
# tac_plus host. They are a different subject with different questions: not "does this
# switch authenticate centrally" but "which switches may authenticate against me, and
# what am I prepared to accept from them".
#
# Added to NCM v1 rather than bumping the version: every field is optional with a
# default, so a snapshot stored before Phase 5 deserialises unchanged and every
# server-side check on it reports Not Evaluated, which is the honest answer for a device
# that was never an AAA server.


class RadiusClient(NcmBase):
    """A network device permitted to authenticate against this server (FR-AAA-05)."""

    name: str
    address: str | None = None
    #: Whether a shared secret is set — never the secret (C-2).
    secret_configured: bool | None = None
    #: A stable fingerprint of the secret, where the source exposes it at all. This is
    #: what makes shared-secret *reuse* detectable across an estate without NetSecOps
    #: ever handling the secret: two clients with the same fingerprint share a key.
    #: None means the server did not expose it, which FR-AAA-05 requires be reported as
    #: "unknown" rather than as "not reused".
    secret_fingerprint: str | None = None
    vendor: str | None = None
    description: str | None = None
    #: RadSec / TLS rather than the classic shared-secret transport.
    tls: bool | None = None
    enabled: bool | None = None


class IdentityStore(NcmBase):
    """Where the server looks up users: internal, Active Directory, LDAP, certificates."""

    name: str
    type: str | None = None
    #: For AD/LDAP: whether the connection is encrypted. A directory bind in the clear
    #: carries credentials across the network on every authentication.
    tls: bool | None = None
    host: str | None = None


class AuthPolicy(NcmBase):
    """One authentication or authorisation rule, in the order the server evaluates it."""

    name: str
    order: int = 0
    enabled: bool | None = None
    #: `authentication` or `authorization`.
    kind: str | None = None
    condition: str | None = None
    #: Which protocols this rule is willing to accept. The weak ones are the finding.
    allowed_protocols: list[str] = Field(default_factory=list)
    identity_source: str | None = None
    result: str | None = None


class CommandSet(NcmBase):
    """TACACS+ command authorisation — which commands a role may run."""

    name: str
    #: True when the set permits anything not explicitly denied, which makes the
    #: remaining rules decoration.
    permit_unmatched: bool | None = None
    commands: list[str] = Field(default_factory=list)


class DeviceGroup(NcmBase):
    """A grouping of network devices, which policy rules match on (FR-AAA-02).

    Worth collecting because ISE authorisation rules are frequently written against a
    group rather than a device, so a rule reading "permit Device Type#All Device
    Types#Switches" is unreadable — and unauditable — without knowing what is in that
    group. It is also where a device quietly acquires privileges: adding a switch to the
    wrong group grants it a policy nobody reviewed for it.
    """

    name: str
    #: ISE nests groups as `Root#Parent#Child`; the parent is kept so the hierarchy
    #: survives into the NCM rather than being flattened into an opaque string.
    parent: str | None = None
    description: str | None = None
    #: What the group classifies — ISE calls this the root type (Device Type, Location).
    kind: str | None = None


class GuestAccess(NcmBase):
    """Guest and sponsored-access settings (FR-AAA-02).

    Guest portals are the part of an AAA deployment that is deliberately reachable by
    people who have no account, which makes their defaults the ones worth reading. Self
    -registration without sponsor approval means anyone within radio range can issue
    themselves network access; a long account lifetime means the access outlives the
    visit that justified it.
    """

    enabled: bool | None = None
    #: Guests may create their own accounts without an employee sponsoring them.
    self_registration: bool | None = None
    #: A sponsor must approve before a self-registered account works. The pairing with
    #: `self_registration` is the finding: either alone is a choice, both is open access.
    sponsor_approval_required: bool | None = None
    #: How long a guest account stays valid.
    max_account_duration_days: int | None = None
    #: Credentials sent to the guest in the clear, by SMS or email.
    credentials_sent_in_clear: bool | None = None
    #: The portal is served over HTTPS.
    https_only: bool | None = None
    portals: list[str] = Field(default_factory=list)


class Repository(NcmBase):
    """A configured backup or upgrade destination (FR-AAA-02).

    An AAA server's backup contains every shared secret, every certificate and the
    credentials for the whole estate, so where it is sent and whether it is encrypted in
    transit is a question about the estate rather than about the server. An FTP or TFTP
    repository moves that archive across the network in the clear.
    """

    name: str
    #: `sftp`, `ftp`, `tftp`, `nfs`, `disk`, `http`, `https`.
    protocol: str | None = None
    host: str | None = None
    path: str | None = None
    #: True when the transport protects the archive in transit. None where the protocol
    #: was not reported — not False, which would assert an insecurity we did not observe.
    encrypted_transport: bool | None = None


class BackupStatus(NcmBase):
    """Whether configuration backups are actually running (FR-AAA-02).

    Scheduled and succeeding are different facts, and a schedule that has been failing
    since a password change looks identical to a healthy one in the configuration.
    """

    scheduled: bool | None = None
    #: ISO-8601 as the device reported it. See `ncm.certificates.parse_expiry` for why
    #: interpretation lives outside the parsers.
    last_backup_at: str | None = None
    last_backup_status: str | None = None
    #: The backup archive itself is encrypted at rest, independently of the transport.
    encrypted: bool | None = None
    repository: str | None = None


class AaaServerConfig(NcmBase):
    """A device that *serves* AAA rather than consuming it."""

    #: `ise`, `fortiauthenticator`, `freeradius`, `tac_plus`.
    product: str | None = None
    clients: list[RadiusClient] = Field(default_factory=list)
    device_groups: list[DeviceGroup] = Field(default_factory=list)
    identity_stores: list[IdentityStore] = Field(default_factory=list)
    policies: list[AuthPolicy] = Field(default_factory=list)
    command_sets: list[CommandSet] = Field(default_factory=list)
    #: None rather than a default instance: an empty `GuestAccess` would answer every
    #: guest question with "unknown", which is right, but a *present* empty block reads
    #: as "we looked and there is no guest access", which is not the same thing.
    guest: GuestAccess | None = None
    repositories: list[Repository] = Field(default_factory=list)
    backup: BackupStatus | None = None
    #: Every protocol the server will accept anywhere in its policy set. Flattened here
    #: because "does this server still allow MS-CHAPv1" is a question about the server,
    #: not about one rule.
    allowed_protocols: list[str] = Field(default_factory=list)
    #: TLS versions offered for EAP-TLS / RadSec.
    tls_versions: list[str] = Field(default_factory=list)
    #: Administrative access to the AAA server itself (FR-AAA-02).
    admin_session_timeout_s: int | None = None
    admin_mfa_enabled: bool | None = None

    @property
    def weak_protocols(self) -> list[str]:
        """The ones whose presence is a finding regardless of context.

        PAP sends the password in the clear inside the RADIUS packet, protected only by
        the shared secret. CHAP and MS-CHAPv1 are broken. EAP-MD5 offers no server
        authentication, so a client will happily talk to any impostor. LEAP is trivially
        crackable offline.
        """
        weak = {"pap", "chap", "ms-chapv1", "mschapv1", "eap-md5", "leap"}
        return sorted({p for p in self.allowed_protocols if p.strip().lower() in weak})


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
    #: Unicast RPF: `rx` (strict — the source must be reachable back out of this
    #: interface), `any` (loose — reachable by some route), or None where the
    #: interface does not configure it.
    #:
    #: Recorded as a fact and deliberately not asserted on. Strict uRPF on an
    #: interface carrying asymmetric traffic drops legitimate packets, so "every
    #: routed interface should have it" is wrong advice in most real topologies, and
    #: NetSecOps cannot yet tell an edge interface from a core one. The value is here
    #: for evidence and reporting until it can.
    urpf_mode: str | None = None


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


class Route(NcmBase):
    """One forwarding-table entry (FR-TOPO-01).

    The shape is deliberately the minimum a path can be walked with — destination, where
    it goes, and how it was learned — rather than everything a routing table prints.
    Metrics and administrative distance are here because two routes to the same prefix
    are ordinary and something has to choose between them; everything else a `show ip
    route` line carries (age, uptime, the advertising neighbour) describes the routing
    protocol's health, which is a different question from where a packet goes.

    ``protocol`` is what makes a graph honest about itself. A topology built from static
    routes alone is not wrong, it is *partial*, and it can only say so if each edge knows
    how it was learned.
    """

    #: The prefix in CIDR form, normalised at parse time. Vendors print this four
    #: different ways — `10.0.0.0 255.0.0.0`, `10.0.0.0/8`, `10.0.0.0 8` — and a graph
    #: that compares them as strings silently fails to match a route to its own subnet.
    destination: str
    #: The gateway. None on a connected or interface-routed entry, which is a real
    #: answer rather than missing data: the destination is on the link.
    next_hop: str | None = None
    interface: str | None = None
    #: connected | static | ospf | bgp | eigrp | rip | isis | other.
    protocol: str | None = None
    #: Administrative distance, then metric. Both optional because a static route in a
    #: configuration file carries neither unless somebody set them.
    distance: int | None = None
    metric: int | None = None
    #: VRFs partition the table: two routes for the same prefix in different VRFs do not
    #: compete, and a path walk that ignores this merges networks that cannot reach each
    #: other. None means the global table.
    vrf: str | None = None


class Routing(NcmBase):
    protocols: list[RoutingProtocol] = Field(default_factory=list)

    #: Superseded by :attr:`routes`, and retained only so that snapshots written before
    #: NCM 1.1 still load.
    #:
    #: **Removing it is not a code change, it is a change to stored data.** Snapshots are
    #: immutable evidence, they are kept for years, and `vuln_assessment` re-validates
    #: them with `NormalisedConfig.model_validate`. Every model here sets
    #: ``extra="forbid"`` so a parser typo fails loudly — which also means a field deleted
    #: from the schema turns every older snapshot into a validation error. Tests would not
    #: have caught it: they build snapshots with the current model.
    #:
    #: So it stays, and no parser writes it any more. New snapshots leave it None and
    #: carry the real list; old ones keep whatever count they recorded. Nothing reads it.
    static_routes: int | None = None

    #: The forwarding table as far as this parser could see it (FR-TOPO-01).
    #:
    #: Empty means "none found", and on a snapshot taken before NCM 1.1 it means "never
    #: looked" — those are different, and `ncm_version` is what tells them apart. A path
    #: engine reading an older snapshot must report Unknown rather than Unreachable, on
    #: the same reasoning as absent-is-not-false in the check engine.
    routes: list[Route] = Field(default_factory=list)

    #: Set when a device's table was larger than the parser would store. A router
    #: carrying a full BGP table has several hundred thousand routes and no assessment
    #: needs them, but a path that falls off the end of a truncated table must resolve to
    #: Unknown rather than Unreachable — so the truncation has to be recorded, not just
    #: applied.
    routes_truncated: bool | None = None

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


class AclBinding(NcmBase):
    """Where an access list is enforced, normalised across platforms.

    `interface` is whatever the device's own binding names, and that differs: IOS and
    NX-OS write `ip access-group NAME in` under a physical interface, so it is
    `GigabitEthernet0/1`; an ASA writes `access-group NAME in interface inside`, naming
    the *nameif* rather than the hardware. Both are kept verbatim rather than resolved to
    one of them, because a consumer matching an ingress interface has both names
    available — the graph records interface names and the interface→zone map — and
    picking one here would throw away the only key that works on the other platform.

    `interface` is None for an ASA `access-group NAME global`, which applies everywhere.
    """

    interface: str | None = None
    #: `in` or `out`. A packet crossing a device is tested against the inbound list on
    #: the interface it arrives on *and* the outbound list on the interface it leaves by,
    #: and a deny in either drops it — so the direction is not decoration.
    direction: str = "in"


class Acl(NcmBase):
    name: str
    type: str | None = None
    entries: list[AclEntry] = Field(default_factory=list)
    #: The raw binding lines, as the device wrote them. Kept for display and evidence.
    applied_to: list[str] = Field(default_factory=list)
    #: The same bindings, parsed. `applied_to` is unparseable across platforms — see
    #: `AclBinding` — and this is what anything reasoning about enforcement reads.
    bindings: list[AclBinding] = Field(default_factory=list)


# ──────────────────────── firewall (Phase 4 populates) ──────────────────────


class NetworkObject(NcmBase):
    name: str
    type: str | None = None
    value: str | None = None
    members: list[str] = Field(default_factory=list)


class SecurityRule(NcmBase):
    order: int = 0
    name: str | None = None
    #: The enforcement context this rule is evaluated in, when the platform has more
    #: than one. On PAN-OS, FortiOS and Check Point every security rule sits in a single
    #: ordered policy and this stays None. On ASA, IOS and NX-OS the policy is a set of
    #: named ACLs bound to different interfaces, and two entries in different ACLs never
    #: see the same packet — so comparing them for shadowing produces a finding about a
    #: conflict that cannot occur. Rules are only compared with others sharing a value.
    rulebase: str | None = None
    #: Whether this rule's rulebase is bound to any interface, on the platforms where
    #: that is a separate act. An ACL that exists and is applied to nothing filters no
    #: traffic — it is frequently a vty or SNMP filter, or a leftover — so a path walk
    #: that evaluated it would report traffic blocked that the device forwards. `None`
    #: where the question does not arise: PAN-OS, FortiOS and Check Point rules are in
    #: force by existing.
    #:
    #: It does not say *which* interface, and the path walk does not yet choose between
    #: two ACLs that are both applied. That is the remaining half, and it is why this is
    #: a three-state field rather than a boolean.
    applied: bool | None = None
    enabled: bool = True
    src_zones: list[str] = Field(default_factory=list)
    src: list[str] = Field(default_factory=list)
    dst_zones: list[str] = Field(default_factory=list)
    dst: list[str] = Field(default_factory=list)
    #: Check Point writes rules as "anything *except* these". The resolver inverts the
    #: address set when this is set; ignoring it would read the rule as its opposite.
    src_negate: bool = False
    dst_negate: bool = False
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
    #: Rulebase name → where it is enforced. The same information as `Acl.bindings`,
    #: carried here because the path walk reads the firewall block and never sees
    #: `ncm.acls` — and without it the walk cannot tell which of a device's access lists
    #: governs a given hop. Empty on platforms with a single ordered policy.
    rulebase_bindings: dict[str, list[AclBinding]] = Field(default_factory=dict)

    #: Rules the device holds that this snapshot does not, because the response was
    #: paginated and only the first page was read. None means the source said nothing
    #: about totals; 0 means it said there were none left.
    #:
    #: This exists because a partial rulebase is more dangerous than an empty one. An
    #: empty rulebase is obviously wrong and somebody investigates. Fifty rules out of
    #: five hundred analyse perfectly: no shadowing, no any-any, a tidy cleanup rule at
    #: the end — a clean report about a seventh of a firewall. Every consumer of
    #: `security_rules` must be able to say "as far as I could see".
    rules_not_retrieved: int | None = None


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
    #: `service tcp-keepalives-in` / `-out`. Unlike every other flag here these are
    #: features whose *presence* is the hardened state, so a check on them wants
    #: `missing: fail` rather than the usual `equals: false`.
    tcp_keepalives_in: bool | None = None
    tcp_keepalives_out: bool | None = None
    #: FortiGate SSL-VPN, from `config vpn ssl settings` / `set status`.
    #:
    #: Here for FR-VUL-03 rather than for a check: every mass-exploited FortiGate CVE —
    #: 2018-13379, 2022-42475, 2023-27997, 2024-21762 — is conditional on SSL-VPN being
    #: enabled, and Fortinet's advisories say so. Matching on version alone reports all
    #: four against every FortiGate of the right version, most of which do not run it.
    #: SSL-VPN being *on* is not itself a finding; it is a legitimate feature.
    ssl_vpn: bool | None = None
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
    #: Populated only on a device that *is* an AAA service (FR-AAA-02 … FR-AAA-04).
    #: Empty on everything else, which is why the server-side checks are scoped by
    #: device class rather than reporting Not Evaluated on every switch in the estate.
    aaa_server: AaaServerConfig = Field(default_factory=AaaServerConfig)
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

    #: The parser could not read the artefact *at all* — malformed XML, invalid JSON, a
    #: bundle that is not a bundle. Distinct from a low coverage figure, and the
    #: distinction is not cosmetic.
    #:
    #: Those failure paths record one explanatory line in `raw_unparsed`, which is the
    #: right thing for a human reading the evidence and the wrong input to an arithmetic
    #: that reads "meaningful lines minus unparsed lines". A five-hundred-line PAN-OS
    #: configuration that parsed into nothing scored 99.8% and rendered as a green
    #: "99% parsed" pill beside a snapshot with an empty NCM. Found by pointing
    #: `scripts/parse_coverage.py` at a corpus we did not write.
    parse_failed: bool = False

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
    "Route",
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
