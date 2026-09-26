"""Collection profiles — what each platform is asked for (FR-COL-02, FR-COL-08).

A profile is the ordered list of commands one collection issues. Two rules shape it:

**Every command must already be on the platform's allow-list in ``policies.py``.** A
profile cannot widen what NetSecOps may send; it can only choose among what a reviewer
has already approved. ``test_profiles.py`` asserts this for every entry, so a profile
that reached for a new command would fail the build rather than quietly expand the
device-facing surface (SRS §8.2).

**Only the configuration is required.** Everything else is supplementary: a switch that
refuses ``show port-security`` because the feature is not licensed should still produce
a snapshot and be assessed, with the checks that needed that output reported as *Not
evaluated — missing data* rather than as passes (FR-COL-08).
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum
from typing import Any, Final

from netsecops.core.errors import ValidationProblem


class Transport(StrEnum):
    """How a platform is read.

    This is not cosmetic: it decides which half of the read-only guard applies. A CLI
    command is checked against the command allow-list and the write-verb deny-list; an
    API call is checked against the HTTP method and path rules. Running a profile entry
    against the wrong one would appear to pass and prove nothing.
    """

    CLI = "cli"
    HTTP = "http"
    #: A POST-only JSON-RPC API — Check Point's Management API, FortiManager's. The
    #: method cannot carry the read-only guarantee here, because *everything* is a POST,
    #: so the guard reads the body instead and the profile must supply one.
    RPC = "rpc"


@dataclass(frozen=True, slots=True)
class CollectionCommand:
    #: For CLI, the command. For HTTP, `"<METHOD> <path>"` — the same spelling the
    #: audit log records, so an operator reading the trail sees exactly what was sent.
    command: str
    #: Why it is issued. Shown in the UI beside the artefact, so an operator watching a
    #: collection can tell what NetSecOps wanted rather than only what it sent.
    purpose: str
    #: A failure here aborts the collection. True for the configuration alone.
    required: bool = False
    #: This command's output is the running configuration, and is what gets parsed.
    yields_config: bool = False
    #: The key this response takes in a bundled profile's artefact, where the last path
    #: segment is not what the parser looks for. ISE needs several — it asks for
    #: `/api/v1/policy/network-access/authorization` and reads
    #: `policy/network-access/authorization`, which is three segments, not one.
    bundle_key: str | None = None
    #: Fetch this operation a page at a time, this many objects per request.
    #:
    #: Only the Check Point Management API, which pages with `offset`/`limit` and
    #: reports `from`, `to` and `total`. Left None everywhere else: a page parameter
    #: an API does not understand is a request that fails, not one it ignores.
    page_size: int | None = None

    def as_request(self) -> tuple[str, str]:
        """Split an HTTP entry into (method, path)."""
        method, _, path = self.command.partition(" ")
        return method.upper(), path

    def key_in_bundle(self) -> str:
        """The name this response is filed under for the parser to find it.

        Defaults to the last path segment, which is what Check Point's operation names
        and FortiAuthenticator's endpoints reduce to. Anything else declares itself.
        """
        if self.bundle_key is not None:
            return self.bundle_key
        _method, path = self.as_request()
        return path.strip("/").split("/")[-1].lower()

    def as_body(self, *, offset: int | None = None) -> dict[str, Any]:
        """The JSON body an RPC entry sends.

        The command is derived from the path rather than declared separately: on the
        Check Point Management API the operation *is* the last path segment, so deriving
        it means the conformance test checks the same string that is actually sent. A
        hand-written second copy could drift from the path and would then be proving
        nothing.

        ``offset`` is passed only while paging. Both page parameters are omitted
        entirely for an unpaged command, so the body of every other operation is
        byte-for-byte what it was — `offset: 0` is not the same request as no offset to
        an API that does not document the parameter.
        """
        _method, path = self.as_request()
        body: dict[str, Any] = {"command": path.rsplit("/", 1)[-1]}
        if self.page_size is not None:
            body["limit"] = self.page_size
            body["offset"] = offset or 0
        return body


@dataclass(frozen=True, slots=True)
class CollectionProfile:
    platform: str
    #: Session setup: paging, width. Never recorded as artefacts — they produce no data
    #: and would clutter the evidence with noise. Empty for HTTP platforms, which have
    #: no session to configure.
    setup: tuple[str, ...]
    commands: tuple[CollectionCommand, ...]
    transport: Transport = Transport.CLI
    #: The parsed artefact is every response together, keyed by command, rather than
    #: the output of one command.
    #:
    #: True for the platforms whose "configuration" is not a document but an API: a
    #: Check Point management server's policy, ISE's deployment, a FortiAuthenticator.
    #: Their parsers are all built around `ResponseBundle` and look responses up by
    #: endpoint, so handing them the body of a single command leaves every lookup
    #: empty — a policy that parses to no rules at all, with nothing reporting failure.
    #: PAN-OS is deliberately not bundled: its configuration really is one XML document.
    bundled: bool = False

    @property
    def config_command(self) -> str:
        for entry in self.commands:
            if entry.yields_config:
                return entry.command
        raise ValidationProblem(
            f"Collection profile for '{self.platform}' defines no configuration command."
        )

    def all_commands(self) -> tuple[str, ...]:
        """Setup plus data commands, in the order they are sent."""
        return self.setup + tuple(entry.command for entry in self.commands)


CISCO_IOS_PROFILE: Final = CollectionProfile(
    platform="cisco_ios",
    setup=("terminal length 0", "terminal width 512"),
    commands=(
        CollectionCommand(
            "show running-config",
            "The configuration itself — everything the parser reads",
            required=True,
            yields_config=True,
        ),
        CollectionCommand("show version", "Software version and model, for vulnerability matching"),
        CollectionCommand("show inventory", "Serial numbers and module list"),
        CollectionCommand("show ip interface brief", "Interface addressing and operational state"),
        CollectionCommand("show interfaces status", "Port state, VLAN and duplex"),
        CollectionCommand(
            "show ip route",
            "The forwarding table, including protocol-learned routes (FR-TOPO-01)",
        ),
        CollectionCommand("show ip ssh", "Live SSH version and timeout, which the config omits"),
        CollectionCommand("show snmp user", "SNMPv3 users; the config stores these opaquely"),
        CollectionCommand("show aaa servers", "AAA server reachability, not visible in config"),
        CollectionCommand("show ntp status", "Whether the clock is actually synchronised"),
        CollectionCommand("show crypto pki certificates", "Certificate expiry and key size"),
        CollectionCommand("show ip http server status", "HTTP/HTTPS management state"),
        CollectionCommand("show vlan brief", "VLAN inventory"),
        CollectionCommand("show spanning-tree summary", "STP mode and guard state"),
        CollectionCommand("show port-security", "Port-security posture"),
        CollectionCommand("show ip dhcp snooping", "DHCP snooping posture"),
        CollectionCommand("show ip arp inspection", "Dynamic ARP inspection posture"),
        CollectionCommand("show line", "Console and VTY line configuration"),
        CollectionCommand("show boot", "Boot variable and image integrity settings"),
    ),
)

CISCO_NXOS_PROFILE: Final = CollectionProfile(
    platform="cisco_nxos",
    setup=("terminal length 0",),
    commands=(
        CollectionCommand(
            "show running-config",
            "The configuration itself — everything the parser reads",
            required=True,
            yields_config=True,
        ),
        CollectionCommand("show version", "NX-OS version and chassis, for vulnerability matching"),
        CollectionCommand("show inventory", "Serial numbers and module list"),
        CollectionCommand("show feature", "Enabled features — NX-OS gates most behaviour on these"),
        CollectionCommand("show interface brief", "Interface state"),
        CollectionCommand(
            "show ip route vrf all",
            "Every VRF's forwarding table, including protocol-learned routes (FR-TOPO-01)",
        ),
        CollectionCommand("show ssh server", "Live SSH server state"),
        CollectionCommand("show snmp user", "SNMPv3 users and their security levels"),
        CollectionCommand("show aaa authentication", "Authentication method lists"),
        CollectionCommand("show tacacs-server", "TACACS+ server configuration"),
        CollectionCommand("show ntp peers", "NTP peers"),
        CollectionCommand("show logging server", "Syslog destinations"),
        CollectionCommand("show user-account", "Local accounts and roles"),
        CollectionCommand("show role", "Role definitions, which NX-OS keeps outside the config"),
        CollectionCommand("show vpc", "vPC peering state"),
    ),
)

CISCO_ASA_PROFILE: Final = CollectionProfile(
    platform="cisco_asa",
    setup=("terminal pager 0",),
    commands=(
        CollectionCommand(
            "show running-config",
            "The configuration itself — everything the parser reads",
            required=True,
            yields_config=True,
        ),
        CollectionCommand("show version", "ASA version and platform, for vulnerability matching"),
        CollectionCommand("show inventory", "Serial numbers and module list"),
        CollectionCommand("show nameif", "Interface names and security levels"),
        CollectionCommand("show interface ip brief", "Interface addressing and state"),
        CollectionCommand(
            "show route",
            "The forwarding table, including protocol-learned routes (FR-TOPO-01)",
        ),
        CollectionCommand("show access-list", "ACL hit counts — absent from the configuration"),
        CollectionCommand("show run access-group", "Which ACL is bound to which interface"),
        CollectionCommand("show run object", "Network and service objects"),
        CollectionCommand("show run object-group", "Object groups"),
        CollectionCommand("show ssh", "SSH access restrictions"),
        CollectionCommand("show run http", "ASDM/HTTPS management restrictions"),
        CollectionCommand("show aaa-server", "AAA server groups and state"),
        CollectionCommand("show crypto ca certificates", "Certificate expiry and key size"),
        CollectionCommand("show ntp associations", "NTP peering"),
        CollectionCommand("show failover", "HA state"),
    ),
)

FORTIOS_PROFILE: Final = CollectionProfile(
    platform="fortios",
    # No paging command: SRS §8.2 forbids piping on FortiGate, and `show
    # full-configuration` is not paged over SSH in the first place.
    setup=(),
    commands=(
        CollectionCommand(
            "show full-configuration",
            "The configuration itself — everything the parser reads",
            required=True,
            yields_config=True,
        ),
        CollectionCommand("get system status", "Firmware version, model and serial"),
        CollectionCommand("get system ha status", "HA cluster role and peer state"),
        CollectionCommand(
            "get system interface physical", "Physical interface state, absent from config"
        ),
        CollectionCommand("get system admin list", "Administrators currently logged in"),
        CollectionCommand("get user radius", "RADIUS server reachability"),
        CollectionCommand(
            "get router info routing-table all",
            "The forwarding table, including protocol-learned routes (FR-TOPO-01)",
        ),
    ),
)

PANOS_PROFILE: Final = CollectionProfile(
    platform="panos",
    # PAN-OS is collected over the XML API, not a shell, so there is no paging to
    # disable. Each entry here is an API request the §8.2 HTTP rules already permit.
    setup=(),
    transport=Transport.HTTP,
    commands=(
        CollectionCommand(
            "GET /api/?type=config&action=show",
            "The candidate-free running configuration, as XML",
            required=True,
            yields_config=True,
        ),
        CollectionCommand(
            "GET /api/?type=op&cmd=<show><system><info></info></system></show>",
            "Software version, model and serial, for vulnerability matching",
        ),
        CollectionCommand(
            "GET /api/?type=op&cmd=<show><high-availability><state></state></high-availability></show>",
            "HA state and peer version",
        ),
        CollectionCommand(
            "GET /api/?type=op&cmd=<show><running><security-policy></security-policy></running></show>",
            "The effective rulebase as the dataplane holds it",
        ),
        # `show counter global` stood here for a while, described as the source of rule
        # hit counts. It is not: it returns global dataplane counters (pkt_rcv,
        # flow_policy_deny and friends) and carries nothing per-rule, so nothing ever
        # read it and every PAN-OS rule reported an unknown hit count. Per-rule counts
        # come from `show rule-hit-count`, which is what is asked for now.
        CollectionCommand(
            "GET /api/?type=op&cmd=<show><rule-hit-count><vsys><vsys-name>"
            "<entry name='vsys1'><rule-base><entry name='security'><rules><all>"
            "</all></rules></entry></rule-base></entry></vsys-name></vsys>"
            "</rule-hit-count></show>",
            "Per-rule hit counts and last-hit times, which the configuration does not carry",
        ),
    ),
)

CISCO_WLC_PROFILE: Final = CollectionProfile(
    platform="cisco_wlc_aireos",
    setup=("config paging disable",),
    commands=(
        CollectionCommand(
            "show run-config commands",
            "The configuration as a command list — everything the parser reads",
            required=True,
            yields_config=True,
        ),
        CollectionCommand("show sysinfo", "Software version and model, for vulnerability matching"),
        CollectionCommand("show wlan summary", "WLAN inventory and state"),
        CollectionCommand("show ap summary", "Joined access points"),
        CollectionCommand("show radius summary", "RADIUS server reachability, absent from config"),
        CollectionCommand("show tacacs summary", "TACACS+ server reachability"),
        CollectionCommand("show mgmtuser", "Administrators and their roles"),
        CollectionCommand("show rogue ap summary", "Rogue detection state and current rogues"),
        CollectionCommand("show certificate summary", "Certificate expiry"),
        CollectionCommand("show interface summary", "Interface addressing and VLANs"),
        CollectionCommand("show wps summary", "Wireless protection policy posture"),
    ),
)

CISCO_ISE_PROFILE: Final = CollectionProfile(
    platform="cisco_ise",
    # ISE is read over its REST APIs; there is no shell to configure. The ERS and
    # OpenAPI endpoints are mixed deliberately — a deployment answers on whichever its
    # version supports, and FR-COL-08 turns the other's 404 into a partial collection
    # rather than a failure.
    setup=(),
    transport=Transport.HTTP,
    bundled=True,
    commands=(
        CollectionCommand(
            "GET /ers/config/networkdevice",
            "Every device permitted to authenticate here — the FR-AAA-05 correlation",
            required=True,
            yields_config=True,
        ),
        CollectionCommand(
            "GET /api/v1/deployment/node",
            "Node names, roles and version",
            bundle_key="deployment/node",
        ),
        CollectionCommand(
            "GET /ers/config/activedirectory", "Active Directory joins used as identity sources"
        ),
        CollectionCommand("GET /ers/config/identitystore", "LDAP and token identity sources"),
        CollectionCommand(
            "GET /ers/config/allowedprotocols",
            "Which authentication protocols the server will accept — PAP, MS-CHAPv1, EAP-MD5",
        ),
        CollectionCommand(
            "GET /api/v1/policy/network-access/authentication",
            "Authentication rules, in order",
            bundle_key="policy/network-access/authentication",
        ),
        CollectionCommand(
            "GET /api/v1/policy/network-access/authorization",
            "Authorisation rules, in order",
            bundle_key="policy/network-access/authorization",
        ),
        CollectionCommand(
            "GET /api/v1/policy/device-admin/command-sets",
            "TACACS+ command authorisation sets",
            bundle_key="policy/device-admin/command-sets",
        ),
        CollectionCommand("GET /ers/config/adminuser", "Administrators of ISE itself"),
        CollectionCommand(
            "GET /api/v1/system-settings/admin-access",
            "Admin session timeout and MFA",
            # The parser reads `admin/settings` and the path asks for
            # `system-settings/admin-access`. Keyed to what the parser reads so the
            # response is not discarded — but the two names disagree about ISE's real
            # API and only a deployment can settle which is right. Recorded in
            # docs/vendor-research.md rather than silently picked.
            bundle_key="admin/settings",
        ),
        CollectionCommand(
            "GET /api/v1/certs/system-certificate",
            "EAP and admin certificates",
            bundle_key="certs/system-certificate",
        ),
    ),
)

FORTIAUTHENTICATOR_PROFILE: Final = CollectionProfile(
    platform="fortiauthenticator",
    setup=(),
    transport=Transport.HTTP,
    bundled=True,
    commands=(
        CollectionCommand(
            "GET /api/v1/radiusclients/",
            "Devices permitted to authenticate here — the FR-AAA-05 correlation",
            required=True,
            yields_config=True,
        ),
        CollectionCommand("GET /api/v1/system/", "Hostname, firmware and admin access settings"),
        CollectionCommand(
            "GET /api/v1/ldapservers/", "Remote identity sources and their transport"
        ),
        CollectionCommand("GET /api/v1/localusers/", "Local user accounts"),
        CollectionCommand("GET /api/v1/usergroups/", "Group membership"),
        CollectionCommand("GET /api/v1/certificates/", "Certificate expiry"),
        CollectionCommand("GET /api/v1/adminprofiles/", "Administrators of the appliance itself"),
    ),
)

#: FreeRADIUS and tac_plus share this profile's *shape* but not its paths, so they are
#: two profiles over one allow-list. Only `cat` of a file inside the approved directories
#: is ever issued (SRS §8.2).
FREERADIUS_PROFILE: Final = CollectionProfile(
    platform="freeradius",
    setup=(),
    commands=(
        CollectionCommand(
            "cat /etc/freeradius/3.0/clients.conf",
            "The devices permitted to authenticate, and whether each has a shared secret",
            required=True,
            yields_config=True,
        ),
        CollectionCommand(
            "cat /etc/freeradius/3.0/mods-available/eap",
            "Which EAP methods the server will accept, and its TLS floor",
        ),
        CollectionCommand(
            "cat /etc/freeradius/3.0/radiusd.conf", "Logging and LDAP identity sources"
        ),
        CollectionCommand(
            "cat /etc/freeradius/3.0/sites-enabled/default",
            "The virtual server's authorise list, which is FreeRADIUS's policy",
        ),
        CollectionCommand("radiusd -v", "Version, for vulnerability matching"),
        CollectionCommand("systemctl is-active freeradius", "Whether the service is running"),
    ),
)

TACPLUS_PROFILE: Final = CollectionProfile(
    platform="tac_plus",
    setup=(),
    commands=(
        CollectionCommand(
            "cat /etc/tac_plus/tac_plus.conf",
            "Clients, groups, command authorisation and local accounts",
            required=True,
            yields_config=True,
        ),
        CollectionCommand("tac_plus -v", "Version, for vulnerability matching"),
        CollectionCommand("systemctl is-active tac_plus", "Whether the service is running"),
        CollectionCommand("ls -la /etc/tac_plus", "File permissions on a file full of secrets"),
    ),
)

CHECKPOINT_MGMT_PROFILE: Final = CollectionProfile(
    platform="checkpoint_mgmt",
    # The Management API is POST-only by design, so there is no session to configure and
    # no read-only guarantee to be had from the method. Every entry below is a `show-*`
    # command, which is what `_checkpoint_show_only` in readonly.py enforces — the login
    # itself is also opened with `read-only: true` (http_transport.py), so both a
    # client-side and a server-side restriction apply.
    setup=(),
    transport=Transport.RPC,
    bundled=True,
    commands=(
        CollectionCommand(
            "POST /web_api/show-access-rulebase",
            "The security policy itself — on Check Point it lives here, not on the gateway",
            required=True,
            yields_config=True,
            # 500 is the server's maximum. Check Point's own guidance is that the
            # largest page is not the fastest — the response is big and the server
            # works harder per chunk — but the cost here is per collection, not per
            # interaction, and fewer round trips against a management server under
            # load is the better trade.
            page_size=500,
        ),
        CollectionCommand(
            "POST /web_api/show-nat-rulebase",
            "NAT rules, for the exposed-service analysis",
            page_size=500,
        ),
        CollectionCommand(
            "POST /web_api/show-gateways-and-servers",
            "Gateway inventory, version and enabled blades",
        ),
        CollectionCommand(
            "POST /web_api/show-administrators",
            "Management administrators and their permission profiles",
        ),
        CollectionCommand(
            "POST /web_api/show-groups",
            "Object groups the rulebase dictionary may not carry in full",
        ),
        CollectionCommand(
            "POST /web_api/show-service-groups",
            "Service groups, for the same reason",
        ),
    ),
)

CHECKPOINT_GAIA_PROFILE: Final = CollectionProfile(
    platform="checkpoint_gaia",
    setup=("set clienv rows 0",),
    commands=(
        CollectionCommand(
            "show configuration",
            "The Gaia OS configuration — interfaces, administrators, SNMP, logging",
            required=True,
            yields_config=True,
        ),
        CollectionCommand("show version all", "Gaia version and build, for vulnerability matching"),
        CollectionCommand("show asset all", "Hardware model and serial"),
        CollectionCommand("show interfaces all", "Live interface state, absent from the config"),
        CollectionCommand("show users", "Accounts that exist, including any the config omits"),
        CollectionCommand("show password-controls all", "The effective password policy"),
        CollectionCommand("show ntp servers", "NTP peering"),
        CollectionCommand("show clock", "Whether the clock is plausibly synchronised"),
        CollectionCommand("show route", "The forwarding table, including learned routes"),
        CollectionCommand("fw ver", "Firewall module version"),
        CollectionCommand("fw stat", "Which policy is installed, and when"),
        CollectionCommand("enabled_blades", "Which software blades are actually running"),
        CollectionCommand("cplic print", "Licence state, which gates several blades"),
    ),
)

#: IOS-XE shares IOS's configuration syntax and its command set.
PROFILES: Final[dict[str, CollectionProfile]] = {
    "cisco_ios": CISCO_IOS_PROFILE,
    "cisco_iosxe": CISCO_IOS_PROFILE,
    "cisco_nxos": CISCO_NXOS_PROFILE,
    "cisco_asa": CISCO_ASA_PROFILE,
    "cisco_wlc_aireos": CISCO_WLC_PROFILE,
    "cisco_ise": CISCO_ISE_PROFILE,
    "fortios": FORTIOS_PROFILE,
    "panos": PANOS_PROFILE,
    "checkpoint_mgmt": CHECKPOINT_MGMT_PROFILE,
    "checkpoint_gaia": CHECKPOINT_GAIA_PROFILE,
    "fortiauthenticator": FORTIAUTHENTICATOR_PROFILE,
    "freeradius": FREERADIUS_PROFILE,
    "tac_plus": TACPLUS_PROFILE,
}


class NoProfileError(LookupError):
    """No collection profile exists for a platform."""


def get_profile(platform: str) -> CollectionProfile:
    try:
        return PROFILES[platform]
    except KeyError:
        raise NoProfileError(
            f"No collection profile is defined for platform '{platform}'. "
            f"Known platforms: {', '.join(sorted(PROFILES))}"
        ) from None


def has_profile(platform: str | None) -> bool:
    return platform in PROFILES


__all__ = [
    "PROFILES",
    "CollectionCommand",
    "CollectionProfile",
    "NoProfileError",
    "Transport",
    "get_profile",
    "has_profile",
]
