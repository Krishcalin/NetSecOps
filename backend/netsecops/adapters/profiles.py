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
from typing import Final

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

    def as_request(self) -> tuple[str, str]:
        """Split an HTTP entry into (method, path)."""
        method, _, path = self.command.partition(" ")
        return method.upper(), path

    def as_body(self) -> dict[str, str]:
        """The JSON body an RPC entry sends.

        Derived from the path rather than declared separately: on the Check Point
        Management API the operation *is* the last path segment, so deriving it means the
        conformance test checks the same string that is actually sent. A hand-written
        second copy could drift from the path and would then be proving nothing.
        """
        _method, path = self.as_request()
        return {"command": path.rsplit("/", 1)[-1]}


@dataclass(frozen=True, slots=True)
class CollectionProfile:
    platform: str
    #: Session setup: paging, width. Never recorded as artefacts — they produce no data
    #: and would clutter the evidence with noise. Empty for HTTP platforms, which have
    #: no session to configure.
    setup: tuple[str, ...]
    commands: tuple[CollectionCommand, ...]
    transport: Transport = Transport.CLI

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
            "get router info routing-table all", "Routing table, for reachability context"
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
        CollectionCommand(
            "GET /api/?type=op&cmd=<show><counter><global></global></counter></show>",
            "Rule hit counts, which the configuration does not carry",
        ),
    ),
)

CHECKPOINT_MGMT_PROFILE: Final = CollectionProfile(
    platform="checkpoint_mgmt",
    # The Management API is POST-only by design, so there is no session to configure and
    # no read-only guarantee to be had from the method. Every entry below is a `show-*`
    # command, which is what `checkpoint_show_only` in policies.py actually enforces.
    setup=(),
    transport=Transport.RPC,
    commands=(
        CollectionCommand(
            "POST /web_api/show-access-rulebase",
            "The security policy itself — on Check Point it lives here, not on the gateway",
            required=True,
            yields_config=True,
        ),
        CollectionCommand(
            "POST /web_api/show-nat-rulebase",
            "NAT rules, for the exposed-service analysis",
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
    "fortios": FORTIOS_PROFILE,
    "panos": PANOS_PROFILE,
    "checkpoint_mgmt": CHECKPOINT_MGMT_PROFILE,
    "checkpoint_gaia": CHECKPOINT_GAIA_PROFILE,
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
