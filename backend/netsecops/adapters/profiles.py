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
from typing import Final

from netsecops.core.errors import ValidationProblem


@dataclass(frozen=True, slots=True)
class CollectionCommand:
    command: str
    #: Why it is issued. Shown in the UI beside the artefact, so an operator watching a
    #: collection can tell what NetSecOps wanted rather than only what it sent.
    purpose: str
    #: A failure here aborts the collection. True for the configuration alone.
    required: bool = False
    #: This command's output is the running configuration, and is what gets parsed.
    yields_config: bool = False


@dataclass(frozen=True, slots=True)
class CollectionProfile:
    platform: str
    #: Session setup: paging, width. Never recorded as artefacts — they produce no data
    #: and would clutter the evidence with noise.
    setup: tuple[str, ...]
    commands: tuple[CollectionCommand, ...]

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

#: IOS-XE shares IOS's configuration syntax and its command set.
PROFILES: Final[dict[str, CollectionProfile]] = {
    "cisco_ios": CISCO_IOS_PROFILE,
    "cisco_iosxe": CISCO_IOS_PROFILE,
    "cisco_nxos": CISCO_NXOS_PROFILE,
    "cisco_asa": CISCO_ASA_PROFILE,
    "fortios": FORTIOS_PROFILE,
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
    "get_profile",
    "has_profile",
]
