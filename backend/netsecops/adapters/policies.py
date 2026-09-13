"""Per-platform read-only allow-lists — SRS §8.2, as data.

This file is the single place a customer's security reviewer needs to read to know
exactly what NetSecOps may send to their equipment. ``netsecops-cli audit-commands``
prints it, and the conformance tests assert that no adapter ever emits anything absent
from it.

Rules of the road when adding an entry:

- Add the *narrowest* command that yields the data. ``show run object`` beats
  ``show running-config`` if it answers the question.
- ``session_only=True`` is only for commands that change the CLI session and nothing
  else — paging, terminal width, scripting mode. If you find yourself reaching for it
  to silence the deny-list on a real command, the command does not belong here.
- Cite the SRS or vendor documentation in ``note`` when a rule looks surprising.
"""

from __future__ import annotations

from typing import Final

from netsecops.adapters.readonly import CommandRule, HttpRule, PlatformPolicy


def _cmds(*patterns: str) -> tuple[CommandRule, ...]:
    return tuple(CommandRule(pattern=p) for p in patterns)


# ─────────────────────────── Cisco IOS / IOS-XE ─────────────────────────────

CISCO_IOS = PlatformPolicy(
    platform="cisco_ios",
    commands=(
        CommandRule(
            "terminal length 0", session_only=True, note="Disables paging for this session only"
        ),
        CommandRule("terminal width 512", session_only=True, note="Session-only formatting"),
        CommandRule("enable", note="SRS §8.1.4 — enable mode is permitted; config mode is not"),
        *_cmds(
            "show version",
            "show running-config [all]",
            "show inventory",
            "show ip interface brief",
            "show interfaces status",
            "show interfaces description",
            "show cdp neighbors detail",
            "show lldp neighbors detail",
            "show vlan brief",
            "show spanning-tree summary",
            "show ip route summary",
            "show ip ssh",
            "show ssh",
            "show crypto key mypubkey rsa",
            "show snmp community",
            "show snmp user",
            "show aaa servers",
            "show aaa method-lists all",
            "show tacacs",
            "show radius server-group all",
            "show ntp status",
            "show ntp associations",
            "show logging | include (Trap|Buffer|Logging to)",
            "show users",
            "show access-lists",
            "show ip access-lists",
            "show line",
            "show clock",
            "show archive",
            "show ip http server status",
            "show crypto pki certificates",
            "show boot",
            "show redundancy",
            "show stackwise-virtual",
            "show switch",
            "show port-security",
            "show ip dhcp snooping",
            "show ip arp inspection",
            "show errdisable recovery",
            "show wireless summary",
            "show wlan summary",
            "show wlan all",
            "show ap summary",
            "show ap config general <name>",
            "show wireless profile policy summary",
        ),
    ),
)

# ────────────────────────────── Cisco NX-OS ─────────────────────────────────

CISCO_NXOS = PlatformPolicy(
    platform="cisco_nxos",
    commands=(
        CommandRule(
            "terminal length 0",
            session_only=True,
            note="Disables paging for this session only",
        ),
        *_cmds(
            "show version",
            "show running-config [all]",
            "show inventory",
            "show interface brief",
            "show cdp neighbors detail",
            "show vlan brief",
            "show vpc",
            "show feature",
            "show ssh server",
            "show snmp community",
            "show snmp user",
            "show aaa authentication",
            "show aaa authorization",
            "show tacacs-server",
            "show radius-server",
            "show ntp peers",
            "show logging server",
            "show user-account",
            "show role",
            "show access-lists",
            "show hardware",
            "show system resources",
        ),
    ),
)

# ────────────────────────────── Cisco IOS-XR ────────────────────────────────

CISCO_IOSXR = PlatformPolicy(
    platform="cisco_iosxr",
    commands=(
        CommandRule(
            "terminal length 0",
            session_only=True,
            note="Disables paging for this session only",
        ),
        *_cmds(
            "show version",
            "show running-config",
            "show inventory",
            "show ipv4 interface brief",
            "show ssh",
            "show aaa",
            "show tacacs",
            "show radius",
            "show ntp associations",
            "show logging",
            "show user",
            "show install active summary",
        ),
    ),
)

# ──────────────────────────────── Cisco ASA ─────────────────────────────────

CISCO_ASA = PlatformPolicy(
    platform="cisco_asa",
    commands=(
        CommandRule(
            "terminal pager 0", session_only=True, note="ASA equivalent of terminal length 0"
        ),
        CommandRule("enable"),
        *_cmds(
            "show version",
            "show running-config [all]",
            "show inventory",
            "show interface ip brief",
            "show nameif",
            "show access-list",
            "show nat",
            "show ssh",
            "show ssh sessions",
            "show snmp-server statistics",
            "show aaa-server",
            "show ntp associations",
            "show logging",
            "show crypto ca certificates",
            "show crypto ikev1 sa",
            "show crypto ikev2 sa",
            "show failover",
            "show context",
            "show local-host",
            "show run access-group",
            "show run object",
            "show run object-group",
            "show run service-policy",
            "show run policy-map",
            "show run class-map",
            "show run http",
            "show run ssh",
            "show run username",
        ),
    ),
)

# ───────────────────────── Cisco WLC (AireOS) ───────────────────────────────

CISCO_WLC_AIREOS = PlatformPolicy(
    platform="cisco_wlc_aireos",
    commands=(
        CommandRule(
            "config paging disable",
            session_only=True,
            note="SRS §8.2 explicit exception: affects the CLI session only, despite the 'config' verb",
        ),
        *_cmds(
            "show sysinfo",
            "show run-config",
            "show run-config commands",
            "show wlan summary",
            "show wlan <id>",
            "show ap summary",
            "show ap config general <name>",
            "show radius summary",
            "show tacacs summary",
            "show mgmtuser",
            "show network summary",
            "show snmpcommunity",
            "show snmpv3user",
            "show certificate summary",
            "show rogue ap summary",
            "show interface summary",
            "show time",
            "show logging",
            "show local-auth config",
            "show wps summary",
        ),
    ),
)

# ────────────────────── Check Point Gaia (clish) ────────────────────────────

CHECKPOINT_GAIA = PlatformPolicy(
    platform="checkpoint_gaia",
    commands=(
        CommandRule(
            "set clienv rows 0",
            session_only=True,
            note="SRS §8.2 explicit exception: clish pager, session-only",
        ),
        *_cmds(
            "show configuration",
            "show version all",
            "show asset all",
            "show interfaces all",
            "show hostname",
            "show ntp servers",
            "show snmp <subject>",
            "show aaa <subject>",
            "show user <name>",
            "show users",
            "show password-controls all",
            "show syslog all",
            "show clock",
            "show route",
            "cpstat os -f all",
            "cpinfo -y all",
            "fw ver",
            "fw stat",
            "enabled_blades",
            "cplic print",
        ),
    ),
)

#: Expert-mode reads, permitted only when a device carries ``allow_expert=true``
#: (SRS §8.2, Appendix D open question 2 — default off).
CHECKPOINT_GAIA_EXPERT = PlatformPolicy(
    platform="checkpoint_gaia_expert",
    commands=(
        *CHECKPOINT_GAIA.commands,
        *_cmds(
            "cat $FWDIR/conf/fwauthd.conf",
            "fw ctl pstat",
            "cphaprob -a if",
            "cphaprob state",
        ),
    ),
)

# ─────────────────── Linux AAA hosts (FreeRADIUS / tac_plus) ────────────────

LINUX_AAA = PlatformPolicy(
    platform="linux_aaa",
    commands=_cmds(
        "cat <path>",
        "ls -la <path>",
        "stat <path>",
        "find <path> -type f",
        "freeradius -v",
        "radiusd -v",
        "tac_plus -v",
        "openssl x509 -in <path> -noout -text",
        "systemctl is-active <service>",
        "ss -lntup",
        "cat /etc/os-release",
    ),
)

#: Only when a device carries ``allow_sudo_read=true`` (SRS §8.2).
LINUX_AAA_SUDO = PlatformPolicy(
    platform="linux_aaa_sudo",
    commands=(*LINUX_AAA.commands, *_cmds("sudo -n cat <path>")),
)

# ────────────────────────── FortiGate (REST + SSH) ──────────────────────────

_FORTIGATE_GET_PREFIXES: Final[tuple[str, ...]] = (
    "/api/v2/monitor/system/status",
    "/api/v2/monitor/system/ha-peer",
    "/api/v2/monitor/system/firmware",
    "/api/v2/monitor/system/config/backup",
    "/api/v2/monitor/firewall/policy",
    "/api/v2/monitor/wifi/managed_ap",
    "/api/v2/monitor/switch-controller/managed-switch",
    "/api/v2/cmdb/system/",
    "/api/v2/cmdb/log.syslogd/setting",
    "/api/v2/cmdb/firewall/",
    "/api/v2/cmdb/firewall.service/",
    "/api/v2/cmdb/user/",
    "/api/v2/cmdb/vpn.ipsec/",
    "/api/v2/cmdb/vpn.certificate/",
    "/api/v2/cmdb/wireless-controller/",
    "/api/v2/cmdb/ips/sensor",
    "/api/v2/cmdb/antivirus/profile",
    "/api/v2/cmdb/webfilter/profile",
    "/api/v2/cmdb/dnsfilter/profile",
)

FORTIGATE = PlatformPolicy(
    platform="fortios",
    # SRS §8.2: FortiGate SSH must never pipe.
    forbid_pipe=True,
    commands=_cmds(
        "show full-configuration",
        "show",
        "get system status",
        "get system ha status",
        "get system performance status",
        "get system interface physical",
        "get system admin list",
        "get router info routing-table all",
        "get user radius",
        "diagnose sys top",
    ),
    http=tuple(
        HttpRule("GET", prefix, reason="FortiOS read endpoint (SRS §8.2)")
        for prefix in _FORTIGATE_GET_PREFIXES
    ),
)

# ──────────────────────────── FortiManager ──────────────────────────────────

FORTIMANAGER = PlatformPolicy(
    platform="fortimanager",
    http=(
        HttpRule(
            "POST",
            "/jsonrpc",
            reason="JSON-RPC is POST-only; the body must carry method=get, or an "
            "exec limited to login/logout (SRS §8.1.3c)",
            body_predicate="fortimanager_get_only",
        ),
    ),
)

# ───────────────────────── FortiAuthenticator ───────────────────────────────

FORTIAUTHENTICATOR = PlatformPolicy(
    platform="fortiauthenticator",
    http=tuple(
        HttpRule("GET", prefix)
        for prefix in (
            "/api/v1/radiusclients/",
            "/api/v1/localusers/",
            "/api/v1/usergroups/",
            "/api/v1/ldapservers/",
            "/api/v1/certificates/",
            "/api/v1/system/",
            "/api/v1/adminprofiles/",
        )
    ),
)

# ────────────────────────── PAN-OS / Panorama ───────────────────────────────

PANOS = PlatformPolicy(
    platform="panos",
    http=(
        HttpRule(
            "GET",
            "/api/",
            reason="XML API reads are issued as GET where the vendor permits it",
        ),
        HttpRule(
            "POST",
            "/api/",
            reason="XML API accepts POST; the body must be keygen, an op show, a "
            "config show/get, or an export of configuration/certificate (SRS §8.1.3d)",
            body_predicate="panos_read_only",
        ),
        *(
            HttpRule("GET", prefix, reason="PAN-OS REST read")
            for prefix in (
                "/restapi/v10.1/Policies/",
                "/restapi/v10.1/Objects/",
                "/restapi/v10.1/Network/",
                "/restapi/v10.1/Device/",
                "/restapi/v11.0/Policies/",
                "/restapi/v11.0/Objects/",
                "/restapi/v11.0/Network/",
                "/restapi/v11.0/Device/",
            )
        ),
    ),
)

# ────────────────── Check Point Management API (POST-only) ──────────────────

CHECKPOINT_MGMT = PlatformPolicy(
    platform="checkpoint_mgmt",
    http=(
        HttpRule(
            "POST",
            "/web_api/",
            reason="The Management API is POST-only; the command must be show-*, "
            "login, logout or keepalive (SRS §8.1.3b)",
            body_predicate="checkpoint_show_only",
        ),
    ),
)

# ─────────────────────────── Cisco FMC / ISE ────────────────────────────────

CISCO_FMC = PlatformPolicy(
    platform="cisco_ftd_fmc",
    http=(
        HttpRule(
            "POST",
            "/api/fmc_platform/v1/auth/generatetoken",
            reason="Token generation only (SRS §8.1.3e)",
            body_predicate="auth_only",
        ),
        HttpRule("GET", "/api/fmc_platform/v1/"),
        HttpRule("GET", "/api/fmc_config/v1/"),
        HttpRule("GET", "/api/fdm/v6/", reason="FDM device-managed read (optional)"),
    ),
)

CISCO_ISE = PlatformPolicy(
    platform="cisco_ise",
    http=(
        HttpRule("GET", "/ers/config/"),
        HttpRule("GET", "/api/v1/policy/"),
        HttpRule("GET", "/api/v1/certs/"),
        HttpRule("GET", "/api/v1/deployment/"),
        HttpRule("GET", "/api/v1/repository"),
        HttpRule("GET", "/api/v1/system-settings/"),
        HttpRule("GET", "/api/v1/backup-restore/config/last-backup-status"),
        HttpRule("GET", "/api/v1/patch"),
        HttpRule("GET", "/api/v1/hotpatch"),
    ),
)


# ─────────────────────────────── registry ───────────────────────────────────

#: Platforms whose read-only contract is genuinely identical to another's, sharing the
#: same policy object rather than a copied list. A reviewer reads one list and knows it
#: governs both; a copy would drift the first time someone amended only one of them.
ALIASES: Final[dict[str, PlatformPolicy]] = {
    # IOS-XE is IOS at the CLI. The differences are in platform features, not in which
    # commands exist or which of them write.
    "cisco_iosxe": CISCO_IOS,
}

POLICIES: Final[dict[str, PlatformPolicy]] = {
    policy.platform: policy
    for policy in (
        CISCO_IOS,
        CISCO_NXOS,
        CISCO_IOSXR,
        CISCO_ASA,
        CISCO_WLC_AIREOS,
        CISCO_FMC,
        CISCO_ISE,
        PANOS,
        FORTIGATE,
        FORTIMANAGER,
        FORTIAUTHENTICATOR,
        CHECKPOINT_MGMT,
        CHECKPOINT_GAIA,
        CHECKPOINT_GAIA_EXPERT,
        LINUX_AAA,
        LINUX_AAA_SUDO,
    )
} | ALIASES


def get_policy(platform: str) -> PlatformPolicy:
    """Look up a platform's read-only contract.

    An unknown platform is a hard error, not a permissive default: a device we cannot
    describe is a device we must not touch.
    """
    try:
        return POLICIES[platform]
    except KeyError:
        raise KeyError(
            f"No read-only policy is defined for platform '{platform}'. "
            "Add one to netsecops/adapters/policies.py before collecting from it."
        ) from None
