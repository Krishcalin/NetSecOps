"""Parser registry (C-6).

One lookup from platform to parser, so nothing outside this package needs a vendor
conditional. An unknown platform raises rather than returning a permissive default: a
device whose configuration we cannot interpret must not be silently reported as clean.
"""

from __future__ import annotations

from typing import Final

from netsecops.parsers.arista.eos import AristaEosParser
from netsecops.parsers.barracuda.waf import BarracudaWafParser
from netsecops.parsers.base import ConfigParser
from netsecops.parsers.checkpoint.gaia import CheckPointGaiaParser
from netsecops.parsers.checkpoint.mgmt import CheckPointMgmtParser
from netsecops.parsers.cisco.aci import CiscoAciParser
from netsecops.parsers.cisco.asa import CiscoAsaParser
from netsecops.parsers.cisco.fmc import CiscoFmcParser
from netsecops.parsers.cisco.ios import CiscoIosParser
from netsecops.parsers.cisco.ise import CiscoIseParser
from netsecops.parsers.cisco.nxos import CiscoNxosParser
from netsecops.parsers.cisco.wlc import CiscoWlcParser
from netsecops.parsers.cloud.aws import AwsParser
from netsecops.parsers.cloud.azure import AzureNsgParser
from netsecops.parsers.f5.bigip import F5BigIpParser
from netsecops.parsers.fortinet.fortiauthenticator import FortiAuthenticatorParser
from netsecops.parsers.fortinet.fortios import FortiOsParser
from netsecops.parsers.juniper.junos import JunosParser
from netsecops.parsers.linux.freeradius import FreeRadiusParser
from netsecops.parsers.linux.tacplus import TacPlusParser
from netsecops.parsers.paloalto.panos import PanOsParser
from netsecops.parsers.radware.alteon import RadwareAlteonParser
from netsecops.parsers.symantec.proxysg import SymantecProxySgParser
from netsecops.parsers.vmware.nsx import VmwareNsxParser

PARSERS: Final[dict[str, type[ConfigParser]]] = {
    "cisco_ios": CiscoIosParser,
    # IOS-XE is IOS as far as configuration syntax goes; the differences are in
    # platform features, not in how the running-config is written.
    "cisco_iosxe": CiscoIosParser,
    # A Catalyst 9800 writes its WLANs, policy profiles and AP blocks into an ordinary
    # IOS-XE running configuration, which `CiscoIosParser._parse_wireless` has read
    # since Phase 5. It is a separate platform because it is asked *more* — see
    # `CISCO_C9800_PROFILE` — not because it reads differently. An Embedded Wireless
    # Controller on a Catalyst AP is the same image and shares this key.
    "cisco_c9800": CiscoIosParser,
    "cisco_nxos": CiscoNxosParser,
    "cisco_asa": CiscoAsaParser,
    # AireOS is a command-list format, not a configuration file — see the parser.
    "cisco_wlc_aireos": CiscoWlcParser,
    # ISE is an AAA *server*: it fills `aaa_server` rather than `aaa` (FR-AAA-02).
    "cisco_ise": CiscoIseParser,
    # Firepower through its management centre. A bundle of REST responses rather than a
    # configuration, and the first platform to emit a non-terminating rule action.
    "cisco_ftd_fmc": CiscoFmcParser,
    # A forward proxy. No rulebase — SGOS policy is CPL in a separate file that
    # `show configuration` does not emit — so `firewall.security_rules` stays empty and
    # a rulebase check reports Not Evaluated rather than a clean device.
    "symantec_proxysg": SymantecProxySgParser,
    # ── read from an export, with no collection profile ──────────────────────
    # These four have a parser and deliberately no profile. Each needs a credential
    # type and a transport this product does not have, and a parser wired to a
    # collector that does not exist is the capability-with-no-surface pattern. They are
    # ingested through FR-COL-11 instead, which is how a read-restricted cloud or
    # vSphere estate was always going to be assessed. The collectors are their own
    # slice, with their own credential design.
    "cisco_aci": CiscoAciParser,
    "vmware_nsx": VmwareNsxParser,
    "aws_vpc": AwsParser,
    "azure_nsg": AzureNsgParser,
    "fortios": FortiOsParser,
    "panos": PanOsParser,
    # Check Point splits in two: the security policy lives on the management server and
    # is read over its API, while the gateway itself only holds the Gaia OS
    # configuration. Neither can answer the other's questions, so they are separate
    # platforms rather than one parser guessing which it was handed.
    "checkpoint_mgmt": CheckPointMgmtParser,
    "checkpoint_gaia": CheckPointGaiaParser,
    # EOS is IOS-like enough to share `CiscoStyleParser`, and different enough not to
    # share `CiscoIosParser`: CIDR addresses and routes, `management ssh` in place of
    # `line vty`, and a role on every username.
    "arista_eos": AristaEosParser,
    # An ADC like Alteon, and it fills `load_balancer` the same way — but its brace
    # tree has no statement terminators, so it reads with its own parser rather than
    # the Junos one.
    "f5_bigip": F5BigIpParser,
    # SRX, MX and EX share one key: the configuration format belongs to Junos rather
    # than to the chassis, and the parser reads either the brace form or `display set`.
    "juniper_junos": JunosParser,
    # An ADC, so it is the first platform to fill `load_balancer`. Its menu-path dump is
    # unlike anything else here and has its own parser rather than a syntax flag.
    "radware_alteon": RadwareAlteonParser,
    # A WAF is a reverse proxy, so it fills `load_balancer` too — its services are VIPs
    # and its back ends are real servers. What it adds is `enforcement`: whether a
    # listener blocks what it detects or only logs it.
    "barracuda_waf": BarracudaWafParser,
    # AAA servers (FR-AAA-02 … FR-AAA-04). These fill `aaa_server` rather than `aaa`:
    # they are the service the estate authenticates *against*, not a consumer of it.
    "fortiauthenticator": FortiAuthenticatorParser,
    "freeradius": FreeRadiusParser,
    "tac_plus": TacPlusParser,
}


class NoParserError(LookupError):
    """No parser is registered for a platform."""


def get_parser(platform: str) -> ConfigParser:
    """Return a parser instance for ``platform``."""
    try:
        return PARSERS[platform]()
    except KeyError:
        raise NoParserError(
            f"No configuration parser is registered for platform '{platform}'. "
            f"Known platforms: {', '.join(sorted(PARSERS))}"
        ) from None


def supported_platforms() -> list[str]:
    return sorted(PARSERS)


__all__ = ["PARSERS", "NoParserError", "get_parser", "supported_platforms"]
