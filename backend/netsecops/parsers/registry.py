"""Parser registry (C-6).

One lookup from platform to parser, so nothing outside this package needs a vendor
conditional. An unknown platform raises rather than returning a permissive default: a
device whose configuration we cannot interpret must not be silently reported as clean.
"""

from __future__ import annotations

from typing import Final

from netsecops.parsers.base import ConfigParser
from netsecops.parsers.cisco.asa import CiscoAsaParser
from netsecops.parsers.cisco.ios import CiscoIosParser
from netsecops.parsers.cisco.nxos import CiscoNxosParser
from netsecops.parsers.fortinet.fortios import FortiOsParser

PARSERS: Final[dict[str, type[ConfigParser]]] = {
    "cisco_ios": CiscoIosParser,
    # IOS-XE is IOS as far as configuration syntax goes; the differences are in
    # platform features, not in how the running-config is written.
    "cisco_iosxe": CiscoIosParser,
    "cisco_nxos": CiscoNxosParser,
    "cisco_asa": CiscoAsaParser,
    "fortios": FortiOsParser,
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
