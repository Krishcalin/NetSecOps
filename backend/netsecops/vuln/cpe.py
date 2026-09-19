"""CPE 2.3 identifiers built from the NCM (FR-VUL-01).

A CPE is the join key between a device and the NVD. Get it wrong and nothing matches —
which is the failure mode to design for, because it is silent. A device with a
misspelled product name reports zero vulnerabilities and looks exactly like a device
that is fully patched.

**Two things this module will not do.**

*Guess a product name.* The vendor and product strings below have to match NVD's CPE
dictionary exactly: `cisco:ios_xe`, not `cisco:iosxe` or `cisco:ios-xe`. They are
declared in one table, :data:`PRODUCTS`, and a platform absent from it yields no CPE at
all. A guessed identifier is worse than none, because none is visible as "not matched"
while a guess is indistinguishable from a clean bill of health.

*Emit a wildcard version.* `cpe:2.3:o:cisco:ios:*:...` matches every IOS release ever
published, so a device whose version could not be read would match every IOS advisory in
the database. :func:`software_cpe` returns None when the version is unknown, and the
matcher reports the device as unassessable rather than catastrophically vulnerable.

**Verified against the dictionary on 2026-09-19.** Every string in :data:`PRODUCTS` was
queried against the live NVD CPE API. Eleven matched, with counts from 71 entries
(`fortinet:fortiauthenticator`) to 6,474 (`cisco:ios`). Two did not exist and have been
moved to :data:`NO_DICTIONARY_ENTRY`:

* `checkpoint:security_management` — NVD has no product for the Check Point management
  server. Its Check Point catalogue runs to `security_gateway`, `provider-1`,
  `firewall-1` and `vpn-1`, none of which is the management server, and picking the
  nearest would file management-plane CVEs against the gateway.
* `shrubbery:tac_plus` — there is no `shrubbery` vendor. `tac_plus` exists only as
  `cisco:tac_plus` and `facebook:tac_plus`, which are separate forks of the daemon with
  their own version schemes; a config alone does not say which fork produced it.

Both were silently matching nothing before, which is the failure this module opens by
describing. They now match nothing *visibly*, which is the point of the distinction.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from enum import StrEnum
from typing import Final

from netsecops.core.logging import get_logger
from netsecops.ncm.models import NormalisedConfig

log = get_logger(__name__)


class Part(StrEnum):
    """The CPE part component.

    Network gear needs all three: the OS carries the software CVEs, the hardware carries
    end-of-life and platform-specific advisories, and the AAA servers are applications
    running on something else.
    """

    APPLICATION = "a"
    OS = "o"
    HARDWARE = "h"


@dataclass(frozen=True, slots=True)
class ProductName:
    """One platform's place in the CPE dictionary."""

    part: Part
    vendor: str
    product: str


#: Platform (as the parser registry spells it) to its CPE vendor and product.
#:
#: Every entry verified against the live NVD dictionary — see the module docstring. A
#: platform missing from here deliberately produces no CPE, and one whose product does
#: not exist in the dictionary belongs in :data:`NO_DICTIONARY_ENTRY` rather than here.
PRODUCTS: Final[dict[str, ProductName]] = {
    "cisco_ios": ProductName(Part.OS, "cisco", "ios"),
    "cisco_iosxe": ProductName(Part.OS, "cisco", "ios_xe"),
    "cisco_nxos": ProductName(Part.OS, "cisco", "nx-os"),
    "cisco_asa": ProductName(Part.OS, "cisco", "adaptive_security_appliance_software"),
    "cisco_wlc_aireos": ProductName(Part.OS, "cisco", "wireless_lan_controller_software"),
    # ISE and the other AAA servers are applications: the CVEs are against the product,
    # not against the operating system underneath it.
    "cisco_ise": ProductName(Part.APPLICATION, "cisco", "identity_services_engine"),
    "panos": ProductName(Part.OS, "paloaltonetworks", "pan-os"),
    "fortios": ProductName(Part.OS, "fortinet", "fortios"),
    "fortiauthenticator": ProductName(Part.APPLICATION, "fortinet", "fortiauthenticator"),
    "checkpoint_gaia": ProductName(Part.OS, "checkpoint", "gaia_os"),
    "freeradius": ProductName(Part.APPLICATION, "freeradius", "freeradius"),
}

#: Platforms NetSecOps parses that the NVD dictionary has no product for, and why.
#:
#: Separate from simply being absent from :data:`PRODUCTS`, which would look like an
#: oversight. These were checked, and the honest answer is that no identifier exists —
#: so software CPE matching cannot run for them and the name fallback in the matcher is
#: all there is. Recorded rather than guessed, because a guess produces a confident
#: clean bill of health and an absence produces a visible gap.
NO_DICTIONARY_ENTRY: Final[dict[str, str]] = {
    "checkpoint_mgmt": (
        "NVD has no product for the Check Point management server. Its catalogue covers "
        "security_gateway, provider-1, firewall-1 and vpn-1, and filing management-plane "
        "CVEs against the gateway would attribute them to the wrong device."
    ),
    "tac_plus": (
        "There is no `shrubbery` vendor in NVD. `tac_plus` exists as cisco:tac_plus and "
        "facebook:tac_plus, separate forks with their own version schemes, and a parsed "
        "config does not say which fork produced it."
    ),
}

#: Hardware CPEs are per vendor, not per platform: the model string is the product.
HARDWARE_VENDORS: Final[dict[str, str]] = {
    "cisco": "cisco",
    "paloalto": "paloaltonetworks",
    "fortinet": "fortinet",
    "checkpoint": "checkpoint",
}

#: Characters that stand for themselves in a CPE 2.3 formatted string. Everything else
#: printable is backslash-escaped — parentheses above all, since `15.2(7)E3` is an
#: entirely ordinary Cisco version and an unescaped `(` makes the string unparseable to
#: anything reading it back.
_UNRESERVED = re.compile(r"[A-Za-z0-9._\-]")

#: A CPE component may not contain whitespace. A model string like `Nexus9000 C93180YC-EX`
#: does, and the dictionary spells such products with underscores.
_WHITESPACE = re.compile(r"\s+")


def quote(value: str) -> str:
    """Bind one value into a CPE 2.3 formatted-string component.

    Lowercased, whitespace collapsed to underscores, and every character outside
    ``[A-Za-z0-9._-]`` escaped with a backslash. CPE matching is case-insensitive in
    principle and case-sensitive in every implementation that actually compares strings,
    so the case is normalised here rather than hoped for.
    """
    collapsed = _WHITESPACE.sub("_", value.strip().lower())
    return "".join(
        character if _UNRESERVED.match(character) else "\\" + character for character in collapsed
    )


@dataclass(frozen=True, slots=True)
class Cpe:
    """A CPE 2.3 identifier.

    Only the components NetSecOps can honestly fill are modelled; the rest bind to `*`
    (ANY). `update`, `edition` and the target fields are left ANY deliberately — a
    narrower CPE matches fewer advisories, and inventing a value for a field the device
    never reported would silently exclude the advisories that matter.
    """

    part: Part
    vendor: str
    product: str
    version: str

    def to_string(self) -> str:
        """The formatted-string binding, as NVD publishes it."""
        return ":".join(
            (
                "cpe",
                "2.3",
                self.part.value,
                quote(self.vendor),
                quote(self.product),
                # `-` is CPE's NA, used for hardware, which has no software version.
                self.version if self.version in ("*", "-") else quote(self.version),
                # update, edition, language, sw_edition, target_sw, target_hw, other.
                # Seven, not six: a short CPE shifts every field left of the one it
                # dropped, so `target_hw` would be read as `other` by anything parsing
                # it back, and the string would not match the dictionary at all.
                *("*",) * 7,
            )
        )

    def __str__(self) -> str:
        return self.to_string()


def software_cpe(ncm: NormalisedConfig, *, platform: str | None = None) -> Cpe | None:
    """The OS or application CPE for a device, or None if it cannot be built honestly.

    None is returned when the platform is not in :data:`PRODUCTS` or when the device
    never reported a version. Both are cases where a CPE could be produced and would be
    actively harmful: an unmapped product matches nothing while looking like a clean
    result, and a wildcard version matches every advisory ever written for the product.
    """
    platform = platform or ncm.device.platform
    if not platform:
        return None

    name = PRODUCTS.get(platform)
    if name is None:
        log.debug("vuln.cpe_no_product_mapping", platform=platform)
        return None

    version = (ncm.device.version or "").strip()
    if not version:
        log.debug("vuln.cpe_no_version", platform=platform)
        return None

    return Cpe(part=name.part, vendor=name.vendor, product=name.product, version=version)


def hardware_cpe(ncm: NormalisedConfig) -> Cpe | None:
    """The hardware CPE, or None when the model or vendor is unknown.

    The version component is `-` (NA) rather than `*` (ANY): a chassis has no software
    version, and saying "not applicable" is a different claim from "any", which would
    make the identifier match hardware entries it should not.

    **Coverage is partial, and cannot be made complete.** Unlike :data:`PRODUCTS`, whose
    eleven strings were chosen and are verified, the product here is whatever the parser
    read off the device — an unbounded set, one entry per chassis a customer owns. Eight
    real model strings checked against the NVD dictionary on 2026-09-19:

    * `C9300-48P`, `PA-3220`, `PA-850` — matched exactly.
    * `FortiGate-100F` — NVD writes `fortigate_100f`. Punctuation only.
    * `ASA5525` — NVD writes `asa_5525-x`. Not punctuation: the device reports a shorter
      part number than the dictionary's, and closing that needs product knowledge.
    * `WS-C2960X-48FPD-L`, `Nexus9000 C93180YC-EX` — NVD has no entry at all, for any
      spelling. Not a miss to fix.

    No single normalisation helps: `pa-3220` matches *keeping* its hyphen while
    `fortigate_100f` needs an underscore, so a rule that fixes Fortinet breaks Palo Alto.
    A punctuation-insensitive comparison in :func:`same_product` would cover both and is
    the obvious candidate, but it widens identity matching for every CPE in the system
    and is not worth doing on eight samples without deciding it deliberately.

    What this means in practice: a chassis advisory is matched where the device's own
    model string is what NVD calls the box, and is silently not matched otherwise. The
    failure direction is safe — an unmatched model produces no finding rather than a
    wrong one — but it is a coverage gap, not a solved problem, and
    `GET /vulnerabilities/cpe-coverage` is where an operator should be able to see it.
    """
    vendor = HARDWARE_VENDORS.get((ncm.device.vendor or "").strip().lower())
    model = (ncm.device.model or "").strip()
    if not vendor or not model:
        return None

    return Cpe(part=Part.HARDWARE, vendor=vendor, product=model, version="-")


def product_key(cpe: str) -> tuple[str, str, str] | None:
    """The (part, vendor, product) of a CPE string, for identity comparison.

    Deliberately ignores the version component. An advisory publishes
    `cpe:2.3:o:paloaltonetworks:pan-os:*:...` and states the affected versions separately
    in its product tree, so comparing versions *through* the CPE would compare a device's
    real version against a wildcard and match nothing. Version comparison is
    :mod:`netsecops.vuln.versions`' job and is done against the advisory's stated range.

    Returns None for anything that is not a CPE 2.3 formatted string, rather than
    raising: advisories carry malformed identifiers, and one bad string must not abort a
    whole feed.
    """
    text = (cpe or "").strip().lower()
    if not text.startswith("cpe:2.3:"):
        return None

    # Split on unescaped colons only. A quoted `\:` inside a component is data, and
    # splitting on it would shift every field after it by one.
    parts: list[str] = []
    current: list[str] = []
    escaped = False
    for character in text:
        if escaped:
            current.append(character)
            escaped = False
        elif character == "\\":
            current.append(character)
            escaped = True
        elif character == ":":
            parts.append("".join(current))
            current = []
        else:
            current.append(character)
    parts.append("".join(current))

    if len(parts) < 5:
        return None
    return parts[2], parts[3], parts[4]


def same_product(left: str | None, right: str | None) -> bool:
    """Whether two CPE strings name the same product, ignoring version.

    False when either is missing or unparseable — an unknown identifier is not a match,
    and treating it as one would attach advisories to devices on the strength of a
    string nobody could read.
    """
    if not left or not right:
        return False
    parsed_left, parsed_right = product_key(left), product_key(right)
    if parsed_left is None or parsed_right is None:
        return False
    return parsed_left == parsed_right


def unverified_products() -> dict[str, str]:
    """Every CPE product string this module will emit, for checking against a real
    dictionary.

    Named for the state it was written in. All of these have since been confirmed
    against the live NVD dictionary — see the module docstring — and the two that had no
    entry were moved to :data:`NO_DICTIONARY_ENTRY`. The function stays because the
    dictionary is not fixed: a vendor rename or a product NVD retires would put an entry
    back in the state this was built to find, and re-running it is how that is noticed.
    """
    return {
        platform: f"{name.vendor}:{name.product}" for platform, name in sorted(PRODUCTS.items())
    }


__all__ = [
    "HARDWARE_VENDORS",
    "NO_DICTIONARY_ENTRY",
    "PRODUCTS",
    "Cpe",
    "Part",
    "ProductName",
    "hardware_cpe",
    "product_key",
    "quote",
    "same_product",
    "software_cpe",
    "unverified_products",
]
