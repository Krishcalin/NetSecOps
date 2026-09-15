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

**What is not yet verified.** The product strings here are written from the CPE naming
convention and have *not* been checked against a real NVD dictionary — there is no feed
data in the repository to check them against. :func:`unverified_products` exists so the
feed-ingestion slice can do exactly that once it has the dictionary, and
`test_vuln_cpe.py::TestProductNamesAreVerifiedWhenFeedsLand` records the obligation.
Treat every entry as provisional until then.
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
#: Provisional — see the module docstring. Each entry is the name the CPE dictionary is
#: expected to use, and a platform missing from here deliberately produces no CPE.
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
    "checkpoint_mgmt": ProductName(Part.APPLICATION, "checkpoint", "security_management"),
    "freeradius": ProductName(Part.APPLICATION, "freeradius", "freeradius"),
    "tac_plus": ProductName(Part.APPLICATION, "shrubbery", "tac_plus"),
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
    """
    vendor = HARDWARE_VENDORS.get((ncm.device.vendor or "").strip().lower())
    model = (ncm.device.model or "").strip()
    if not vendor or not model:
        return None

    return Cpe(part=Part.HARDWARE, vendor=vendor, product=model, version="-")


def unverified_products() -> dict[str, str]:
    """Every CPE product string this module will emit, for checking against a real
    dictionary.

    The feed-ingestion slice calls this once it holds the NVD CPE dictionary and reports
    any entry with no match. Until then every name here is provisional, and this function
    is the list of what has to be confirmed.
    """
    return {
        platform: f"{name.vendor}:{name.product}" for platform, name in sorted(PRODUCTS.items())
    }


__all__ = [
    "HARDWARE_VENDORS",
    "PRODUCTS",
    "Cpe",
    "Part",
    "ProductName",
    "hardware_cpe",
    "quote",
    "software_cpe",
    "unverified_products",
]
