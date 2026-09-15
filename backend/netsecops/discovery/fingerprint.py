"""Identifying a device from what it volunteers (FR-DISC-03).

    The system SHALL fingerprint vendor/platform from SSH banner, TLS certificate
    subject, HTTP headers/login page markers and SNMP sysObjectID, with a
    confidence score.

Four signals, and they are not of equal worth. Treating them as though they were is the
mistake this module is built to avoid, because the resulting confidence number gets read
as though it means something.

**sysObjectID is the only authoritative signal.** It is a structured OID rooted in the
device's IANA Private Enterprise Number, emitted by the agent, and not a string anybody
sets in a config file. **A banner is a preference.** `SSH-2.0-Cisco-1.25` is strong
evidence, but an operator can set it to anything, and plenty do. **A TLS subject names
whoever generated the certificate**, which after a decade of estate management may be
the customer's own CA rather than the vendor. So the signals carry different weights,
and the weights are declared rather than implied by the order of an if-chain.

**Conflicting signals are reported, never resolved.** If SSH says Cisco and the TLS
certificate says Fortinet, the honest reading is not "Cisco, 60% confident" — it is that
something is wrong: a load balancer in front of the host, a NAT collapsing two devices
onto one address, or a certificate nobody rotated after a hardware swap. Picking the
heavier signal and moving on produces a plausible, wrong inventory entry that somebody
will later assign credentials to. Conflicts lower the score *and* are listed.

**Nothing here authenticates**, so confidence is capped below certainty
(:data:`MAX_CONFIDENCE`). Every probe this reads is a string the far end chose to send.
FR-DISC-04 requires human approval before a discovered host is assessed, and a score of
100 invites exactly the automation that requirement exists to prevent.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Final

from netsecops.core.logging import get_logger

log = get_logger(__name__)


class Signal(StrEnum):
    """Where a piece of evidence came from."""

    SNMP_SYSOBJECTID = "snmp_sysobjectid"
    SNMP_SYSDESCR = "snmp_sysdescr"
    SSH_BANNER = "ssh_banner"
    TLS_SUBJECT = "tls_subject"
    HTTP_HEADER = "http_header"


#: What each signal is worth, and why.
#:
#: sysObjectID is authoritative: an OID rooted in the vendor's IANA enterprise number,
#: emitted by the SNMP agent rather than configured as text. sysDescr is nearly as good
#: but is a free-text field some platforms let you override. A banner and an HTTP header
#: are operator-settable. A TLS subject names whoever issued the certificate, which on a
#: long-lived estate is often the customer's own CA.
WEIGHTS: Final[dict[Signal, int]] = {
    Signal.SNMP_SYSOBJECTID: 50,
    Signal.SNMP_SYSDESCR: 35,
    Signal.SSH_BANNER: 25,
    Signal.TLS_SUBJECT: 20,
    Signal.HTTP_HEADER: 15,
}

#: Fingerprinting infers; it never authenticates. Every input is a string the far end
#: chose to send, so the score stops short of certainty and FR-DISC-04's review step
#: stays meaningful.
MAX_CONFIDENCE: Final[int] = 90

#: IANA Private Enterprise Numbers, which prefix every vendor's sysObjectID subtree.
#: An OID outside this table yields no vendor rather than a guess — the estate is full
#: of printers, UPSes and cameras, and naming one of them "cisco" because the OID looked
#: familiar puts it in an inventory somebody will try to collect from.
ENTERPRISE_NUMBERS: Final[dict[str, str]] = {
    "9": "cisco",
    "25461": "paloalto",
    "12356": "fortinet",
    "2620": "checkpoint",
    "2636": "juniper",
}

#: sysObjectID subtrees precise enough to name a platform, not merely a vendor.
#: Deliberately sparse: a vendor match with no platform is a useful, honest result.
PLATFORM_OIDS: Final[tuple[tuple[str, str], ...]] = (
    ("1.3.6.1.4.1.9.1.", "cisco_ios"),
    ("1.3.6.1.4.1.9.12.3.1.3.", "cisco_nxos"),
    ("1.3.6.1.4.1.9.1.745", "cisco_asa"),
    ("1.3.6.1.4.1.25461.2.3.", "panos"),
    ("1.3.6.1.4.1.12356.101.1.", "fortios"),
)

#: Text patterns, each mapping to (vendor, platform-or-None).
#:
#: Only patterns that actually discriminate are listed. A PAN-OS box answers SSH with a
#: stock `SSH-2.0-OpenSSH_7.5` and a Check Point gateway with something equally generic;
#: matching those would attribute every Linux host in the estate to a firewall vendor.
#: Where a vendor has no distinctive string, it is simply absent, and the signal
#: contributes nothing rather than contributing noise.
TEXT_PATTERNS: Final[tuple[tuple[re.Pattern[str], str, str | None], ...]] = (
    (re.compile(r"\bCisco-\d", re.I), "cisco", None),
    (re.compile(r"\bCisco\s+IOS[- ]XE\b", re.I), "cisco", "cisco_iosxe"),
    (re.compile(r"\bCisco\s+IOS\b", re.I), "cisco", "cisco_ios"),
    (re.compile(r"\bNX-OS\b", re.I), "cisco", "cisco_nxos"),
    (re.compile(r"\bAdaptive Security Appliance\b", re.I), "cisco", "cisco_asa"),
    (re.compile(r"\bCisco Systems\b", re.I), "cisco", None),
    # No trailing `\b` on these two. An underscore is a word character, so `\bFortiSSH\b`
    # does not match `SSH-2.0-FortiSSH_1.0` — which is the exact string a FortiGate
    # sends. Vendors suffix product names with `_version` constantly, and a trailing
    # boundary silently turns the most distinctive Fortinet signal into no signal.
    (re.compile(r"\bFortiSSH", re.I), "fortinet", None),
    (re.compile(r"\bFortiGate", re.I), "fortinet", "fortios"),
    (re.compile(r"\bFortinet\b", re.I), "fortinet", None),
    (re.compile(r"\bPalo Alto Networks\b", re.I), "paloalto", None),
    (re.compile(r"\bPAN-OS\b", re.I), "paloalto", "panos"),
    (re.compile(r"\bCheck Point\b", re.I), "checkpoint", None),
    (re.compile(r"\bGaia\b", re.I), "checkpoint", "checkpoint_gaia"),
)


@dataclass(frozen=True, slots=True)
class Evidence:
    """One signal's reading, kept verbatim.

    ``raw`` survives into the review queue because FR-DISC-04 puts a human in front of
    this. "Cisco, 70%" is not reviewable; "the SSH banner said SSH-2.0-Cisco-1.25" is.
    """

    signal: Signal
    raw: str
    vendor: str | None = None
    platform: str | None = None

    @property
    def weight(self) -> int:
        return WEIGHTS[self.signal] if self.vendor else 0


@dataclass(slots=True)
class Fingerprint:
    """What discovery thinks a host is, and how sure it is."""

    vendor: str | None = None
    platform: str | None = None
    confidence: int = 0
    evidence: list[Evidence] = field(default_factory=list)
    #: Signals that disagreed. Non-empty means the host needs a human before anything
    #: else happens to it.
    conflicts: list[str] = field(default_factory=list)

    @property
    def identified(self) -> bool:
        return self.vendor is not None

    @property
    def contested(self) -> bool:
        return bool(self.conflicts)


def read_sysobjectid(oid: str) -> Evidence:
    """Read an SNMP sysObjectID into vendor and, where the subtree says so, platform."""
    text = (oid or "").strip()
    evidence = Evidence(signal=Signal.SNMP_SYSOBJECTID, raw=text)
    if not text.startswith("1.3.6.1.4.1."):
        # Not in the private-enterprise arm at all. Says nothing about a vendor.
        return evidence

    remainder = text[len("1.3.6.1.4.1.") :]
    enterprise = remainder.split(".", 1)[0]
    vendor = ENTERPRISE_NUMBERS.get(enterprise)
    if vendor is None:
        log.debug("discovery.unknown_enterprise_oid", oid=text, enterprise=enterprise)
        return evidence

    # Longest matching subtree wins, so a precise ASA OID beats the generic Cisco one.
    platform: str | None = None
    matched = ""
    for prefix, candidate in PLATFORM_OIDS:
        if text.startswith(prefix) and len(prefix) > len(matched):
            platform, matched = candidate, prefix

    return Evidence(signal=Signal.SNMP_SYSOBJECTID, raw=text, vendor=vendor, platform=platform)


def read_text(signal: Signal, text: str) -> Evidence:
    """Read a banner, certificate subject, header or sysDescr.

    The most specific pattern wins: a string containing both "Cisco" and "NX-OS" is a
    Nexus, and matching the vendor-only pattern first would lose the platform.
    """
    value = (text or "").strip()
    evidence = Evidence(signal=signal, raw=value)
    if not value:
        return evidence

    best: tuple[str, str | None] | None = None
    for pattern, vendor, platform in TEXT_PATTERNS:
        if not pattern.search(value):
            continue
        # A pattern naming a platform is more specific than one naming only a vendor.
        if best is None or (platform is not None and best[1] is None):
            best = (vendor, platform)

    if best is None:
        return evidence
    return Evidence(signal=signal, raw=value, vendor=best[0], platform=best[1])


def fingerprint(evidence: list[Evidence]) -> Fingerprint:
    """Combine every signal collected from one host into a single verdict.

    Agreement accumulates; disagreement is recorded and costs confidence. The vendor
    chosen is the one with the most weight behind it, but where two vendors were named
    the disagreement is surfaced rather than buried under the winner.
    """
    result = Fingerprint(evidence=list(evidence))
    useful = [item for item in evidence if item.vendor]

    if not useful:
        return result

    by_vendor: dict[str, int] = {}
    for item in useful:
        by_vendor[item.vendor or ""] = by_vendor.get(item.vendor or "", 0) + item.weight

    # Highest weight wins, ties broken by name so the result is deterministic — an
    # inventory entry that changes between identical runs is worse than a wrong one,
    # because nobody can tell which run to believe.
    vendor = max(sorted(by_vendor), key=lambda name: by_vendor[name])
    result.vendor = vendor
    result.confidence = min(by_vendor[vendor], MAX_CONFIDENCE)

    if len(by_vendor) > 1:
        # Two vendors named for one address. Something is in the way, or something is
        # mislabelled; either way a human decides, not this function.
        named = ", ".join(
            f"{item.signal.value} says {item.vendor}" for item in useful if item.vendor
        )
        result.conflicts.append(
            f"Signals disagree about the vendor of this host ({named}). That usually "
            "means a proxy or load balancer in front of it, two devices behind one "
            "address, or a certificate never rotated after a hardware change — not a "
            "device that is partly one vendor. Confirm before onboarding."
        )
        # Halved rather than zeroed: the evidence is real and worth reviewing, it just
        # cannot support a confident answer.
        result.confidence = max(1, result.confidence // 2)

    platforms = {item.platform for item in useful if item.platform and item.vendor == vendor}
    if len(platforms) == 1:
        result.platform = platforms.pop()
    elif len(platforms) > 1:
        result.conflicts.append(
            f"Signals agree this is {vendor} but name different platforms "
            f"({', '.join(sorted(platforms))}). The vendor is usable; the platform is not."
        )
        result.confidence = max(1, result.confidence - 15)

    log.info(
        "discovery.fingerprinted",
        vendor=result.vendor,
        platform=result.platform,
        confidence=result.confidence,
        signals=len(useful),
        contested=result.contested,
    )
    return result


__all__ = [
    "ENTERPRISE_NUMBERS",
    "MAX_CONFIDENCE",
    "PLATFORM_OIDS",
    "WEIGHTS",
    "Evidence",
    "Fingerprint",
    "Signal",
    "fingerprint",
    "read_sysobjectid",
    "read_text",
]
