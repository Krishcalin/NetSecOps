"""Vendor version strings, parsed and compared (FR-VUL-01).

Every vulnerability verdict reduces to a version comparison, so this module decides
whether the product reports a CVE or stays quiet. It is worth stating plainly what makes
that hard, because the obvious implementation is wrong in a way that is invisible until
someone acts on the output.

**Network versions are not a total order.** `packaging.Version` and every semver library
assume any two versions can be ranked. Cisco IOS breaks that assumption outright:
`15.2(7)E3` and `15.2(4)M5` are different *trains*, maintained as parallel branches with
their own fix schedules. Neither is "later". An advisory that says "fixed in 15.2(4)M5"
tells you nothing whatsoever about a switch running 15.2(7)E3 — the fix may have landed
in the E train earlier, later, or never.

A comparison that forces an order on those two produces a confident answer to a question
nobody asked. If it decides E3 < M5 the device is reported vulnerable when it may be
patched; if it decides E3 > M5 the device is reported safe when it may be exploitable.
Both are worse than silence, and silence is a legitimate answer here — the matcher
degrades to *Likely* and says why.

So :func:`compare` returns ``None`` for incomparable versions, and the type system makes
that impossible to ignore: there is no ``__lt__`` on :class:`DeviceVersion`, because an
operator that must sometimes answer "I don't know" cannot be spelled ``<``.

**What the existing check engine does, and why this is separate.**
:func:`netsecops.checks.engine._version_of` truncates to the numeric prefix — `15.2(7)E3`
becomes `15.2`. That is correct for check applicability, where ranges are written against
major releases ("this check applies to IOS 15 and later"). It is unusable here: the
entire question a CVE asks is whether the device is on `15.2(7)E3` or `15.2(7)E6`, and a
truncating parser answers "15.2" to both.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Final

from netsecops.core.logging import get_logger

log = get_logger(__name__)


class Ordering(StrEnum):
    """The result of a comparison that produced one.

    ``compare`` returns ``Ordering | None``; ``None`` means the two versions are not
    ordered with respect to each other, which is a real answer and not a failure.
    """

    LESS = "less"
    EQUAL = "equal"
    GREATER = "greater"


class Scheme(StrEnum):
    """How a vendor spells its versions.

    Two versions in different schemes are never comparable — `R81.20` and `7.2.5` are
    not on a common scale, and the fact that both parse into numbers is not a reason to
    subtract them.
    """

    #: `15.2(7)E3`, `12.4(24)T1` — train-based, parallel branches, partially ordered.
    IOS = "ios"
    #: `17.9.4a`, `16.12.5b` — numeric with an optional rebuild letter.
    IOSXE = "iosxe"
    #: `10.3(4a)`, `9.3(11)` — numeric with a bracketed maintenance release.
    NXOS = "nxos"
    #: `9.18(2)`, `9.12(4)56` — like NX-OS with an optional interim build.
    ASA = "asa"
    #: `8.10.190.0` — four-part dotted.
    AIREOS = "aireos"
    #: `11.0.3-h1` — dotted with an optional hotfix.
    PANOS = "panos"
    #: `7.2.5`, sometimes with a build number the NCM keeps separately.
    FORTIOS = "fortios"
    #: `R81.20`, optionally with a jumbo hotfix take.
    GAIA = "gaia"
    #: `3.2.0.542` (ISE), `6.5.2` (FortiAuthenticator), `3.0.21` (FreeRADIUS) — plain
    #: dotted numbers with no vendor-specific structure.
    DOTTED = "dotted"


#: Platform (as the parser registry spells it) to the scheme its versions follow.
SCHEMES: Final[dict[str, Scheme]] = {
    "cisco_ios": Scheme.IOS,
    # IOS-XE reports `17.9.4a` on modern releases, but a 16.x box can still answer with
    # the IOS-style `15.2(7)E3` form. `parse` detects the shape rather than trusting the
    # platform label, so this is the default and not an assertion.
    "cisco_iosxe": Scheme.IOSXE,
    "cisco_nxos": Scheme.NXOS,
    "cisco_asa": Scheme.ASA,
    "cisco_wlc_aireos": Scheme.AIREOS,
    "cisco_ise": Scheme.DOTTED,
    "panos": Scheme.PANOS,
    "fortios": Scheme.FORTIOS,
    "fortiauthenticator": Scheme.DOTTED,
    "checkpoint_gaia": Scheme.GAIA,
    "checkpoint_mgmt": Scheme.GAIA,
    "freeradius": Scheme.DOTTED,
    "tac_plus": Scheme.DOTTED,
}


@dataclass(frozen=True, slots=True)
class DeviceVersion:
    """One parsed version, and the original string it came from.

    ``raw`` is kept because every finding shows the operator the version their device
    reported, not this module's reconstruction of it. A finding that says "9.18(2)" when
    the device said "9.18(2)12" invites the reader to distrust everything around it.

    There are deliberately no rich-comparison methods. ``a < b`` cannot express "these
    are not ordered", so offering it would push callers into exactly the false certainty
    this module exists to prevent. Use :func:`compare`.
    """

    raw: str
    scheme: Scheme
    #: The numeric backbone, most significant first. Compared element by element.
    release: tuple[int, ...]
    #: Cisco IOS train (`E`, `M`, `T`, `S`, `SY`, …). Versions in different trains are
    #: not ordered with respect to each other, which is the whole reason this is a field
    #: rather than part of the rebuild string.
    train: str | None = None
    #: What follows the train or the numeric backbone: `3` in `15.2(7)E3`, `a` in
    #: `10.3(4a)`, `1` in `11.0.3-h1`. Ordered within an otherwise-equal version.
    rebuild: tuple[int | str, ...] = field(default_factory=tuple)

    def __str__(self) -> str:
        return self.raw


# ────────────────────────────────── parsing ─────────────────────────────────

#: `15.2(7)E3`, `12.4(24)T`, `15.2(4)M5` — the classic IOS form. The train letters are
#: the branch; the digits after them are the rebuild within it.
_IOS = re.compile(
    r"^(?P<major>\d+)\.(?P<minor>\d+)\((?P<release>\d+)(?P<maint>[a-z]*)\)"
    r"(?P<train>[A-Z]+)?(?P<rebuild>\d*)(?P<tail>[a-z]*)$"
)

#: `10.3(4a)`, `9.3(11)`, `9.18(2)`, `9.12(4)56` — NX-OS and ASA. Same shape, and they
#: differ only in that ASA may append an interim build number after the bracket.
_BRACKETED = re.compile(
    r"^(?P<major>\d+)\.(?P<minor>\d+)\((?P<release>\d+)(?P<maint>[a-z]*)\)(?P<build>\d*)$"
)

#: `17.9.4a`, `8.10.190.0`, `7.2.5`, `3.2.0.542` — plain dotted numbers with an optional
#: trailing letter on the last component.
_DOTTED = re.compile(r"^(?P<numbers>\d+(?:\.\d+)*)(?P<suffix>[a-z]*)$")

#: `11.0.3-h1`, `10.2.9-h3` — PAN-OS hotfix form.
_PANOS = re.compile(r"^(?P<numbers>\d+(?:\.\d+)*)(?:-h(?P<hotfix>\d+))?$")

#: `R81.20`, `R80.40`, and the jumbo take when the collection captured one.
_GAIA = re.compile(r"^R(?P<major>\d+)(?:\.(?P<minor>\d+))?(?:\s*(?:Take|take)\s*(?P<take>\d+))?$")


def parse(raw: str | None, *, platform: str | None = None) -> DeviceVersion | None:
    """Parse a version string, or return ``None`` if it cannot be understood.

    ``None`` is returned rather than a best guess. A version this module cannot read is
    a device the matcher must decline to rule on, and inventing a structure for it would
    turn an unreadable string into confident output — the same failure mode as treating
    an absent configuration field as ``false``.

    ``platform`` selects the scheme where the shape alone is ambiguous. It is a hint,
    not an instruction: `15.2(7)E3` is parsed as IOS whichever platform claims it,
    because a device that answers in that form is running that kind of image regardless
    of how it was onboarded.
    """
    if raw is None:
        return None

    text = raw.strip()
    if not text:
        return None

    hinted = SCHEMES.get(platform or "", Scheme.DOTTED)

    # Shape first, hint second — but only where the shape is actually decisive. The IOS
    # train form is unmistakable *when a train letter is present*: `15.2(7)E3` is an IOS
    # image whatever platform claims it, and that form appears on boxes onboarded as
    # iosxe. Without the letter it is not decisive at all — `9.18(2)` is a perfectly
    # ordinary ASA version and `10.3(4a)` an NX-OS one, and both match this pattern with
    # an empty train. Those fall through to the hint below.
    match = _IOS.match(text)
    if match and match.group("train"):
        train = match.group("train")
        rebuild: list[int | str] = []
        if maint := match.group("maint"):
            rebuild.append(maint)
        if number := match.group("rebuild"):
            rebuild.append(int(number))
        if tail := match.group("tail"):
            rebuild.append(tail)
        return DeviceVersion(
            raw=text,
            scheme=Scheme.IOS,
            release=(int(match["major"]), int(match["minor"]), int(match["release"])),
            train=train or None,
            rebuild=tuple(rebuild),
        )

    if match := _GAIA.match(text):
        minor = match.group("minor")
        take = match.group("take")
        return DeviceVersion(
            raw=text,
            scheme=Scheme.GAIA,
            release=(int(match["major"]), int(minor) if minor else 0),
            rebuild=(int(take),) if take else (),
        )

    # The bracketed form with no train letter. Cisco spells NX-OS, ASA and an unbranched
    # IOS release identically here, so the platform is the only thing that can tell them
    # apart — and getting it wrong matters, since a scheme mismatch makes two versions
    # incomparable rather than merely mis-ranked.
    if hinted in (Scheme.NXOS, Scheme.ASA, Scheme.IOS) and (match := _BRACKETED.match(text)):
        rebuild = []
        if maint := match.group("maint"):
            rebuild.append(maint)
        if build := match.group("build"):
            rebuild.append(int(build))
        return DeviceVersion(
            raw=text,
            scheme=hinted,
            release=(int(match["major"]), int(match["minor"]), int(match["release"])),
            # An IOS release with no train letter is on the trunk, not on an unknown
            # branch: `train=None` is a real answer that compares against other trunk
            # releases and, correctly, against nothing on a branch.
            train=None,
            rebuild=tuple(rebuild),
        )

    if hinted is Scheme.PANOS and (match := _PANOS.match(text)):
        hotfix = match.group("hotfix")
        return DeviceVersion(
            raw=text,
            scheme=Scheme.PANOS,
            release=tuple(int(part) for part in match["numbers"].split(".")),
            rebuild=(int(hotfix),) if hotfix else (),
        )

    if match := _DOTTED.match(text):
        suffix = match.group("suffix")
        # An unbracketed dotted version keeps the caller's scheme so that an IOS-XE
        # `17.9.4a` never compares against a FortiOS `17.9.4a` that means something else.
        #
        # For ASA and NX-OS the brackets are *notation*, not meaning: a device reports
        # `9.18(2)` and the NVD states the same release as `9.18.2`. Classifying the
        # dotted spelling as a different scheme made the two incomparable, which meant
        # every NVD advisory against an ASA or a Nexus silently returned "not evaluated"
        # — a whole vendor's worth of matching quietly dead. They stay in the platform's
        # own scheme so the two spellings compare.
        #
        # IOS is deliberately not in that list. Its train letter is semantic, not
        # notation, and a dotted `15.2.7` does not say whether it means the E train or
        # the M train. Leaving it DOTTED keeps it incomparable with a device on a named
        # train, which is the honest answer rather than a coin flip.
        scheme = Scheme.DOTTED if hinted is Scheme.IOS else hinted
        return DeviceVersion(
            raw=text,
            scheme=scheme,
            release=tuple(int(part) for part in match["numbers"].split(".")),
            rebuild=(suffix,) if suffix else (),
        )

    log.debug("vuln.version_unparsed", raw=text, platform=platform)
    return None


# ──────────────────────────────── comparison ────────────────────────────────


def compare(left: DeviceVersion, right: DeviceVersion) -> Ordering | None:
    """Order two versions, or return ``None`` if they are not ordered.

    ``None`` is returned when:

    * the versions are in different schemes — `R81.20` and `7.2.5` share no scale; or
    * they are Cisco IOS versions in different trains, which are parallel branches with
      independent fix schedules.

    Callers must handle ``None`` as "unknown" and not as "not less than". That
    distinction is the difference between a device reported vulnerable because nothing
    could rule it out and one reported safe because nothing could rule it in.
    """
    if left.scheme is not right.scheme:
        return None

    if left.scheme is Scheme.IOS and left.train != right.train:
        # Same numbers, different branch. 15.2(7)E3 and 15.2(7)M3 are different images.
        return None

    if (ordering := _compare_sequences(left.release, right.release)) is not None:
        return ordering

    return _compare_rebuilds(left.rebuild, right.rebuild)


def _compare_sequences(left: tuple[int, ...], right: tuple[int, ...]) -> Ordering | None:
    """Element-wise comparison, shorter padded with zeros.

    `17.9` and `17.9.0` are the same release stated two ways, which is why the padding
    is zeros rather than treating the shorter one as lower.
    """
    width = max(len(left), len(right))
    padded_left = left + (0,) * (width - len(left))
    padded_right = right + (0,) * (width - len(right))

    for a, b in zip(padded_left, padded_right, strict=True):
        if a < b:
            return Ordering.LESS
        if a > b:
            return Ordering.GREATER
    return None


def _compare_rebuilds(left: tuple[int | str, ...], right: tuple[int | str, ...]) -> Ordering:
    """Order the rebuild suffixes of two otherwise-identical releases.

    An absent rebuild sorts below a present one: `9.18(2)` is the base release and
    `9.18(2)12` is a later interim build of it. Mixed types compare as strings, since
    `4a` and `4` differ in a way no numeric coercion represents honestly.
    """
    width = max(len(left), len(right))
    for index in range(width):
        a = left[index] if index < len(left) else None
        b = right[index] if index < len(right) else None

        if a == b:
            continue
        if a is None:
            return Ordering.LESS
        if b is None:
            return Ordering.GREATER
        if isinstance(a, int) and isinstance(b, int):
            return Ordering.LESS if a < b else Ordering.GREATER
        return Ordering.LESS if str(a) < str(b) else Ordering.GREATER

    return Ordering.EQUAL


__all__ = [
    "SCHEMES",
    "DeviceVersion",
    "Ordering",
    "Scheme",
    "compare",
    "parse",
]
