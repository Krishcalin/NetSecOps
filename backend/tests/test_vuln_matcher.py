"""Feature-aware vulnerability matching (FR-VUL-03).

This is the only module in Phase 6 whose output a human acts on, so the tests are
weighted towards the verdicts that would cost someone something.

Two failures dominate, and they are not symmetric:

* A wrong *Not Affected* is silent. Nobody is told the question went unasked, and the
  device stays exposed until the next audit — or the breach.
* A wrong *Confirmed* is loud and self-defeating. Flag every device running the product
  and the operator stops reading the vulnerability view within a week, taking the real
  findings with it.

Most of what follows pins the third and fourth verdicts — the ones that exist so the
engine never has to choose between those two.
"""

from __future__ import annotations

import pytest

from netsecops.ncm.models import NormalisedConfig
from netsecops.vuln.advisory import (
    Advisory,
    AffectedProduct,
    ConstraintKind,
    FeatureCondition,
    VersionConstraint,
)
from netsecops.vuln.matcher import Confidence, match

# ───────────────────────────────── helpers ──────────────────────────────────


def device(
    *, vendor="cisco", platform="cisco_ios", version="15.2(7)E3", **features
) -> NormalisedConfig:
    ncm = NormalisedConfig()
    ncm.device.vendor = vendor
    ncm.device.platform = platform
    ncm.device.version = version
    for name, value in features.items():
        setattr(ncm.features, name, value)
    return ncm


def affected(
    raw: str,
    *,
    kind=ConstraintKind.RANGE,
    introduced=None,
    fixed=None,
    version=None,
    vendor="Cisco",
    product="IOS",
    cpe=None,
) -> AffectedProduct:
    return AffectedProduct(
        vendor=vendor,
        product=product,
        cpe=cpe,
        product_id="CSAFPID-0001",
        constraint=VersionConstraint(
            kind=kind, raw=raw, introduced=introduced, fixed=fixed, version=version
        ),
    )


def advisory(*entries: AffectedProduct, conditions=(), notes=(), fixed=()) -> Advisory:
    return Advisory(
        source="Cisco",
        advisory_id="cisco-sa-2024-0001",
        cve_ids=["CVE-2024-11111"],
        affected=list(entries),
        fixed=list(fixed),
        conditions=list(conditions),
        notes_unparsed=list(notes),
    )


# ═══════════════════════════ the ordinary answers ════════════════════════════


class TestVersionMatching:
    def test_a_version_inside_the_range_is_confirmed(self) -> None:
        result = match(
            device(version="15.2(7)E3"),
            advisory(affected(">=15.2(7)E1 <15.2(7)E6", introduced="15.2(7)E1", fixed="15.2(7)E6")),
        )

        assert result.confidence is Confidence.CONFIRMED
        assert "15.2(7)E3" in result.reasoning[0]

    def test_the_fixed_release_itself_is_not_affected(self) -> None:
        """`fixed` is exclusive — the release containing the fix is the safe one.

        An off-by-one here reports every patched device as still vulnerable, which is
        how a team learns to ignore the tool.
        """
        result = match(
            device(version="15.2(7)E6"),
            advisory(affected("<15.2(7)E6", fixed="15.2(7)E6")),
        )

        assert result.confidence is Confidence.NOT_AFFECTED

    def test_a_version_below_the_lower_bound_is_not_affected(self) -> None:
        result = match(
            device(version="15.2(7)E1"),
            advisory(affected(">=15.2(7)E3 <15.2(7)E6", introduced="15.2(7)E3", fixed="15.2(7)E6")),
        )

        assert result.confidence is Confidence.NOT_AFFECTED

    def test_an_exact_version_match(self) -> None:
        result = match(
            device(version="15.2(7)E3"),
            advisory(affected("15.2(7)E3", kind=ConstraintKind.EXACT, version="15.2(7)E3")),
        )

        assert result.confidence is Confidence.CONFIRMED

    def test_a_whole_product_advisory_matches_any_version(self) -> None:
        result = match(
            device(version="15.2(7)E3"), advisory(affected("*", kind=ConstraintKind.ALL))
        )

        assert result.confidence is Confidence.CONFIRMED

    def test_a_different_product_does_not_match(self) -> None:
        result = match(
            device(platform="cisco_ios"),
            advisory(
                affected("<11.0.3", fixed="11.0.3", vendor="Palo Alto Networks", product="PAN-OS")
            ),
        )

        assert result.confidence is Confidence.NOT_AFFECTED
        assert "no product matching" in result.reasoning[0]


# ═════════════════════════ the appliance is the product ══════════════════════


def appliance(*, vendor="paloalto", platform="panos", version="10.2.3", model="PA-3220"):
    """A firewall, which is both an operating system and a box.

    Vendor advisories routinely scope to the chassis rather than to the software — the
    flaw is in a crypto accelerator, a management port, a bootloader — and NVD records
    that as a hardware CPE marked `vulnerable: true`. Nothing else in the estate is
    identified two ways like this, which is why it has its own section.
    """
    ncm = NormalisedConfig()
    ncm.device.vendor = vendor
    ncm.device.platform = platform
    ncm.device.version = version
    ncm.device.model = model
    return ncm


def hardware_entry(cpe: str) -> AffectedProduct:
    """An affected-hardware statement, shaped as `parse_nvd_feed` produces one.

    The constraint is UNPARSED because the CPE's version component is `-` (NA): a
    chassis has no software version, so there is no range to read.
    """
    return AffectedProduct(
        vendor="paloaltonetworks",
        product="pa-3220",
        cpe=cpe,
        product_id="nvd-hw-1",
        constraint=VersionConstraint(kind=ConstraintKind.UNPARSED, raw=cpe),
    )


def vendor_hardware_entry(cpe: str) -> AffectedProduct:
    """The same claim as a vendor states it, with an interpretable scope.

    Used wherever a test needs to assert *not affected*: the NVD shape above carries an
    unreadable range, which correctly blocks any clean verdict, so it can only ever
    demonstrate "cannot tell".
    """
    return AffectedProduct(
        vendor="paloaltonetworks",
        product="pa-3220",
        cpe=cpe,
        product_id="psirt-1",
        constraint=VersionConstraint(kind=ConstraintKind.ALL, raw="*"),
    )


PA_3220 = "cpe:2.3:h:paloaltonetworks:pa-3220:-:*:*:*:*:*:*:*"


class TestHardwareIsMatchedToo:
    """FireMon parses the config and knows the model, and never turns it into exposure.

    The gap here was worse than not answering: an advisory naming the chassis failed
    product identity on the CPE part alone (`h` against the device's `o`), left nothing
    applicable, and — the advisory being fully interpreted — was reported **not
    affected**. That verdict is the one that *resolves* an open finding, so a hardware
    advisory did not merely go unnoticed, it closed the record of itself.
    """

    def test_an_advisory_naming_this_chassis_is_matched(self) -> None:
        result = match(appliance(), advisory(hardware_entry(PA_3220)))

        assert result.confidence is Confidence.CONFIRMED
        assert "PA-3220" in " ".join(result.reasoning)

    def test_a_vendor_advisory_on_this_chassis_is_not_reported_clean(self) -> None:
        """The dangerous half, and the reason this is a defect rather than a gap.

        NVD writes a chassis CPE's version as `-`, which reads as an unparseable range
        and leaves the advisory not fully interpreted — so the old code answered "cannot
        tell", which is merely unhelpful. A vendor advisory states its scope in a form
        that *is* interpretable, so the same identity miss produced **not affected** on
        the exact model named — and that is the verdict that closes an open finding.
        """
        result = match(appliance(), advisory(vendor_hardware_entry(PA_3220)))

        assert result.confidence is Confidence.CONFIRMED

    def test_a_different_chassis_is_not_matched(self) -> None:
        result = match(appliance(model="PA-5220"), advisory(vendor_hardware_entry(PA_3220)))

        assert result.confidence is Confidence.NOT_AFFECTED

    def test_a_device_with_no_model_is_not_matched(self) -> None:
        """Absent is not false. A device whose model was never collected is not a match.

        Matching it on vendor alone would attach every Palo Alto chassis advisory to
        every Palo Alto device — which is the failure this whole engine exists to avoid,
        pointed the other way.
        """
        result = match(appliance(model=None), advisory(vendor_hardware_entry(PA_3220)))

        assert result.confidence is Confidence.NOT_AFFECTED

    def test_the_nvd_shape_never_clears_a_device(self) -> None:
        """NVD writes a chassis version as `-`, which is not a range anyone can read.

        So even a device that is plainly a different model cannot be *cleared* by such
        an advisory — it is reported as unevaluated. That is the fully-interpreted rule
        doing its job, and it is why the assertions above use the vendor shape.
        """
        result = match(appliance(model="PA-5220"), advisory(hardware_entry(PA_3220)))

        assert result.confidence is Confidence.NOT_EVALUATED

    def test_the_software_version_is_irrelevant_to_a_chassis_advisory(self) -> None:
        """A hardware flaw is not fixed by an upgrade, so no version clears it."""
        for version in ("8.1.0", "10.2.3", "11.9.9"):
            result = match(appliance(version=version), advisory(hardware_entry(PA_3220)))
            assert result.confidence is Confidence.CONFIRMED, version

    def test_an_os_advisory_still_matches_on_the_os(self) -> None:
        """The hardware path must not displace the one that already worked."""
        result = match(
            appliance(version="10.2.3"),
            advisory(
                affected(
                    "<10.2.9",
                    fixed="10.2.9",
                    vendor="paloaltonetworks",
                    product="pan-os",
                    cpe="cpe:2.3:o:paloaltonetworks:pan-os:*:*:*:*:*:*:*:*",
                )
            ),
        )

        assert result.confidence is Confidence.CONFIRMED


# ══════════════════════ the verdicts that exist to be honest ═════════════════


class TestNotEvaluated:
    """Each of these is a question that could not be asked.

    Rounded down to NOT_AFFECTED they vanish into a clean report; rounded up to
    CONFIRMED they bury the real findings. Both are worse than saying so.
    """

    def test_a_device_with_no_version_is_not_evaluated(self) -> None:
        result = match(device(version=None), advisory(affected("<15.2(7)E6", fixed="15.2(7)E6")))

        assert result.confidence is Confidence.NOT_EVALUATED
        assert "no software version" in result.reasoning[0]
        assert "show version" in result.reasoning[0], "the message must say how to fix it"

    def test_an_unreadable_device_version_is_not_evaluated(self) -> None:
        result = match(
            device(version="unknown"), advisory(affected("<15.2(7)E6", fixed="15.2(7)E6"))
        )

        assert result.confidence is Confidence.NOT_EVALUATED

    def test_different_cisco_trains_cannot_be_ranked(self) -> None:
        """The case `versions.py` exists for, reaching the verdict it exists to produce.

        15.2(7)E3 and 15.2(4)M5 are parallel trains with independent fix schedules.
        Forcing an order reports a patched device as exploitable or clears a vulnerable
        one, depending which way the comparison happens to fall.
        """
        result = match(
            device(version="15.2(7)E3"),
            advisory(affected("<15.2(4)M5", fixed="15.2(4)M5")),
        )

        assert result.confidence is Confidence.NOT_EVALUATED
        assert "different Cisco release trains" in result.reasoning[0]
        assert "read from the advisory" in result.reasoning[0]

    def test_an_incomparable_lower_bound_is_also_not_evaluated(self) -> None:
        """Both ends of a range need their own coverage, not just the fixed one.

        Added after a mutation check: replacing the lower-bound incomparability branch
        with "not in range" passed every other test in this file, because they all use
        upper-bound-only ranges. That branch silently returns NOT_AFFECTED, so the
        untested path was one that clears a vulnerable device without saying anything.
        """
        result = match(
            device(version="15.2(7)E3"),
            advisory(affected(">=15.2(4)M1 <15.2(4)M5", introduced="15.2(4)M1", fixed="15.2(4)M5")),
        )

        assert result.confidence is Confidence.NOT_EVALUATED
        assert "different Cisco release trains" in result.reasoning[0]

    def test_an_unparsed_advisory_range_is_not_evaluated(self) -> None:
        result = match(
            device(version="15.2(7)E3"),
            advisory(
                affected("all releases before the 15.2 rebuild", kind=ConstraintKind.UNPARSED)
            ),
        )

        assert result.confidence is Confidence.NOT_EVALUATED
        assert "cannot interpret" in result.reasoning[0]
        assert "read the advisory" in result.reasoning[0]


class TestClearingADeviceNeedsMoreEvidenceThanFlaggingOne:
    """The asymmetry the module is built around.

    One matching statement rules a device in. Ruling it out requires that every
    statement was read and none matched.
    """

    def test_a_fully_understood_advisory_can_clear_a_device(self) -> None:
        result = match(
            device(version="15.2(7)E9"),
            advisory(affected("<15.2(7)E6", fixed="15.2(7)E6")),
        )

        assert result.confidence is Confidence.NOT_AFFECTED

    def test_a_partly_unreadable_advisory_cannot_clear_a_device(self) -> None:
        """Same device, same range, plus one statement nobody could parse.

        The readable half says "not affected". The document as a whole cannot say that,
        because something in it was never evaluated — and that unevaluated statement is
        exactly where the device might be named.
        """
        result = match(
            device(version="15.2(7)E9"),
            advisory(
                affected("<15.2(7)E6", fixed="15.2(7)E6"),
                notes=["product 'CSAFPID-0999' is named in product_status but undefined"],
            ),
        )

        assert result.confidence is Confidence.NOT_EVALUATED
        assert "could not be interpreted" in result.reasoning[0]
        assert "CSAFPID-0999" in result.reasoning[0], "name what was unreadable"

    def test_an_unparsed_statement_alongside_a_readable_miss_blocks_clearing(self) -> None:
        result = match(
            device(version="15.2(7)E9"),
            advisory(
                affected("<15.2(7)E6", fixed="15.2(7)E6"),
                affected("some prose nobody can parse", kind=ConstraintKind.UNPARSED),
            ),
        )

        assert result.confidence is not Confidence.NOT_AFFECTED

    def test_a_hit_still_wins_even_when_the_advisory_is_partly_unreadable(self) -> None:
        """Ruling *in* needs only one statement, so partial understanding does not
        weaken a positive match into an unknown."""
        result = match(
            device(version="15.2(7)E3"),
            advisory(
                affected("<15.2(7)E6", fixed="15.2(7)E6"),
                notes=["something else was unreadable"],
            ),
        )

        assert result.confidence is Confidence.CONFIRMED


# ═══════════════════════ feature awareness (FR-VUL-03) ═══════════════════════


HTTP_CONDITION = FeatureCondition(
    path="features.http_server",
    expected=True,
    description="the HTTP server is enabled",
)


class TestFeatureConditions:
    def test_version_plus_feature_is_confirmed(self) -> None:
        result = match(
            device(version="15.2(7)E3", http_server=True),
            advisory(affected("<15.2(7)E6", fixed="15.2(7)E6"), conditions=[HTTP_CONDITION]),
        )

        assert result.confidence is Confidence.CONFIRMED
        assert "HTTP server is enabled" in result.reasoning[-1]

    def test_a_disabled_feature_clears_the_device(self) -> None:
        """`no ip http server` is a real answer, and the device is genuinely safe."""
        result = match(
            device(version="15.2(7)E3", http_server=False),
            advisory(affected("<15.2(7)E6", fixed="15.2(7)E6"), conditions=[HTTP_CONDITION]),
        )

        assert result.confidence is Confidence.NOT_AFFECTED
        assert "not affected" in result.reasoning[-1]

    def test_an_unknown_feature_is_likely_not_confirmed_and_not_cleared(self) -> None:
        """The NCM's "absent is not false" rule, carried all the way to a CVE verdict.

        The parser never established whether the HTTP server is on. That is neither
        evidence of exposure nor evidence of safety, and FR-VUL-03 names this case
        Likely.
        """
        result = match(
            device(version="15.2(7)E3", http_server=None),
            advisory(affected("<15.2(7)E6", fixed="15.2(7)E6"), conditions=[HTTP_CONDITION]),
        )

        assert result.confidence is Confidence.LIKELY
        assert "establishes features.http_server either way" in result.reasoning[-1]
        assert "check the device" in result.reasoning[-1]

    def test_an_advisory_with_no_conditions_is_confirmed_on_version_alone(self) -> None:
        """Most advisories state no condition, and version is then the whole claim."""
        result = match(
            device(version="15.2(7)E3", http_server=None),
            advisory(affected("<15.2(7)E6", fixed="15.2(7)E6")),
        )

        assert result.confidence is Confidence.CONFIRMED

    def test_conditions_are_only_reached_after_a_version_hit(self) -> None:
        """A device outside the range is not affected whatever its features do."""
        result = match(
            device(version="15.2(7)E9", http_server=True),
            advisory(affected("<15.2(7)E6", fixed="15.2(7)E6"), conditions=[HTTP_CONDITION]),
        )

        assert result.confidence is Confidence.NOT_AFFECTED

    def test_one_failed_condition_clears_even_when_another_passes(self) -> None:
        result = match(
            device(version="15.2(7)E3", http_server=True, smart_install=False),
            advisory(
                affected("<15.2(7)E6", fixed="15.2(7)E6"),
                conditions=[
                    HTTP_CONDITION,
                    FeatureCondition(
                        path="features.smart_install",
                        expected=True,
                        description="Smart Install is enabled",
                    ),
                ],
            ),
        )

        assert result.confidence is Confidence.NOT_AFFECTED

    def test_a_condition_can_read_the_management_block(self) -> None:
        """FR-VUL-03 names `features`/`management`, and paths are JMESPath over the NCM."""
        ncm = device(version="15.2(7)E3")
        ncm.management.services.telnet.enabled = True

        result = match(
            ncm,
            advisory(
                affected("<15.2(7)E6", fixed="15.2(7)E6"),
                conditions=[
                    FeatureCondition(
                        path="management.services.telnet.enabled",
                        expected=True,
                        description="Telnet is enabled",
                    )
                ],
            ),
        )

        assert result.confidence is Confidence.CONFIRMED


# ════════════════════════════ what a match carries ═══════════════════════════


class TestTheFindingIsActionable:
    def test_every_verdict_explains_itself(self) -> None:
        """FR-VUL-03 requires an explanation.

        A vulnerability finding that cannot say why is one an engineer will refuse to
        action, and be right to.
        """
        cases = [
            match(device(version=None), advisory(affected("<15.2(7)E6", fixed="15.2(7)E6"))),
            match(device(), advisory(affected("<15.2(7)E6", fixed="15.2(7)E6"))),
            match(device(version="15.2(7)E9"), advisory(affected("<15.2(7)E6", fixed="15.2(7)E6"))),
            match(device(), advisory(affected("<15.2(4)M5", fixed="15.2(4)M5"))),
        ]

        for result in cases:
            assert result.reasoning, f"{result.confidence} gave no explanation"
            assert len(result.reasoning[0]) > 40

    def test_the_cve_and_source_travel_with_the_match(self) -> None:
        result = match(device(), advisory(affected("<15.2(7)E6", fixed="15.2(7)E6")))

        assert result.cve_ids == ["CVE-2024-11111"]
        assert result.advisory_id == "cisco-sa-2024-0001"
        assert result.source == "Cisco"

    def test_the_fixed_release_is_carried_for_the_upgrade_view(self) -> None:
        """FR-VUL-10 needs what to upgrade *to*, not only what is broken."""
        result = match(
            device(),
            advisory(
                affected("<15.2(7)E6", fixed="15.2(7)E6"),
                fixed=[affected("15.2(7)E6", kind=ConstraintKind.EXACT, version="15.2(7)E6")],
            ),
        )

        assert result.fixed_versions == ["15.2(7)E6"]

    @pytest.mark.parametrize(
        ("confidence", "expected"),
        [
            (Confidence.CONFIRMED, True),
            (Confidence.LIKELY, True),
            (Confidence.NOT_EVALUATED, True),
            (Confidence.NOT_AFFECTED, False),
        ],
    )
    def test_unevaluated_devices_are_surfaced_not_hidden(
        self, confidence: Confidence, expected: bool
    ) -> None:
        """A device nobody could assess is a gap in coverage.

        Filing it with the clean results is how an estate grows blind spots that look
        like good news.
        """
        from netsecops.vuln.matcher import Match

        assert Match("a", "b", confidence).actionable is expected
