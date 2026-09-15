"""Device fingerprinting from discovery probes (FR-DISC-03).

A fingerprint feeds the review queue that FR-DISC-04 puts a human in front of, so the
number attached to it gets read as though it means something. Two ways it can mislead:

* **Claiming more than the evidence supports.** Every input here is a string the far end
  chose to send, and none of it is authenticated. A banner is operator-settable; a TLS
  subject names whoever issued the certificate.
* **Resolving a contradiction instead of reporting it.** Two vendors named for one
  address is not a device that is 60% Cisco. It is a proxy, a NAT, or a stale
  certificate — and quietly picking the heavier signal produces a plausible, wrong
  inventory entry that somebody will later assign credentials to.

Most of what follows is about the second.
"""

from __future__ import annotations

import pytest

from netsecops.discovery.fingerprint import (
    MAX_CONFIDENCE,
    WEIGHTS,
    Evidence,
    Signal,
    fingerprint,
    read_sysobjectid,
    read_text,
)

# ══════════════════════════ reading each signal ══════════════════════════════


class TestSysObjectId:
    """The only authoritative signal: a structured OID, not a settable string."""

    def test_a_cisco_enterprise_oid_names_the_vendor(self) -> None:
        evidence = read_sysobjectid("1.3.6.1.4.1.9.1.1745")

        assert evidence.vendor == "cisco"

    @pytest.mark.parametrize(
        ("oid", "vendor"),
        [
            ("1.3.6.1.4.1.9.1.1", "cisco"),
            ("1.3.6.1.4.1.25461.2.3.50", "paloalto"),
            ("1.3.6.1.4.1.12356.101.1.1000", "fortinet"),
            ("1.3.6.1.4.1.2620.1.6", "checkpoint"),
        ],
    )
    def test_each_vendors_enterprise_number(self, oid: str, vendor: str) -> None:
        assert read_sysobjectid(oid).vendor == vendor

    def test_a_precise_subtree_also_names_the_platform(self) -> None:
        assert read_sysobjectid("1.3.6.1.4.1.25461.2.3.50").platform == "panos"

    def test_the_longest_matching_subtree_wins(self) -> None:
        """The ASA OID sits under the generic Cisco one; the specific answer is right."""
        assert read_sysobjectid("1.3.6.1.4.1.9.1.745").platform == "cisco_asa"

    def test_a_vendor_with_no_platform_subtree_still_names_the_vendor(self) -> None:
        """A partial answer is a useful, honest answer."""
        evidence = read_sysobjectid("1.3.6.1.4.1.2620.1.6")

        assert evidence.vendor == "checkpoint"
        assert evidence.platform is None

    @pytest.mark.parametrize(
        "oid",
        [
            "1.3.6.1.4.1.8072.3.2.10",  # net-snmp on a generic Linux host
            "1.3.6.1.4.1.11.2.3.9.1",  # HP printer
            "1.3.6.1.2.1.1.1.0",  # not in the private-enterprise arm at all
            "",
            "not-an-oid",
        ],
    )
    def test_an_unrecognised_oid_names_nobody(self, oid: str) -> None:
        """The estate is full of printers, UPSes and cameras.

        Naming one "cisco" because the OID looked familiar puts it in an inventory
        somebody will then try to collect from with real credentials.
        """
        assert read_sysobjectid(oid).vendor is None


class TestTextSignals:
    @pytest.mark.parametrize(
        ("text", "vendor", "platform"),
        [
            ("SSH-2.0-Cisco-1.25", "cisco", None),
            ("Cisco IOS Software, Version 15.2(7)E3", "cisco", "cisco_ios"),
            ("Cisco IOS-XE Software, Version 17.9.4a", "cisco", "cisco_iosxe"),
            ("Cisco Nexus Operating System (NX-OS) Software", "cisco", "cisco_nxos"),
            ("Cisco Adaptive Security Appliance Software Version 9.18(2)", "cisco", "cisco_asa"),
            ("SSH-2.0-FortiSSH_1.0", "fortinet", None),
            ("CN=FGT60F, O=Fortinet", "fortinet", None),
            ("O=Palo Alto Networks, CN=perimeter-fw-01", "paloalto", None),
            ("PAN-OS 11.0.3", "paloalto", "panos"),
            ("Check Point Gaia R81.20", "checkpoint", "checkpoint_gaia"),
        ],
    )
    def test_discriminating_strings(self, text: str, vendor: str, platform: str | None) -> None:
        evidence = read_text(Signal.SSH_BANNER, text)

        assert evidence.vendor == vendor
        assert evidence.platform == platform

    def test_the_more_specific_pattern_wins(self) -> None:
        """A string naming both the vendor and the platform must yield both."""
        evidence = read_text(Signal.SNMP_SYSDESCR, "Cisco Systems NX-OS running on a Nexus")

        assert evidence.platform == "cisco_nxos"

    @pytest.mark.parametrize(
        "text",
        [
            "SSH-2.0-OpenSSH_7.5",  # what a PAN-OS box actually answers
            "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5",
            "Server: nginx",
            "Server: Apache/2.4.41",
            "",
            "   ",
        ],
    )
    def test_a_generic_string_is_not_evidence(self, text: str) -> None:
        """PAN-OS and Check Point both answer SSH with stock OpenSSH.

        A pattern matching those would attribute every Linux host in the estate to a
        firewall vendor — noise that looks exactly like signal in an inventory.
        """
        assert read_text(Signal.SSH_BANNER, text).vendor is None

    def test_a_signal_with_no_vendor_carries_no_weight(self) -> None:
        assert read_text(Signal.SSH_BANNER, "SSH-2.0-OpenSSH_8.2").weight == 0


# ═══════════════════════════ combining signals ═══════════════════════════════


class TestAgreement:
    def test_one_signal_identifies_a_host(self) -> None:
        result = fingerprint([read_sysobjectid("1.3.6.1.4.1.9.1.745")])

        assert result.vendor == "cisco"
        assert result.platform == "cisco_asa"
        assert result.identified
        assert not result.contested

    def test_agreeing_signals_accumulate(self) -> None:
        """Two sources saying the same thing is worth more than either alone."""
        one = fingerprint([read_text(Signal.SSH_BANNER, "SSH-2.0-Cisco-1.25")])
        two = fingerprint(
            [
                read_text(Signal.SSH_BANNER, "SSH-2.0-Cisco-1.25"),
                read_text(Signal.TLS_SUBJECT, "O=Cisco Systems, CN=core-sw-01"),
            ]
        )

        assert two.confidence > one.confidence
        assert not two.contested

    def test_the_authoritative_signal_outweighs_a_banner(self) -> None:
        """A banner is a preference; sysObjectID is emitted by the agent."""
        assert WEIGHTS[Signal.SNMP_SYSOBJECTID] > WEIGHTS[Signal.SSH_BANNER]
        assert WEIGHTS[Signal.SSH_BANNER] > WEIGHTS[Signal.HTTP_HEADER]

    def test_no_usable_signal_identifies_nothing(self) -> None:
        result = fingerprint(
            [
                read_text(Signal.SSH_BANNER, "SSH-2.0-OpenSSH_8.2"),
                read_sysobjectid("1.3.6.1.4.1.8072.3.2.10"),
            ]
        )

        assert not result.identified
        assert result.confidence == 0

    def test_nothing_at_all_identifies_nothing(self) -> None:
        assert fingerprint([]).identified is False


class TestConflictsAreReportedNotResolved:
    """The failure mode that produces a confident, wrong inventory entry."""

    def test_two_vendors_for_one_host_is_flagged(self) -> None:
        result = fingerprint(
            [
                read_text(Signal.SSH_BANNER, "SSH-2.0-Cisco-1.25"),
                read_text(Signal.TLS_SUBJECT, "CN=FGT60F, O=Fortinet"),
            ]
        )

        assert result.contested
        assert "disagree about the vendor" in result.conflicts[0]
        assert "proxy or load balancer" in result.conflicts[0], "say what it usually means"

    def test_a_conflict_costs_confidence(self) -> None:
        """Measured against the winning vendor's own weight, not against a different
        evidence set.

        Comparing a contested host to an agreeing one passes even with the penalty
        removed, because the two have different totals anyway — the gap comes from the
        vendor split rather than from the conflict being penalised. The honest assertion
        is that the winner scores *less than its own evidence would otherwise earn*.
        """
        contested = fingerprint(
            [
                read_text(Signal.SSH_BANNER, "SSH-2.0-Cisco-1.25"),
                read_text(Signal.TLS_SUBJECT, "CN=FGT60F, O=Fortinet"),
            ]
        )

        assert contested.vendor == "cisco"
        assert contested.confidence < WEIGHTS[Signal.SSH_BANNER], (
            "a contested winner must score below the weight of the signal that won it"
        )

    def test_a_conflict_does_not_zero_the_result(self) -> None:
        """The evidence is real and worth reviewing; it just cannot support certainty."""
        result = fingerprint(
            [
                read_text(Signal.SSH_BANNER, "SSH-2.0-Cisco-1.25"),
                read_text(Signal.TLS_SUBJECT, "CN=FGT60F, O=Fortinet"),
            ]
        )

        assert result.confidence > 0
        assert result.vendor is not None, "a candidate is still offered for review"

    def test_agreeing_on_vendor_but_not_platform_keeps_the_vendor(self) -> None:
        """Half an answer, honestly labelled, beats a whole invented one."""
        result = fingerprint(
            [
                Evidence(Signal.SNMP_SYSDESCR, "…", vendor="cisco", platform="cisco_ios"),
                Evidence(Signal.SSH_BANNER, "…", vendor="cisco", platform="cisco_nxos"),
            ]
        )

        assert result.vendor == "cisco"
        assert result.platform is None
        assert "name different platforms" in result.conflicts[0]

    def test_the_result_is_deterministic_when_weights_tie(self) -> None:
        """An inventory entry that changes between identical runs is worse than a wrong
        one, because nobody can tell which run to believe."""
        evidence = [
            Evidence(Signal.SSH_BANNER, "a", vendor="fortinet"),
            Evidence(Signal.TLS_SUBJECT, "b", vendor="cisco"),
        ]

        first = fingerprint(list(evidence))
        second = fingerprint(list(reversed(evidence)))

        assert first.vendor == second.vendor


class TestConfidenceStaysHonest:
    def test_it_never_reaches_certainty(self) -> None:
        """Nothing here authenticates.

        FR-DISC-04 requires a human before a discovered host is assessed, and a score of
        100 invites exactly the automation that requirement exists to prevent.
        """
        result = fingerprint(
            [
                read_sysobjectid("1.3.6.1.4.1.9.1.745"),
                read_text(Signal.SNMP_SYSDESCR, "Cisco Adaptive Security Appliance"),
                read_text(Signal.SSH_BANNER, "SSH-2.0-Cisco-1.25"),
                read_text(Signal.TLS_SUBJECT, "O=Cisco Systems"),
                read_text(Signal.HTTP_HEADER, "Server: Cisco Systems"),
            ]
        )

        assert result.confidence == MAX_CONFIDENCE
        assert result.confidence < 100

    def test_the_raw_evidence_survives_for_review(self) -> None:
        """ "Cisco, 70%" is not reviewable; the banner text is.

        FR-DISC-04 puts a person in front of this, and they need what the host actually
        said rather than this module's conclusion about it.
        """
        result = fingerprint([read_text(Signal.SSH_BANNER, "SSH-2.0-Cisco-1.25")])

        assert result.evidence[0].raw == "SSH-2.0-Cisco-1.25"
        assert result.evidence[0].signal is Signal.SSH_BANNER
