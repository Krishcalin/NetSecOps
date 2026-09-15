"""Discovery probe authorisation and scopes (FR-DISC-01, FR-DISC-02).

SRS §1.2 puts port sweeps, exploitation and brute-forcing out of scope, and FR-DISC-02
enumerates the five things discovery may do instead. These tests are the enforcement of
that boundary, so they are written the way the read-only conformance tests are: mostly
about what is refused.

The failure this package has to be designed against is not a bug but a drift. Every
individual widening — one more port, a slightly longer banner read, a second OID — is
defensible on its own, and their sum is a scanner pointed at a customer's production
network. Each test below is a place where that drift has to stop and be argued for.
"""

from __future__ import annotations

import ipaddress

import pytest

from netsecops.core.errors import ValidationProblem
from netsecops.discovery.probes import (
    DEFAULT_TCP_PORTS,
    PERMITTED_OIDS,
    PORT_CEILING,
    SSH_BANNER_LIMIT,
    ProbeKind,
    ProbeViolationError,
    authorise,
    normalise_ports,
)
from netsecops.discovery.scopes import MAX_SCOPE_HOSTS, build_scope, parse_target

# ════════════════════════ the boundary itself ════════════════════════════════


class TestTheProbeSetIsClosed:
    def test_exactly_these_five_probes_exist(self) -> None:
        """Pinned deliberately.

        FR-DISC-02 lists five permitted probes. Adding a sixth is a change to what this
        product sends to customer networks and needs an SRS amendment — this assertion
        is what makes that impossible to do by accident in a refactor.
        """
        assert {kind.value for kind in ProbeKind} == {
            "icmp_echo",
            "tcp_connect",
            "ssh_banner",
            "https_certificate",
            "snmp_sysdescr",
        }

    @pytest.mark.parametrize(
        "kind",
        [
            "udp_scan",
            "syn_scan",
            "os_detect",
            "version_scan",
            "http_login",
            "telnet_banner",
            "nmap",
        ],
    )
    def test_anything_else_is_refused(self, kind: str) -> None:
        with pytest.raises(ProbeViolationError, match="not a discovery probe"):
            authorise(kind, "10.0.0.1", port=22)

    def test_the_ssh_banner_read_is_bounded(self) -> None:
        """255 bytes is the RFC 4253 limit on an identification string.

        Reading further consumes the key-exchange packet, which is protocol interaction
        rather than reading what the server volunteered.
        """
        assert SSH_BANNER_LIMIT == 255


class TestPorts:
    def test_the_default_list_is_what_the_requirement_names(self) -> None:
        assert DEFAULT_TCP_PORTS == (22, 443)

    def test_a_port_off_the_list_is_refused(self) -> None:
        with pytest.raises(ProbeViolationError, match="not on this scope's list"):
            authorise(ProbeKind.TCP_CONNECT, "10.0.0.1", port=23, allowed_ports=(22, 443))

    def test_a_configured_port_is_allowed(self) -> None:
        """ "Configurable list" is in the requirement — SSH on 2222 is ordinary."""
        probe = authorise(
            ProbeKind.TCP_CONNECT, "10.0.0.1", port=2222, allowed_ports=(22, 443, 2222)
        )

        assert probe.port == 2222

    def test_a_list_long_enough_to_be_a_sweep_is_refused(self) -> None:
        """The drift this package exists to resist.

        Every port on a long list is individually permitted by FR-DISC-02's "configurable
        list", and the result is still a port scan. The ceiling makes assembling one out
        of permitted probes impossible.
        """
        with pytest.raises(ProbeViolationError, match="port sweeps"):
            normalise_ports(tuple(range(1, PORT_CEILING + 5)))

    def test_an_over_long_list_is_refused_not_truncated(self) -> None:
        """Truncating would leave the operator believing ports were checked.

        A host reported "reachable on nothing" because the probe was silently dropped
        reads identically to a host that is genuinely closed.
        """
        with pytest.raises(ProbeViolationError):
            normalise_ports(tuple(range(20, 20 + PORT_CEILING + 1)))

    def test_duplicates_collapse_and_order_is_stable(self) -> None:
        assert normalise_ports([443, 22, 443, 22]) == (22, 443)

    @pytest.mark.parametrize("port", [0, -1, 65536, 99999])
    def test_impossible_port_numbers(self, port: int) -> None:
        with pytest.raises(ProbeViolationError):
            normalise_ports((port,))

    def test_an_empty_list_falls_back_to_the_default(self) -> None:
        assert normalise_ports(()) == DEFAULT_TCP_PORTS
        assert normalise_ports(None) == DEFAULT_TCP_PORTS


class TestSnmp:
    def test_snmp_needs_a_configured_credential(self) -> None:
        """FR-DISC-02 calls SNMP optional; without a credential there is nothing to use.

        Probing anyway would mean trying `public`, which is a credential guess. SRS §1.2
        rules out brute-forcing, and one guess is the thin end of that.
        """
        with pytest.raises(ProbeViolationError, match="no brute-forcing"):
            authorise(ProbeKind.SNMP_SYSDESCR, "10.0.0.1", snmp_configured=False)

    def test_with_a_credential_it_reads_the_two_permitted_oids(self) -> None:
        probe = authorise(ProbeKind.SNMP_SYSDESCR, "10.0.0.1", snmp_configured=True)

        assert probe.oids == PERMITTED_OIDS
        assert probe.port == 161

    def test_only_sysdescr_and_sysobjectid(self) -> None:
        assert set(PERMITTED_OIDS) == {"1.3.6.1.2.1.1.1.0", "1.3.6.1.2.1.1.2.0"}

    @pytest.mark.parametrize(
        "oid",
        [
            "1.3.6.1.2.1.1.5.0",  # sysName — identifying, but not on the list
            "1.3.6.1.2.1.2.2.1.2",  # ifDescr — inventory, needs an onboarded device
            "1.3.6.1.4.1.9.9.23.1.2.1.1.6",  # CDP neighbours — topology
            "1.3.6.1.2.1.1",  # the subtree rather than a leaf
        ],
    )
    def test_any_other_oid_is_refused(self, oid: str) -> None:
        """Walking the MIB is collection's job, and collection needs approval first."""
        with pytest.raises(ProbeViolationError, match="sysDescr and sysObjectID"):
            authorise(ProbeKind.SNMP_SYSDESCR, "10.0.0.1", snmp_configured=True, oids=(oid,))


class TestTargets:
    def test_a_hostname_is_refused(self) -> None:
        """A name resolves at send time to something the guard never inspected.

        It also makes the audit record a label rather than the address contacted, which
        is the wrong answer to "what did you touch on our network".
        """
        with pytest.raises(ProbeViolationError, match="not an IP address"):
            authorise(ProbeKind.TCP_CONNECT, "switch.example.com", port=22)

    @pytest.mark.parametrize("host", ["", "   ", "10.0.0.256", "not-an-ip", "10.0.0.1/24"])
    def test_malformed_targets(self, host: str) -> None:
        with pytest.raises(ProbeViolationError):
            authorise(ProbeKind.TCP_CONNECT, host, port=22)

    def test_ipv6_is_accepted_and_normalised(self) -> None:
        probe = authorise(ProbeKind.TCP_CONNECT, "2001:0db8:0000::1", port=443)

        assert probe.host == "2001:db8::1"

    def test_an_icmp_probe_carries_no_port(self) -> None:
        with pytest.raises(ProbeViolationError, match="no port"):
            authorise(ProbeKind.ICMP_ECHO, "10.0.0.1", port=22)

    def test_a_tcp_probe_without_a_port_is_refused(self) -> None:
        with pytest.raises(ProbeViolationError, match="needs a TCP port"):
            authorise(ProbeKind.SSH_BANNER, "10.0.0.1")

    def test_an_authorised_probe_describes_itself_for_the_audit_log(self) -> None:
        probe = authorise(ProbeKind.SSH_BANNER, "10.0.0.1", port=22)

        assert probe.describe() == "ssh_banner 10.0.0.1:22"


# ═════════════════════════════ scopes ════════════════════════════════════════


class TestTargetParsing:
    def test_a_cidr(self) -> None:
        assert parse_target("10.0.0.0/24") == [ipaddress.ip_network("10.0.0.0/24")]

    def test_a_single_address_becomes_a_host_route(self) -> None:
        assert parse_target("10.0.0.5") == [ipaddress.ip_network("10.0.0.5/32")]

    def test_a_host_bit_inside_a_cidr_is_read_as_the_network(self) -> None:
        """Operators write `10.0.0.5/24` constantly and mean the /24."""
        assert parse_target("10.0.0.5/24") == [ipaddress.ip_network("10.0.0.0/24")]

    def test_a_hyphenated_range_becomes_covering_cidrs(self) -> None:
        """Summarised rather than expanded, so exclusion can subtract from it."""
        networks = parse_target("10.0.0.10-10.0.0.20")

        assert sum(net.num_addresses for net in networks) == 11

    @pytest.mark.parametrize(
        "entry",
        ["", "   ", "not-an-address", "10.0.0.20-10.0.0.10", "10.0.0.1-2001:db8::1"],
    )
    def test_malformed_entries(self, entry: str) -> None:
        with pytest.raises(ValidationProblem):
            parse_target(entry)


class TestScopeSizeCeiling:
    def test_a_mistyped_prefix_is_refused(self) -> None:
        """`/8` is one character from `/18` and sixteen million probes from it.

        The worst thing this package could do is send those. The refusal names the
        likely cause, because an operator who sees "over the limit" and nothing else
        raises the limit.
        """
        with pytest.raises(ValidationProblem, match="mistyped prefix"):
            build_scope("typo", ["10.0.0.0/8"])

    def test_the_ceiling_is_checked_without_enumerating(self) -> None:
        """A /8 must be refused in constant time, not by exhausting memory first."""
        with pytest.raises(ValidationProblem):
            build_scope("huge", ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"])

    def test_a_large_block_mostly_excluded_is_allowed(self) -> None:
        """The ceiling applies to what will actually be probed.

        Exclusions are subtracted before the count, so a block far over the limit that
        has been carved down to a /16 is allowed — the operator is probing 65,534
        addresses regardless of how they described them.
        """
        scope = build_scope(
            "carved",
            ["10.0.0.0/12"],  # 1,048,574 on its own — well over the ceiling
            exclusions=["10.0.0.0/13", "10.8.0.0/14", "10.12.0.0/15", "10.14.0.0/16"],
        )

        assert scope.size == 65_534, "everything but 10.15.0.0/16 was removed"
        assert scope.size < MAX_SCOPE_HOSTS
        assert scope.covers("10.15.0.1")
        assert not scope.covers("10.0.0.1")

    def test_a_sixteen_bit_block_is_within_the_ceiling(self) -> None:
        scope = build_scope("flat-mgmt", ["10.10.0.0/16"])

        assert scope.size == 65_534

    def test_an_empty_target_list_is_refused(self) -> None:
        with pytest.raises(ValidationProblem, match="at least one target"):
            build_scope("nothing", [])


class TestExclusions:
    def test_an_excluded_block_is_removed_from_the_address_space(self) -> None:
        """Subtracted, not filtered.

        Filtering at probe time leaves the excluded addresses one missing `continue`
        away from being contacted. Subtracting means they are never enumerated at all.
        """
        scope = build_scope("campus", ["10.0.0.0/24"], exclusions=["10.0.0.128/25"])

        assert scope.covers("10.0.0.10")
        assert not scope.covers("10.0.0.200")
        assert all(int(host) < int(ipaddress.ip_address("10.0.0.128")) for host in scope.hosts())

    def test_an_excluded_host_never_appears_in_enumeration(self) -> None:
        scope = build_scope("campus", ["10.0.0.0/29"], exclusions=["10.0.0.3"])

        assert ipaddress.ip_address("10.0.0.3") not in list(scope.hosts())

    def test_an_exclusion_swallowing_the_whole_target_leaves_nothing(self) -> None:
        scope = build_scope("cancelled", ["10.0.0.0/24"], exclusions=["10.0.0.0/16"])

        assert scope.size == 0
        assert list(scope.hosts()) == []

    def test_an_exclusion_outside_the_target_changes_nothing(self) -> None:
        scope = build_scope("elsewhere", ["10.0.0.0/24"], exclusions=["192.168.1.0/24"])

        assert scope.size == 254

    def test_exclusions_do_not_count_toward_the_ceiling(self) -> None:
        scope = build_scope("campus", ["10.0.0.0/24"], exclusions=["10.0.0.128/25"])

        assert scope.size == 126, "254 minus the excluded half"


class TestScopeEnumeration:
    def test_a_single_host_scope_yields_that_host(self) -> None:
        """A /32 has no `hosts()` by the stdlib's definition, and is how an operator
        names one device."""
        scope = build_scope("one", ["10.0.0.5"])

        assert [str(host) for host in scope.hosts()] == ["10.0.0.5"]

    def test_network_and_broadcast_are_not_probed(self) -> None:
        scope = build_scope("small", ["10.0.0.0/29"])
        hosts = [str(host) for host in scope.hosts()]

        assert "10.0.0.0" not in hosts
        assert "10.0.0.7" not in hosts
        assert len(hosts) == 6

    def test_enumeration_is_lazy(self) -> None:
        """A /16 within the ceiling is 65,534 addresses; the first probe should not
        wait for all of them to be materialised."""
        scope = build_scope("flat", ["10.10.0.0/16"])
        hosts = scope.hosts()

        assert str(next(hosts)) == "10.10.0.1"

    def test_the_default_is_a_review_queue_not_auto_onboarding(self) -> None:
        """FR-DISC-04: nothing is assessed without approval unless someone opted in."""
        assert build_scope("default", ["10.0.0.0/24"]).auto_onboard is False
