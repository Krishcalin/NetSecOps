"""Capability that was built, permitted, and is used by nothing (SRS §8.2).

Nine defects of one shape were found by hand in two days: an approved command no
profile issues, a controller's access-point list nothing parsed, checks filed away from
the device class whose data fills them, a status the console rendered as its opposite,
a field returned by the API and shown nowhere, a count that never reached the response.
Every one was found because somebody happened to look. `vendor-research.md` §2 and §4a
record three more from earlier, and `api-reachability.md` exists because the same shape
turned up in the API surface.

**This file is the attempt to stop finding them one at a time.** Four seams were
measured; exactly one is crisply checkable, and the other three are recorded below as
rejected so nobody spends the afternoon re-attempting them.

---

**What works: an approved command no profile issues.** Both sides are data — a
`PlatformPolicy`'s rules and a `CollectionProfile`'s commands — and `CommandRule`
already compiles to the exact regex the guard matches with, so the comparison is the
real one rather than a string-equality approximation. It found
`show cdp neighbors detail` and `show lldp neighbors detail`: approved in SRS §8.2, on
two allow-lists, issued by no profile and parsed by nothing, which is why the topology
graph is built from routing tables and configuration and cannot say what is physically
adjacent to what.

**Rejected: an NCM field no check reads.** 289 of 355 populated fields are never
mentioned by a check expression, because checks are only one consumer — the rulebase
analyser, the topology builder, the vulnerability matcher, the reports and the console
all read the NCM too. At that ratio it is not a signal.

**Rejected: a job type nothing creates.** There is no such thing: `JobCreate.job_type`
and `ScheduleCreate.job_type` are both plain `JobType`, so the generic endpoint and the
scheduler can create every one. The interesting property — whether anything creates a
`vuln_rematch` *automatically when a feed import changes the catalogue* — is about
absent behaviour, and absent behaviour is not machine-checkable.

**Rejected: a collected command whose output nothing parses.** Parsers consume
supporting artefacts three different ways — `ParseContext.artifact()`, a bundle lookup
keyed by endpoint, and scanning `context.lines` when the whole collection is one blob —
so a static sweep sees the first and misses the other two. Measured at five commands
"read" out of about a hundred issued, which is a detector reporting itself broken.
"""

from __future__ import annotations

from netsecops.adapters.policies import POLICIES, PlatformPolicy, get_policy
from netsecops.adapters.profiles import PROFILES

# ─────────────────────────── the declared backlog ───────────────────────────

#: Every allow-listed command that no profile issues, with why. Modelled on
#: `api-reachability.md`'s triage: the point is not that the list is empty — it is that
#: it is **bounded, visible, and cannot grow without somebody writing a line here**.
#:
#: `NOT TRIAGED` is an honest verdict rather than a placeholder. These were approved in
#: SRS §8.2 by a customer's security reviewer and never asked for; whether each is a
#: real data gap or a command nobody needs takes a person who knows the platform, and
#: guessing a reason per entry would make this file look decided when it is not.
#:
#: Removing an entry means one of two things happened, and both are progress: a profile
#: now issues it, or it came off the allow-list. Narrowing an allow-list is the better
#: outcome where nothing needs the command — this product's promise is what it *may*
#: send, not only what it does.
_NOT_TRIAGED = (
    "NOT TRIAGED — approved in SRS §8.2 and never issued. Either a data gap worth "
    "closing or a command to remove from the allow-list; deciding needs somebody who "
    "knows the platform."
)
_UNUSED_PRIVILEGE = (
    "Approved under SRS §8.1.4 and issued by nothing — not a profile, and not the "
    "session layer. Every collection profile reads what it needs without escalating."
)

DECLARED_UNISSUED: dict[tuple[str, str], str] = {
    # The three CDP/LLDP entries that were here are gone, which is what shrinking this
    # list looks like: the profiles issue them now and the parsers read them, so the
    # declarations went stale and `test_no_declaration_outlives_the_thing_it_explains`
    # said so on the same run that made them true.
    ("cisco_ios", "enable"): _UNUSED_PRIVILEGE,
    ("cisco_asa", "enable"): _UNUSED_PRIVILEGE,
    **{
        ("cisco_ios", command): _NOT_TRIAGED
        for command in (
            "show interfaces description",
            "show ip route summary",
            "show ssh",
            "show crypto key mypubkey rsa",
            "show snmp community",
            "show aaa method-lists all",
            "show tacacs",
            "show radius server-group all",
            "show ntp associations",
            "show logging | include (Trap|Buffer|Logging to)",
            "show users",
            "show access-lists",
            "show ip access-lists",
            "show clock",
            "show archive",
            "show redundancy",
            "show stackwise-virtual",
            "show switch",
            "show errdisable recovery",
        )
    },
    **{
        ("cisco_nxos", command): _NOT_TRIAGED
        for command in (
            "show vlan brief",
            "show snmp community",
            "show aaa authorization",
            "show radius-server",
            "show access-lists",
            "show hardware",
            "show system resources",
        )
    },
    **{
        ("cisco_asa", command): _NOT_TRIAGED
        for command in (
            "show nat",
            "show ssh sessions",
            "show snmp-server statistics",
            "show logging",
            "show crypto ikev1 sa",
            "show crypto ikev2 sa",
            "show context",
            "show local-host",
            "show run service-policy",
            "show run policy-map",
            "show run class-map",
            "show run ssh",
            "show run username",
        )
    },
    **{
        ("checkpoint_gaia", command): _NOT_TRIAGED
        for command in ("show hostname", "show syslog all", "cpstat os -f all", "cpinfo -y all")
    },
    **{
        ("cisco_wlc_aireos", command): _NOT_TRIAGED
        for command in (
            "show run-config",
            "show network summary",
            "show snmpcommunity",
            "show snmpv3user",
            "show time",
            "show logging",
            "show local-auth config",
        )
    },
    **{
        ("fortios", command): _NOT_TRIAGED
        for command in ("show", "get system performance status", "diagnose sys top")
    },
    **{
        ("linux_aaa", command): _NOT_TRIAGED
        for command in ("freeradius -v", "ss -lntup", "cat /etc/os-release")
    },
}

#: Platforms whose read-only contract exists and which nothing collects from. Legal —
#: `test_platform_keys` allows a policy without a profile — and each is a decision.
POLICIES_WITHOUT_A_PROFILE: dict[str, str] = {
    "cisco_iosxr": "Approved in SRS §1.3 and never built. No parser either.",
    "cisco_ftd_fmc": "Firepower via FMC, approved and not built.",
    "fortimanager": "Used for child enumeration (children.py), which is not a collection.",
    "radware_alteon": (
        "Deliberate, 2026-09-28. No sample of `cc` output exists in public "
        "documentation to write a parser against — see docs/new-device-families.md."
    ),
    "barracuda_waf": (
        "Deliberate, 2026-09-28. Only `services` is a confirmed object path and nothing "
        "names the field that says whether a service blocks or logs."
    ),
    "checkpoint_gaia_expert": "An escape, not a platform — see this module's siblings.",
    "linux_aaa_sudo": "An escape, not a platform.",
}


def _unissued() -> dict[tuple[str, str], str]:
    """Every approved command that no profile matching its policy issues.

    Keyed by the *policy's own* platform, because `POLICIES` carries alias keys onto
    shared objects — `cisco_iosxe` and `cisco_c9800` are both `CISCO_IOS`, and counting
    them separately would report every IOS command three times as unissued.
    """
    by_policy: dict[int, tuple[PlatformPolicy, list[str]]] = {}
    for platform in PROFILES:
        policy = get_policy(platform)
        by_policy.setdefault(id(policy), (policy, []))[1].append(platform)

    found: dict[tuple[str, str], str] = {}
    for policy, platforms in by_policy.values():
        issued = [command for p in platforms for command in PROFILES[p].all_commands()]
        for rule in policy.commands:
            # A placeholder rule can never match a profile's static command string, so
            # it would be a permanent false positive rather than a finding. A
            # session-only rule that went unissued is a formatting command nobody
            # needed, not a capability gap.
            if "<" in rule.pattern or rule.session_only:
                continue
            if not any(rule.compile().match(command) for command in issued):
                found[(policy.platform, rule.pattern)] = ""
    return found


class TestEveryApprovedCommandIsAccountedFor:
    """`vendor-research.md` §2 found four of these by reading. This finds all of them.

    The finding it records is worth restating: `show route` was on the Gaia allow-list
    and unissued, and issuing it made the SNMP route walk unnecessary — a whole
    subsystem deleted because somebody noticed a command in a list.
    """

    def test_the_sweep_finds_something(self) -> None:
        # A comparison that silently matched everything would make every assertion
        # below vacuous, which is the shape of failure this whole file is about.
        assert _unissued(), "the sweep found nothing at all — check the matching"

    def test_nothing_is_approved_and_unissued_without_a_reason(self) -> None:
        undeclared = sorted(key for key in _unissued() if key not in DECLARED_UNISSUED)

        assert undeclared == [], (
            "These commands are on a read-only allow-list and no profile issues them. "
            "Either issue them, remove them from the allow-list, or add a line to "
            "DECLARED_UNISSUED saying why they stay:\n  "
            + "\n  ".join(f"{platform}: {command}" for platform, command in undeclared)
        )

    def test_no_declaration_outlives_the_thing_it_explains(self) -> None:
        """A stale exemption is drift in the other direction.

        An entry here for a command a profile now issues is a reason nobody will read
        and a line nobody will delete, and it makes the list above look longer than the
        backlog really is.
        """
        found = _unissued()
        stale = sorted(key for key in DECLARED_UNISSUED if key not in found)

        assert stale == [], (
            "These are declared as unissued and are now issued, or have left the "
            "allow-list. Delete the declarations:\n  "
            + "\n  ".join(f"{platform}: {command}" for platform, command in stale)
        )

    def test_every_reason_says_something(self) -> None:
        for (platform, command), reason in DECLARED_UNISSUED.items():
            assert len(reason) > 30, f"{platform}: {command} has no real reason"


class TestEveryPolicyWithoutAProfileIsADecision:
    """A read-only contract for a platform nothing collects from.

    Legal, and `test_platform_keys` says so — `radware_alteon` and `barracuda_waf` were
    both landed deliberately in that state on 2026-09-28, because a profile implies a
    parser and neither could be written from public documentation. The point of pinning
    it is that the *next* one should be as deliberate.
    """

    @staticmethod
    def _uncollected() -> list[str]:
        """Policies that **no** profile resolves to.

        Not "policies whose own name has no profile", which was the first version and
        was wrong twice over: `cisco_iosxe` shares `cisco_ios`'s policy and would have
        read as uncollected, and `linux_aaa` is a shared contract with no platform of
        its own — `freeradius` and `tac_plus` both resolve to it and both collect.
        """
        used = {id(get_policy(platform)) for platform in PROFILES}
        return sorted(
            platform
            for platform, policy in POLICIES.items()
            if policy.platform == platform and id(policy) not in used
        )

    def test_there_are_some(self) -> None:
        assert self._uncollected(), "nothing to check — the filter is wrong"

    def test_each_one_is_declared(self) -> None:
        undeclared = [p for p in self._uncollected() if p not in POLICIES_WITHOUT_A_PROFILE]

        assert undeclared == [], (
            "These platforms may be sent commands and nothing ever sends them. Add a "
            f"line to POLICIES_WITHOUT_A_PROFILE: {undeclared}"
        )

    def test_no_declaration_is_stale(self) -> None:
        uncollected = set(self._uncollected())
        stale = sorted(p for p in POLICIES_WITHOUT_A_PROFILE if p not in uncollected)

        assert stale == [], f"these now have a profile; delete the declarations: {stale}"


class TestTheBacklogIsVisible:
    """The number itself, so a reader of the test output learns the size of the thing.

    Not asserted as a maximum — a ratchet would make adding an allow-list entry fail
    the build for the wrong reason. It is asserted as *known*, so a change of any size
    shows up in the diff of this file rather than only in a passing run.
    """

    def test_the_declared_backlog_is_the_size_it_says(self) -> None:
        # 61 when the sweep was written; 58 once CDP and LLDP were issued on both
        # platforms. The number moving is the point.
        assert len(DECLARED_UNISSUED) == 58

    def test_most_of_it_is_honestly_untriaged(self) -> None:
        # Stated rather than hidden behind invented per-command reasons. Writing a
        # plausible justification for each would make this file look decided, and a
        # decision nobody made is worse than an open question somebody can see.
        untriaged = [k for k, reason in DECLARED_UNISSUED.items() if reason is _NOT_TRIAGED]

        assert len(untriaged) == 56
