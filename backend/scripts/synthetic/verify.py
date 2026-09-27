"""Parse one rendered configuration per platform and report what reached the NCM.

Run before seeding, and worth running after any change to a renderer. A configuration
that renders but does not parse produces a device with an empty normalised model —
which is the worst outcome available here, because the device still appears in the
inventory, still counts in totals, and contributes nothing to any feature. It looks
like data.

Routes get the most attention because they are the join the layer-3 graph is built
from, and a firewall with no routes is invisible to path analysis while looking
perfectly healthy everywhere else.
"""

from __future__ import annotations

import sys

from synthetic.plan import build_plan
from synthetic.render import render

from netsecops.parsers.base import ParseContext
from netsecops.parsers.registry import get_parser


def _summarise(ncm) -> dict[str, int]:
    firewall = ncm.firewall
    return {
        "ifaces": len(ncm.interfaces),
        "routes": len(ncm.routing.routes),
        "rules": len(firewall.security_rules),
        # Rules in force, which is not the same number. On Cisco, writing an access list
        # and binding it to an interface are separate acts; `applied` is None on PAN-OS,
        # FortiOS and Check Point, where a rule is in force by existing. A firewall whose
        # rules are all unbound enforces nothing while looking correct in every other
        # column here — which is exactly what happened to four ASAs in this estate.
        "inforce": sum(1 for rule in firewall.security_rules if rule.applied is not False),
        "nat": len(firewall.nat_rules),
        "objects": len(firewall.address_objects),
        "users": len(ncm.users),
        "snmp": len(ncm.snmp.v1v2c_communities),
        "syslog": len(ncm.logging.syslog_servers),
        "ntp": len(ncm.ntp.servers),
        "acls": len(ncm.acls),
    }


def main() -> int:
    # The estate that will actually be seeded, not a sample of it. Sampling was tried
    # twice and was wrong twice: the platform cycle has five entries, the hardening cycle
    # six, and the two only align at particular sites — the weak ASA that turned out to
    # be enforcing nothing exists only at sites six through nine, so no six-site sample
    # contains one. Rendering and parsing all 650 takes a few seconds, which is nothing
    # beside the seed it is run before.
    plan = build_plan()

    #: Platforms that legitimately carry no routes, so an empty table is not a fault.
    #: A Check Point management server holds policy and forwards nothing.
    ROUTELESS = {"checkpoint_mgmt"}

    seen: dict[str, dict] = {}
    problems: list[str] = []

    # Every node is checked; only the first of each platform/hardening pair reaches the
    # table. Sampling for the checks as well as for the table is how an unbound ASA got
    # through: a weak *edge* firewall claimed the `cisco_asa/weak` slot and the weak
    # *segment* firewall behind it — the one with no interface named `outside`, and no
    # access list bound to anything — was never rendered at all.
    for site in plan:
        for node in site.nodes:
            key = f"{node.platform}/{node.hardening.value}"
            where = f"{key} ({node.tier.value})"

            try:
                text = render(node)
                parser = get_parser(node.platform)
                result = parser.parse(ParseContext(text=text))
            # Caught broadly and reported rather than raised: one platform whose
            # renderer and parser disagree should not hide the state of the other
            # twelve, and finding out about them one run at a time is the slow way.
            except Exception as exc:
                problems.append(f"{where}: {type(exc).__name__}: {exc}")
                continue

            counts = _summarise(result)
            seen.setdefault(key, counts)

            if counts["ifaces"] == 0 and node.interfaces:
                problems.append(
                    f"{where}: {len(node.interfaces)} interface(s) planned, none parsed"
                )
            routes_wanted = sum(1 for v in node.routes.values() if v != "connected")
            if routes_wanted and counts["routes"] == 0 and node.platform not in ROUTELESS:
                problems.append(
                    f"{where}: {routes_wanted} static route(s) planned, none parsed — "
                    "this device would be invisible to path analysis"
                )
            # A Gaia gateway genuinely holds no policy — on Check Point the rulebase
            # lives on the management server — so an empty rulebase there is correct
            # rather than a rendering fault.
            if node.device_class == "firewall" and node.platform != "checkpoint_gaia":
                if counts["rules"] == 0:
                    problems.append(f"{where}: a firewall parsed with no rules")
                elif counts["inforce"] == 0:
                    problems.append(
                        f"{where}: {counts['rules']} rule(s) and none of them bound to an "
                        "interface — this firewall enforces nothing, and looks healthy "
                        "in every other column"
                    )

    problems = sorted(set(problems))

    if seen:
        width = max(len(k) for k in seen)
        header = f"{'platform/hardening':<{width}}  " + "  ".join(
            f"{k:>9}" for k in next(iter(seen.values()))
        )
        print(header)
        print("-" * len(header))
        for key, counts in sorted(seen.items()):
            print(f"{key:<{width}}  " + "  ".join(f"{v:>9}" for v in counts.values()))

    if problems:
        print(f"\n{len(problems)} problem(s):\n")
        for problem in problems:
            print(f"  {problem}")
        return 1

    print("\nEvery rendered platform parses into a populated model.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
