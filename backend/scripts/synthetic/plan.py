"""The shape of the synthetic estate: sites, tiers and an address plan.

Built as data before anything is rendered, so the addresses are allocated once and both
sides of every link agree. A device's static route names its neighbour's *interface*
address, and the layer-3 graph joins on exactly that — an address that is off by one
produces a device that looks fine in the inventory and is invisible to path analysis.

The tiers, per site:

    internet
       │  198.51.<s>.1                     (unmanaged — the path stops here, on purpose)
    ┌──┴──────────┐
    │ edge fw     │ outside 198.51.<s>.2/29     inside 10.<b>.0.1/30
    └──┬──────────┘
       │ 10.<b>.0.2
    ┌──┴──────────┐
    │ core router │ up 10.<b>.0.2/30            down 10.<b>.1.1/24
    └──┬──────────┘
       │ 10.<b>.1.<r+1>
    ┌──┴──────────┐
    │ dist router │ up 10.<b>.1.<r+1>/24        vlan 10.<b>.<10+k>.1/24
    └──┬──────────┘
       │
    ┌──┴──────────┐
    │ access sw   │ 10.<b>.<10+k>.2/24
    └─────────────┘

`b` is the site's second octet, `r` the router index, `k` the switch index. The segment
firewalls (02..05) hang off the core on their own transit /30s and protect a DMZ each,
which is what gives the segmentation matrix pairs that are genuinely separated by a
control rather than by a missing route.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum


class Tier(StrEnum):
    EDGE_FIREWALL = "edge-firewall"
    SEGMENT_FIREWALL = "segment-firewall"
    MANAGEMENT = "management"
    CORE_ROUTER = "core-router"
    DIST_ROUTER = "dist-router"
    ACCESS_SWITCH = "access-switch"


class Hardening(StrEnum):
    """How much of the check library a device is expected to fail.

    Spread deliberately rather than randomly: an estate where everything fails is as
    useless for testing a findings console as one where nothing does, and the
    interesting screens are the ones showing a mix.
    """

    WEAK = "weak"
    STANDARD = "standard"
    HARDENED = "hardened"


@dataclass(slots=True)
class Node:
    """One planned device, before any configuration text exists."""

    hostname: str
    mgmt_ip: str
    platform: str
    vendor: str
    device_class: str
    tier: Tier
    hardening: Hardening
    site: int
    criticality: str
    #: interface name → "address/prefix", as the device will carry them.
    interfaces: dict[str, str] = field(default_factory=dict)
    #: "prefix" → next-hop address. Every next hop is another node's interface address.
    routes: dict[str, str] = field(default_factory=dict)
    #: Zone name → interface, for the platforms that have zones.
    zones: dict[str, str] = field(default_factory=dict)
    #: Free-text, written to the device's notes so the inventory explains itself.
    purpose: str = ""


@dataclass(slots=True)
class Site:
    index: int
    name: str
    #: The site's second octet: 10.<base>.0.0/16 is its whole address space.
    base: int
    nodes: list[Node] = field(default_factory=list)


#: Named so a filtered inventory reads like somewhere real rather than "site-7".
SITE_NAMES = (
    "London",
    "Frankfurt",
    "Singapore",
    "Mumbai",
    "Sydney",
    "Toronto",
    "Dublin",
    "Tokyo",
    "Dubai",
    "Chicago",
)

#: Which platform each firewall slot runs, cycled across sites so every vendor appears
#: at several sites rather than all of one vendor living in one place — a per-vendor
#: filter should return devices from across the estate.
FIREWALL_PLATFORMS = (
    ("cisco_asa", "cisco"),
    ("panos", "paloalto"),
    ("fortios", "fortinet"),
    ("checkpoint_gaia", "checkpoint"),
    ("checkpoint_mgmt", "checkpoint"),
)

#: Hardening by index, so each site has the same spread: mostly standard, a few weak,
#: a few hardened. Weak devices are what put findings on the board.
_HARDENING_CYCLE = (
    Hardening.STANDARD,
    Hardening.WEAK,
    Hardening.STANDARD,
    Hardening.HARDENED,
    Hardening.WEAK,
    Hardening.STANDARD,
)


def _hardening(index: int) -> Hardening:
    return _HARDENING_CYCLE[index % len(_HARDENING_CYCLE)]


def build_plan(
    *,
    sites: int = 10,
    firewalls_per_site: int = 5,
    routers_per_site: int = 10,
    switches_per_site: int = 50,
) -> list[Site]:
    """Allocate the whole estate.

    Defaults give 50 firewalls, 100 routers and 500 switches across ten sites.
    """
    planned: list[Site] = []

    for s in range(sites):
        base = 20 + s
        site = Site(index=s, name=SITE_NAMES[s % len(SITE_NAMES)], base=base)

        # ── the edge firewall ────────────────────────────────────────────
        platform, vendor = FIREWALL_PLATFORMS[s % len(FIREWALL_PLATFORMS)]
        # A management server holds policy and routes nothing, so it can never be the
        # edge. The next platform in the cycle takes the slot instead.
        if platform == "checkpoint_mgmt":
            platform, vendor = FIREWALL_PLATFORMS[0]

        edge = Node(
            hostname=f"{site.name.lower()}-edge-fw-01",
            mgmt_ip=f"10.100.{s}.11",
            platform=platform,
            vendor=vendor,
            device_class="firewall",
            tier=Tier.EDGE_FIREWALL,
            hardening=_hardening(s),
            site=s,
            criticality="critical",
            interfaces={"outside": f"198.51.{s}.2/29", "inside": f"10.{base}.0.1/30"},
            routes={f"10.{base}.0.0/16": f"10.{base}.0.2", "0.0.0.0/0": f"198.51.{s}.1"},
            zones={"untrust": "outside", "trust": "inside"},
            purpose="The site's internet edge. Every path out of the site crosses it.",
        )
        site.nodes.append(edge)

        # ── segment firewalls, each protecting one DMZ ───────────────────
        for f in range(1, firewalls_per_site):
            platform, vendor = FIREWALL_PLATFORMS[(s + f) % len(FIREWALL_PLATFORMS)]
            transit = 4 * f  # 10.<base>.0.4/30, .8/30, .12/30 …
            dmz_octet = 200 + f
            is_manager = platform == "checkpoint_mgmt"

            node = Node(
                hostname=f"{site.name.lower()}-{'mgmt' if is_manager else 'seg'}-fw-{f + 1:02d}",
                mgmt_ip=f"10.100.{s}.{11 + f}",
                platform=platform,
                vendor=vendor,
                device_class="firewall",
                tier=Tier.MANAGEMENT if is_manager else Tier.SEGMENT_FIREWALL,
                hardening=_hardening(s + f),
                site=s,
                criticality="high",
                purpose=(
                    "A Check Point management server: it holds the policy and routes "
                    "nothing, so a path never crosses it and its rulebase is still "
                    "analysed."
                    if is_manager
                    else f"Protects the {dmz_octet} DMZ from the rest of the site."
                ),
            )
            if not is_manager:
                node.interfaces = {
                    "inside": f"10.{base}.0.{transit + 2}/30",
                    "dmz": f"10.{base}.{dmz_octet}.1/24",
                }
                node.routes = {
                    "0.0.0.0/0": f"10.{base}.0.{transit + 1}",
                    f"10.{base}.{dmz_octet}.0/24": "connected",
                }
                node.zones = {"trust": "inside", "dmz": "dmz"}
            site.nodes.append(node)

        # ── the core router ──────────────────────────────────────────────
        core_interfaces = {
            "uplink": f"10.{base}.0.2/30",
            "distribution": f"10.{base}.1.1/24",
        }
        for f in range(1, firewalls_per_site):
            if site.nodes[f].tier is Tier.SEGMENT_FIREWALL:
                core_interfaces[f"dmz-transit-{f}"] = f"10.{base}.0.{4 * f + 1}/30"

        core = Node(
            hostname=f"{site.name.lower()}-core-rtr-01",
            mgmt_ip=f"10.100.{s}.21",
            platform="cisco_nxos",
            vendor="cisco",
            device_class="router",
            tier=Tier.CORE_ROUTER,
            hardening=_hardening(s + 3),
            site=s,
            criticality="critical",
            interfaces=core_interfaces,
            routes={"0.0.0.0/0": f"10.{base}.0.1"},
            purpose="Everything in the site meets here. It carries no rulebase.",
        )
        # Reaching each DMZ means going through its firewall.
        for f in range(1, firewalls_per_site):
            if site.nodes[f].tier is Tier.SEGMENT_FIREWALL:
                core.routes[f"10.{base}.{200 + f}.0/24"] = f"10.{base}.0.{4 * f + 2}"
        site.nodes.append(core)

        # ── distribution routers ─────────────────────────────────────────
        dist_count = routers_per_site - 1
        for r in range(dist_count):
            node = Node(
                hostname=f"{site.name.lower()}-dist-rtr-{r + 2:02d}",
                mgmt_ip=f"10.100.{s}.{22 + r}",
                platform="cisco_ios" if r % 2 else "cisco_nxos",
                vendor="cisco",
                device_class="router",
                tier=Tier.DIST_ROUTER,
                hardening=_hardening(s + r + 1),
                site=s,
                criticality="high",
                interfaces={"uplink": f"10.{base}.1.{r + 2}/24"},
                routes={"0.0.0.0/0": f"10.{base}.1.1"},
                purpose="Distribution. Aggregates access switches onto the core.",
            )
            site.nodes.append(node)

        # ── access switches ──────────────────────────────────────────────
        for k in range(switches_per_site):
            parent = k % dist_count
            vlan_octet = 10 + k
            dist = site.nodes[firewalls_per_site + 1 + parent]

            # The switch's gateway is an SVI on its distribution router, so the router
            # gains an interface and a connected route for every switch it serves.
            dist.interfaces[f"vlan{vlan_octet}"] = f"10.{base}.{vlan_octet}.1/24"

            site.nodes.append(
                Node(
                    hostname=f"{site.name.lower()}-acc-sw-{k + 1:03d}",
                    mgmt_ip=f"10.100.{s}.{100 + k}",
                    platform="cisco_ios",
                    vendor="cisco",
                    device_class="switch",
                    tier=Tier.ACCESS_SWITCH,
                    hardening=_hardening(s + k),
                    site=s,
                    criticality="medium" if k % 5 else "high",
                    interfaces={f"vlan{vlan_octet}": f"10.{base}.{vlan_octet}.2/24"},
                    routes={"0.0.0.0/0": f"10.{base}.{vlan_octet}.1"},
                    purpose=f"Access switch on VLAN {vlan_octet}.",
                )
            )

        # The core has to know how to reach every access VLAN, via the distribution
        # router that actually serves it.
        for k in range(switches_per_site):
            parent = k % dist_count
            core.routes[f"10.{base}.{10 + k}.0/24"] = f"10.{base}.1.{parent + 2}"

        planned.append(site)

    return planned


def summarise(plan: list[Site]) -> dict[str, int]:
    counts: dict[str, int] = {}
    for site in plan:
        for node in site.nodes:
            counts[node.device_class] = counts.get(node.device_class, 0) + 1
            counts[f"platform:{node.platform}"] = counts.get(f"platform:{node.platform}", 0) + 1
    counts["sites"] = len(plan)
    counts["devices"] = sum(len(site.nodes) for site in plan)
    return counts
