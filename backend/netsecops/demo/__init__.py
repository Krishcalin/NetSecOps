"""A demonstration estate, so NetSecOps can be evaluated without a device.

Every product in this category is sold through a proof of concept that starts with a
nine-to-thirteen week implementation: credentials brokered, firewall rules opened,
collectors sited, a change window found. Nobody evaluates a tool on that budget — they
evaluate the vendor's willingness to spend it on them. The result is that the product is
only ever seen by people who have already decided to buy it.

This is the answer to that. `netsecops-cli demo seed` stands up four devices across three
vendors, ingests a configuration for each, assesses them, and leaves a console with real
findings in it. No device is contacted, no credential is needed, and nothing is
fabricated: the configurations are parsed by the same parsers, stored through the same
ingest path as a live collection (FR-COL-11), and assessed by the same check engine
against the same shipped library. The findings are the product's actual opinion of these
configurations.

**The estate is designed, not sampled.** Four devices chosen so that each of the things
this product does differently has something real to show:

    users 10.10.10.0/24
      │
      ├─ demo-access-sw-01   cisco_ios 15.2   telnet, SNMP defaults, no AAA, no timeout
      │                                        — an ordinary switch nobody revisited
      ├─ demo-core-sw-01     cisco_nxos 10.3  hardened, and carries no rulebase at all,
      │                                        so a path across it reports *no decision*
      ├─ demo-edge-fw-01     cisco_asa 9.18(2) permits, and translates. The path
      │                                        continues past it, so the verdict is
      │                                        `partially-allowed` with this device
      │                                        named — and 9.18(2) is old enough that
      │                                        the vulnerability engine matches it
      └─ demo-dmz-fw-01      panos 11.0       a shadowed rule pair, a disabled migration
                                               rule, an any-any permit with no logging,
                                               a duplicate address object. It translates
                                               too — and because the path *ends* here,
                                               that costs nothing, which is the other
                                               half of the same rule

**It refuses to run over a real installation.** Seeding checks that no device exists that
it did not create, and stops if one does. `demo purge` removes exactly what it created,
identified by tag, so an evaluation can be cleared before real onboarding begins rather
than leaving demonstration devices in an inventory somebody later reports on.
"""

from netsecops.demo.estate import (
    DEMO_DEVICES,
    DEMO_TAG,
    DemoDevice,
    SeedReport,
    purge_demo_estate,
    seed_demo_estate,
)

__all__ = [
    "DEMO_DEVICES",
    "DEMO_TAG",
    "DemoDevice",
    "SeedReport",
    "purge_demo_estate",
    "seed_demo_estate",
]
