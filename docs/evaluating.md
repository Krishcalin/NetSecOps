# Evaluating NetSecOps

**Ten minutes, no device, no credential, no change window.**

Every product in this category is sold through a proof of concept that begins with a
nine-to-thirteen week implementation: credentials brokered, firewall rules opened,
collectors sited, a change window found. Nobody evaluates a tool on that budget — they
evaluate the vendor's willingness to spend it on them, which is a different question and
answers it much later than it should.

So NetSecOps ships a demonstration estate. One command stands up four devices across
three vendors, ingests a configuration for each, assesses them, imports advisories and
matches them. The result is a console with real findings in it.

```bash
docker compose up -d
docker compose exec api netsecops-cli create-admin --username you --email you@example.com
docker compose exec api netsecops-cli demo-seed
```

---

## What is real, and what is not

**The devices are not real. Everything said about them is.**

The four configurations ship with the product. They are ingested through the same path an
operator's configuration upload uses (FR-COL-11), parsed by the same parsers a live
collection uses, stored as the same sealed artefacts and snapshots, and assessed by the
same check engine against the same 103-check library. There is no demonstration write
path — deliberately, because a demonstration write path is how a demo comes to show
something the product does not do.

Every finding you see is the product's actual opinion of that configuration. The path
verdicts are computed from the parsed routing tables and rulebases. The vulnerability
matches come from real advisories weighed against the parsed software versions.

What is *not* real: the devices do not exist, so nothing is ever collected from them, no
credential is stored, and nothing on your network is contacted at any point.

Every seeded device carries the tag `netsecops-demo` and a note saying what it is for, so
whoever inherits the installation can tell at a glance which devices are not real.

---

## The estate

```
  users 10.10.10.0/24
    │
    ├─ demo-access-sw-01   cisco_ios 15.2      an ordinary switch nobody revisited
    ├─ demo-core-sw-01     cisco_nxos 10.3     hardened, and carries no rulebase
    ├─ demo-edge-fw-01     cisco_asa 9.18(2)   permits, and translates
    └─ demo-dmz-fw-01      panos 11.0          the rulebase worth reading
                              │
                              └─ DMZ 10.20.0.0/24, web server at 10.20.0.10
```

It is designed rather than sampled. Four devices, chosen so that each of the things this
product does differently has something real to show.

---

## What to look at, in order

### 1. Findings — the ordinary disaster

Start at **Findings**. `demo-access-sw-01` carries the most, and none of them is exotic:
telnet still enabled, SNMP on the default communities, no AAA, no session timeout,
passwords in the clear. It is a switch that was stood up quickly, worked, and was never
revisited. That is what most estates are made of.

Open one and read the **rationale**. Then go to **Checks**, find the same check, and read
the expression it evaluates. The first question anybody asks about a failed finding is
"what exactly did it look at", and it is answerable here rather than in a support ticket.

### 2. Path Analysis — the answer with two axes

Ask for **10.10.10.50 → 10.20.0.10, tcp/443**.

Every firewall on the path permits it and the trace reaches the destination. The verdict
is **partially allowed**, not allowed, and the note says why: the path continues past
`demo-edge-fw-01`, which carries NAT rules. The devices after it were asked about the
addresses in your query rather than the ones the packet was carrying.

That is the product's character in one answer. It would be easy to say "allowed". It
would also be a claim the data does not support, and somebody opens a firewall on the
strength of these answers.

Two more things in the same result:

- `demo-core-sw-01` reports **no decision**, not "allowed". It carries no rulebase. A
  router that forwarded without an opinion is not a control that was checked, and
  rendering the two the same is how an estate comes to look better defended than it is.
- `demo-edge-fw-01` also reports no decision, for a different reason the note gives:
  it carries several access lists bound to different interfaces, and which one governs
  this hop is not yet something the path walk can determine. See *Known limits* below.

Now ask for the same pair on **tcp/22**. That one is **blocked**, and it names the device
and the rule.

### 3. Firewall Analysis — the rulebase worth reading

Open `demo-dmz-fw-01`. Its rulebase contains, deliberately, what real ones contain:

- a **deny sitting above an allow that can never match** — an RDP block above an RDP
  permit for a partner range
- a **disabled migration rule** nobody removed
- an **any-any permit with logging off**
- a **duplicate address object** and an object nothing references

### 4. Vulnerabilities — the half the incumbents do not have

`demo-edge-fw-01` runs ASA 9.18(2). The shipped advisory sample matches it, and the
end-of-life sample says the 9.18 train left support in November 2025.

The NSPM tools in this category ingest vulnerability data from a scanner and have no
native detection of their own. This is computed from the configuration NetSecOps already
parsed.

### 5. Checks — and writing the hundred-and-fourth

Go to **Checks**. Browse the library, filter by platform, read a check's expression. Then
use **Ask the estate** to run one JMESPath expression across every device — `management.ssh.version`,
say — and see what each one selected, including the devices that could not be asked.

Then **Draft a check**. The preview runs a definition that does not exist yet and writes
nothing: no check, no result row, no finding, no risk score.

---

## Known limits, stated here rather than discovered

The demo will show you these, so they are worth saying first.

**A path across a Cisco device with more than one access list reports no decision.** The
device's policy is a set of ACLs bound to different interfaces, and which one governs a
given hop depends on the interface the packet arrives on — a binding that is recorded per
platform in shapes that do not yet agree. Rather than pick one and be confidently wrong
in a direction that says a control is already in place, the walk reports the decision as
unknown and names the ambiguity. Use the rule query against the specific access list to
settle it.

**Address translation is declared, not modelled.** The four firewall parsers disagree
about what their NAT fields mean — PAN-OS puts a rule's source members in `original`
whatever it translates, FortiOS puts a VIP's external address there, Check Point joins
several originals into one string, and Cisco ASA sets neither. A matcher built on that
would be wrong differently on each platform, so a path that continues past a translating
device says so instead.

**A shipped check cannot be copied as the starting point for a custom one.** The check
detail endpoint returns a check's expression but not its applicability or assertion. The
draft editor seeds a template instead.

---

## Clearing it up

```bash
docker compose exec api netsecops-cli demo-purge
```

Removes exactly the devices the seeder created, identified by tag. A device you added by
hand during the evaluation survives — this runs at the moment somebody is onboarding
their first real device, and deleting it then would be the worst possible time.

Imported advisories are left in place. They are public data about the world rather than
anything about your estate.

---

## Then a real device

The next step is one device, read-only, over SSH.

1. **Read [`docs/device-accounts.md`](device-accounts.md)** and create a read-only
   account on one device.
2. **Run `netsecops-cli audit-commands --platform cisco_ios`** (or your platform) and
   hand the output to whoever approves the change. It prints the complete list of what
   NetSecOps is permitted to send to that platform. Nothing outside it ever reaches a
   device — the conformance tests fail the build otherwise.
3. **Store the credential** under Credentials, assign it to the device, and use **Test
   against a device**. It performs one login and one trivial read, and shows you the
   command it issued.
4. **Collect**, and compare what it found with what you expected.

If SSH to the device is not available, **upload its configuration** instead: Inventory →
the device → Configuration → upload. It is assessed identically, which is also how
air-gapped sites run this permanently (C-7).
