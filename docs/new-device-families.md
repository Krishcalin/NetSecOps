# Wireless, link load balancers and web application firewalls

A study of four device families asked for on 2026-09-28: Cisco wireless access points,
Cisco wireless controllers, Radware link load balancers and Barracuda Web Application
Firewalls. Research conducted the same day against vendor documentation, scoped — as
everything in this product is — to **read-only** capability.

Read [vendor-research.md](vendor-research.md) first if you have not. Its standing rule
applies here without amendment:

> Everything here needs verifying before it is built. Treat the sources as the authority
> and this page as a map to them.

That rule has teeth on this page in a way it did not on that one. Two of these four
families are vendors NetSecOps has never touched, and for one of them — Radware — the
command catalogue is behind a support login that public documentation does not
substitute for. Every claim below is marked **verified**, **partial** or **unverified**,
and nothing marked unverified should reach a parser without a capture from a real
device. A misspelled key does not fail; it reads as "not configured" for ever.

---

## The finding that outranks the request

**The Catalyst 9800 is already in scope, already allow-listed, and is asked nothing.**

SRS §1.3 lists "Catalyst 9800 (IOS-XE)" under wireless controllers. SRS §8.2's approved
Cisco command set includes `show wireless summary`, `show wlan summary`, `show wlan all`,
`show ap summary`, `show ap config general` and `show wireless profile policy summary`.
All six are on the `cisco_ios` allow-list today, at `adapters/policies.py:90-95`.

**`CISCO_IOS_PROFILE` issues none of them.**

So a Catalyst 9800 onboarded as `cisco_iosxe` — which is what the platform picker
offers, and which is correct as far as configuration syntax goes — collects
successfully, parses successfully, and produces a Normalised Config Model whose
`wireless` section is empty. The five checks in `checks/library/wireless/` then report
*Not evaluated* on the one device in the estate they were written for, and the device's
page shows a clean-looking assessment of a switch that is actually a wireless
controller.

This is the third instance of one pattern. `vendor-research.md` §2 records four approved
Gaia commands never issued; §4a records three API platforms handed an artefact their
parsers could not read. In all three the capability was built, the permission was
granted, and nothing connected them. **Before building anything new here, wire up what
is already approved** — it is the cheapest work on this page and it closes a real gap
in the estate the request is about.

---

## Cisco wireless

### What is actually in the estate

Three controller generations and two kinds of access point, and they are not variations
of one thing:

| | Platform | Configuration surface | Status today |
|---|---|---|---|
| **AireOS controller** | 5520 / 8540 / vWLC | `show run-config commands` — a command *list*, not a config file | **Built.** `cisco_wlc_aireos`, full policy/profile/parser |
| **Catalyst 9800** | IOS-XE 16.10+ | Ordinary IOS-XE running-config, with wireless sub-modes | **Approved, allow-listed, never asked** |
| **EWC on AP** | Catalyst AP acting as controller | Identical IOS-XE syntax to the 9800 | Same as the 9800 |
| **Lightweight AP** | CAPWAP, joined to a controller | *None of its own* — the controller holds it | Not represented |
| **Autonomous AP** | Aironet / Mobility Express, IOS | Its own running-config | Not represented |

Two consequences fall straight out of that table.

**The EWC needs no platform of its own.** It runs the same IOS-XE image and the same
wireless configuration syntax as a 9800; the difference is where the process runs. One
platform key covers both, and inventing a second would produce two parsers that must be
kept identical.

**A lightweight AP is not a device to collect from.** Its configuration *is* the
controller's — the AP join profile, the RF profile and the policy tag that the
controller applies to it. Reaching out to a CAPWAP AP over SSH to read a configuration
it does not own would be device contact that buys nothing. Lightweight APs belong in the
inventory as **rows derived from the controller**, the way `adapters/children.py`
already derives FortiGates from a FortiManager and firewalls from Panorama. An
autonomous AP is the opposite case: it holds its own configuration, nothing else knows
what is on it, and it needs a collection path.

### How the Catalyst 9800 is read — **verified**

It is IOS-XE. SSH, the `cisco_ios` transport, the same `terminal length 0` session
setup. Nothing new is needed in `adapters/`.

What is new is the *shape of the configuration*. The 9800's model is not a flat list of
SSIDs; it is a set of profiles bound together by tags, and a check that reads only the
WLAN misses most of the posture:

- **WLAN profile** — the SSID and its layer-2 security. This is where WPA2/WPA3, the
  AKM, PMF and the PSK live.
- **Policy profile** — client VLAN, AAA override, session and idle timeout, ACLs,
  peer-to-peer blocking. Verified from the 17.16 configuration guide: the policy profile
  "specifies settings for client VLAN, Authentication, Authorization, and Accounting
  (AAA), Access Control Lists (ACLs), session and idle timeout settings".
- **AP join profile** — CAPWAP timers, the AP's own 802.1X supplicant, and **SSH/Telnet
  access to the AP itself**. Verified: the AP profile "contains general AP settings such
  as CAPWAP timers, 802.1X supplicant, SSH/Telnet settings".
- **Policy tag / site tag / RF tag** — which profiles apply to which APs. A WLAN that
  exists and is bound to no policy tag is not broadcasting anywhere, and a check that
  reports on it is reporting on nothing.

That last point is the one to get right. **An unbound WLAN is the 9800's silent-emptiness
trap**: the configuration contains it, a naive parser finds it, and a finding is raised
about an SSID no client can see. Bindings have to be parsed, not just profiles.

### WLAN security syntax — **verified** against the 17.16 configuration guides

These are exact, quoted from Cisco's WLAN Security and Wi-Fi Protected Access 3 chapters
for IOS-XE 17.16. They are what a parser matches on.

```
security wpa
security wpa wpa1
security wpa wpa1 ciphers [aes | tkip]
security wpa wpa2
security wpa wpa2 ciphers aes
security wpa wpa3
security wpa akm {cckm | dot1x | dot1x-sha256 | ft | psk | psk-sha256}
security wpa akm ft {dot1x | psk | sae}
security wpa akm sae
security wpa akm sae pwe {h2e | hnp | both-h2e-hnp}
security wpa akm owe
security wpa akm dot1x-sha256
security wpa transition-mode-wlan-id <wlan-id>
security pmf mandatory
security wpa psk set-key {ascii | hex} {0 | 8} <password>
security static-wep-key authentication {open | shared}
security static-wep-key encryption {40 | 104} {ascii | hex} 0 <key> <index>
transition-disable
no security wpa wpa1 ciphers tkip
```

Two facts worth carrying into the checks rather than re-deriving:

- **PMF is configured implicitly by WPA3-SAE.** Cisco states that protected management
  frames "are configured internally when configuring WPA3 SAE on a WLAN". A check that
  demands an explicit `security pmf mandatory` line on an SAE WLAN would fail a
  correctly configured network.
- **PMF is mandatory on 6 GHz.** Not a recommendation — the band will not operate
  without it, so a 6 GHz WLAN cannot be non-compliant on this point and a finding
  claiming otherwise is wrong.

### Show commands — **verified as existing**, unverified as a complete set

Confirmed present in Cisco's documentation: `show wlan summary`, `show wlan id <n>`,
`show wireless profile policy detailed <name>`, `show wireless pmk-cache`,
`show wireless stats client detail`, `show wireless client mac-address <mac> detail`.

Confirmed *approved for this product* by SRS §8.2 and already on the allow-list:
`show wireless summary`, `show wlan summary`, `show wlan all`, `show ap summary`,
`show ap config general <name>`, `show wireless profile policy summary`,
`show aaa method-lists all`.

**Not verified:** a command that lists the policy/site/RF tag bindings, and a command
that dumps the AP join profiles. Both are needed for the binding analysis above, and
neither spelling could be confirmed from public documentation in this pass. The safe
position is to take the WLAN and profile structure from the running configuration —
which the existing `show running-config` already collects — and add show commands only
once their output has been seen.

### Rogue detection and MFP — **verified**

Rogue AP detection is configured under the AP profile and is **enabled by default** as
part of the default AP profile. That default matters: a check written as "rogue
detection is not configured, therefore off" would fire on every correctly configured
controller in the estate. The check has to distinguish *disabled* from *absent*.

Infrastructure MFP adds a Message Integrity Check to management frames sent by APs, and
other APs validate them — this is AP impersonation detection, and it is separate from
the client-facing PMF above. Two different controls that a single "management frame
protection" check would conflate.

### What the checks should be

The `checks/library/wireless/` family has five checks written against the AireOS NCM.
Because they read the NCM's `wireless` section rather than raw text, **they apply to the
9800 unchanged the moment the parser fills that section** — which is the argument for
completing the parser before writing anything new.

Worth adding, in order of what an assessment would actually turn up:

1. **AP management access** — Telnet or SSH enabled to the APs from the AP join profile.
   Nothing in the product can see this today on any platform.
2. **AP 802.1X supplicant** — whether APs authenticate to the switch port they plug
   into. Cisco's own guidance is to configure both ends; an AP that does not
   authenticate is an unauthenticated port in a wiring closet.
3. **Unbound WLAN** — configured, invisible, and usually a leftover. Informational, not
   a failure.
4. **Peer-to-peer blocking on guest** — from the policy profile.
5. **AAA override without a RADIUS group** — a policy profile that trusts server
   attributes with no server configured.

---

## Radware Alteon — link load balancing

### What is verifiable, and what is not

**Verified.** The REST API authenticates with HTTP Basic: `Authorization: Basic
<base64 of username:password>`, and Radware states the header must be present on *any*
request or the device answers 401. The API's own documentation is served **from the
device** at `https://<device>/restdoc/`, available from Alteon 34.0.4, 33.5.8 and
33.0.12 upward.

**That is the problem.** The endpoint catalogue is on the appliance, not on the public
web, and Radware's support portal returns "Partial content displayed, please Sign In" to
an anonymous fetch. **The list of REST objects for Alteon could not be established from
public documentation, and nothing on this page should be taken as one.**

**Verified CLI facts**, from Radware's public support answers:

| Command | What it does |
|---|---|
| `/cfg/dump` | Dumps the configuration |
| `cc` | "Configuration dump without keys and certificates" |
| `/info/sys` | System capacity and current device metrics |
| `/info/slb` | Server load balancing information |
| `/stats/sp 1/allcpu` | Per-SP CPU usage |
| `/cfg/sys/access/snmp` | SNMP access level — read-only or read-write |
| `/cfg/sys/ssnmp/rcomm` / `/wcomm` | SNMP read and write community strings |

`cc` deserves attention. A vendor-provided configuration dump **with keys and
certificates already removed** is precisely the artefact this product wants: the
redaction happens on the device, before the data crosses the network, rather than in our
parser afterwards. Where a platform offers that, it should be preferred over the raw
dump. It is the only command on this page with that property.

### The read-only hazard, which is sharper here than anywhere else

**Alteon's configuration-dump command lives inside its configuration tree.** `/cfg/dump`
prints; `/cfg/sys/ssnmp/wcomm` sets the SNMP write community. They differ by a leaf.

Our three-layer guard does not degrade gracefully here:

- **Layer 2, the allow-list,** is fine — entries compile to fully anchored regexes, so
  `/cfg/dump` as an entry matches that string and nothing else. This is the layer that
  works.
- **Layer 3, the deny-list, gives Alteon nothing.** `DENY_PATTERN` is anchored at `^`
  and matches write verbs at the start of a command: `set `, `no `, `write`, `delete`.
  Every Alteon write starts with `/cfg/`, so the pattern never fires, and the
  cross-check that exists to catch a mis-specified allow-list entry is inert for this
  platform.

**This is the one change that must land before an Alteon adapter does.** Adding
`|/cfg/(?!dump\b)` to `DENY_PATTERN` denies everything under the configuration tree
except the dump leaf, and it is safe to add globally because no other platform issues a
command beginning `/cfg/`. Without it, a reviewer approving an Alteon allow-list is the
only thing standing between a typo and a write.

A second, smaller trap: **never write an allow-list entry of the form `/cfg/<arg>`.**
The placeholder charset `[A-Za-z0-9_.:/@=-]+` includes `/`, so one such entry would
admit the entire configuration tree in a single token.

### What an Alteon assessment is about

A link load balancer is not a firewall and the checks should not pretend otherwise. What
matters, in the order an assessor would ask:

1. **Management plane** — the same questions as every other device, and the ones the
   existing `common/` checks already ask: Telnet, HTTP, SNMP v1/v2c, default or weak
   community strings, local accounts, session timeout, syslog and NTP. `/cfg/sys/...`
   holds all of it and it is directly comparable across the estate. **This is where the
   value is**, and it needs no Alteon-specific check at all — only a parser that fills
   the NCM's existing `management`, `users`, `snmp`, `logging` and `ntp` sections.
2. **SSL/TLS termination posture** — an ADC terminates TLS for the applications behind
   it, so its cipher suites and protocol floor are the estate's actual TLS posture for
   those services, whatever the servers behind it support. Certificate expiry on a
   virtual service is an outage, not just a finding.
3. **Health-check and real-server exposure** — a real server reachable directly rather
   than only through the virtual service is a bypass of everything the ADC does.
4. **Link load balancing itself** — which WAN links, in what order, with what failure
   behaviour. Availability rather than security, and out of charter for a *security*
   assessment; worth parsing into the NCM as inventory and not checking.

The honest scope is **1 and 2 for v1, 3 noted, 4 as inventory**. Point 1 alone is most of
the value and rests entirely on parsing a configuration dump we can obtain.

### Unresolved

- Whether `cc` or `/cfg/dump` should be the `yields_config` command. `cc` is safer;
  `/cfg/dump` is the one every Radware operator knows. **Needs a capture of both from a
  real appliance** to see whether `cc` omits anything the checks need.
- The exact REST endpoint paths. Not knowable without a device or a support login. **The
  CLI path is the one to build first** for exactly this reason: every command above is
  publicly documented, and not one REST object is.
- Whether Alteon's CLI pages its output, and what disables it. Every CLI platform in this
  product needs a `session_only` paging command and Alteon's could not be confirmed.

---

## Barracuda Web Application Firewall

### How it is read — **verified**

| | |
|---|---|
| Base path | `/restapi` |
| Ports | **8000** (HTTP), **8443** (HTTPS) |
| Version segment | `v3.2` on current firmware; `v3.1` and `v1` exist on older |
| Login | `POST /restapi/v3.2/login`, body `{"username": "...", "password": "..."}` |
| Token use | HTTP **Basic**, with the token as the *username* and an empty password — `-u '<token>:'` |
| Object reads | `GET /restapi/v3.2/services/<name>` (confirmed by example) |
| Nested objects | `/restapi/{version}/vsites/{vsite_id}/service_groups/{service_group_id}` |

The token is described by Barracuda as "embedded with the username, password, and
timestamp", and "every request made by the user should include the generated token
followed by a colon". That trailing colon is not decoration — it is what makes the token
a basic-auth username with an empty password, and omitting it produces a 401 that looks
like a credential problem.

**Partial.** Barracuda's own prose says "an object may be a service, security policy,
certificate, etc." Only `services` is confirmed as a path. **The spellings for security
policies, certificates, administrative users and system settings are not established**
and must not be guessed — this is the ISE `admin/settings` divergence recorded in
`vendor-research.md` §4a, which is still open, and it cost a permanently empty NCM
section.

### The read-only shape, and why it is the Check Point case again

Reads are `GET`, which the HTTP guard handles directly. **The login is a `POST`**, and
SRS §8.1 item 3 permits POST for authentication specifically — the same exception
`checkpoint_mgmt` already uses. So the policy needs exactly two kinds of rule: one
`HttpRule("POST", "/restapi/v3.2/login", reason="authentication")` and `GET` prefixes for
everything else. No body predicate is needed, unlike Check Point, because Barracuda's
reads are genuinely GETs.

One difference from every HTTP platform already built: **the management API is on a
non-standard port**. `http_transport.py` will need the port to come from the device
record rather than being implied, and 8443 is not 443.

### What a WAF assessment is about, and what the NCM does not have

This is the family that does not fit the existing model, and it is worth being explicit
rather than forcing it.

A WAF's posture is **per-service**, and the questions are:

- Is the service in **passive/monitor mode or active/block mode**? A WAF in monitor mode
  logs attacks and stops none. This is the single most important fact about a WAF and it
  is the WAF equivalent of PAN-OS's "a profile that alerts cannot be distinguished from
  one that blocks", recorded in `vendor-research.md` — a gap that product has too.
- Which **security policy** is bound to the service, and is it the shipped default? A
  default policy is a reasonable starting point and a poor finishing one.
- Is **TLS** terminated, with what protocol floor and cipher suite, and does the
  certificate expire soon?
- Is the **back-end** connection encrypted, or does the WAF re-emit cleartext to the
  origin?
- Are **signature updates** current? A WAF with stale signatures is the same failure as
  a firewall with six-month-old threat content.

The NCM's `firewall` section models zones, address objects and ordered allow/deny rules.
**A WAF has none of those.** Forcing a service-and-policy model into a rulebase shape
would produce a `SecurityRule` list that the rulebase analyser then reasons about —
shadowing, permissiveness, any/any — and every one of those conclusions would be
nonsense. The rulebase analyser must not see WAF data.

The right answer is a **new NCM section**, `waf`, carrying services with their mode,
bound policy, TLS settings and back-end encryption. It is additive: `FR-PARSE-02`
enumerates the NCM's sections and a new one extends that list rather than changing any
existing consumer.

---

## What this costs in the codebase

**A platform name keys three registries** — `adapters/policies.py` (the read-only
contract), `adapters/profiles.py` (what is asked) and `parsers/registry.py` (how it is
read) — and `tests/test_platform_keys.py` fails when they disagree.

| Work | New platform keys | Registries | Parser | NCM | Checks | Device classes |
|---|---|---|---|---|---|---|
| Wire up the 9800's approved commands | — | profile only | extend IOS | — | — | — |
| Catalyst 9800 / EWC wireless | `cisco_c9800` | 3 | new | `wireless` exists | reuse 5, add ~5 | exists |
| Autonomous AP | `cisco_ap_ios` | 3 | new | `wireless` exists | reuse | exists |
| Lightweight AP inventory | — | — | — | — | — | exists |
| Radware Alteon | `radware_alteon` | 3 + deny-list fix | new | reuse `management`/`snmp`/… | reuse `common/`, add TLS | **new: `load_balancer`** |
| Barracuda WAF | `barracuda_waf` | 3 | new | **new: `waf`** | new family | **new: `waf`** |

`devices.device_class` and `devices.vendor` are `String(32)` columns with no check
constraint, so **new classes and vendors need no migration**. The enums in
`db/models/inventory.py` and the console's `CLASS_LABELS` are the only places they are
written down.

---

## Rejected during this research

Recorded because the reasoning is the valuable part, and each of these looks reasonable.

| Idea | Why it was rejected |
|---|---|
| Collect from lightweight APs over SSH | They hold no configuration of their own. Device contact that returns the controller's settings second-hand, or nothing. |
| A separate `cisco_ewc` platform | Same image, same syntax as the 9800. Two parsers that must stay identical is a divergence waiting to happen. |
| Model WAF services as `SecurityRule` | The rulebase analyser would then report shadowing and permissiveness on them. Every one of those conclusions would be meaningless, and they would look exactly like the real ones. |
| Build the Alteon REST adapter first | Not one endpoint path is publicly documented; the CLI's are. Building the REST path from the on-device catalogue means the allow-list cannot be reviewed before somebody has an appliance. |
| An `/cfg/<subtree>` allow-list entry for Alteon | The placeholder charset includes `/`, so one entry would admit the whole configuration tree. |
| A "management frame protection" check spanning PMF and MFP | They are different controls protecting different frames. One check would pass a controller that has one and not the other. |
| Check link-failover order on the Alteon | Availability, not security. Out of charter, and a finding about it would dilute the ones that are not. |

---

## Open questions only a real device settles

1. Does `cc` on an Alteon omit anything the management-plane checks need, compared with
   `/cfg/dump`?
2. What disables paging on an Alteon CLI session?
3. What are the Barracuda REST paths for security policies, certificates, administrators
   and system settings?
4. What does a Catalyst 9800 policy/site/RF tag binding look like in `show
   running-config`, and is there a show command that renders it more directly?
5. Does the Barracuda token expire, and on what interval? Nothing found says.

Each is written so it can be answered in one session with an appliance, and none of them
blocks the work that the first section of this page describes.
