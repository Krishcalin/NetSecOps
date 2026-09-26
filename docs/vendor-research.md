# What the vendors' own documentation says we are missing

Research conducted September 2026 against the public documentation of Cisco, Palo Alto
Networks, Fortinet and Check Point, scoped deliberately to **read-only** capability —
nothing here proposes configuration push, and several candidate commands were rejected
during the research for having side effects.

Two things to know before reading it.

**Everything here needs verifying before it is built.** Two independent passes over the
same Cisco MIB support lists reached opposite conclusions about which routing table NX-OS
implements. A follow-up pass on FortiOS found that four setting names an earlier pass had
recommended parsing do not exist in FortiOS 7.x at all — a parser built on them would have
silently never fired, which is the failure mode this codebase spends most of its effort
avoiding. Treat the sources as the authority and this page as a map to them.

**The most valuable findings were about our own code**, not about missing features. Three
of them are recorded in the "already wrong" section first, because a capability that is
broken outranks one that is absent.

---

## Already wrong, in priority order

### 1. ~~The Management API login can be read-only, and is not~~ — it already is

> **Re-verified 2026-09-26: WRONG, and it was wrong when written.**
> `adapters/http_transport.py:346` already sends `"read-only": True` in the login body,
> and `git log -S` dates that to the original HTTPS-transport commit on 2026-09-14. It
> has never been absent. This was billed as "the best ratio of effort to assurance found
> anywhere in this research"; it was work already done.

The API field is real. `read-only` is on the `login` request schema, boolean, default
false, described as "Login with Read Only permissions" — confirmed from Check Point's
own published schema at `APIs/data/v2.2/dynamic/apis.json`.

**What that field actually enforces is not documented.** The original claim that a
read-only session "cannot acquire object locks and cannot publish" could not be
confirmed in any primary source; the field description says only "Read Only
permissions". CheckMates threads support it but return 403 to direct fetch, so it rests
on search snippets. **Do not put that wording in a product claim** — say the session is
opened read-only and that our own `_checkpoint_show_only` predicate is the enforced
layer we can actually demonstrate.

Two facts that *are* primary and worth keeping: `read-only` is silently ignored when
`continue-last-session` is true, and `enter-last-published-session` logs in read-only
by definition.

### 2. Four approved Gaia commands are never issued

`show route`, `show aaa <subject>`, `show syslog all` and `cpinfo -y all` are all on the
`checkpoint_gaia` allow-list in `adapters/policies.py` and none appears in
`CHECKPOINT_GAIA_PROFILE`. They are permitted and never sent.

`show route` was the one that mattered: it is why the SNMP route walk existed, and it
made it unnecessary. **Actioned** — `show route` is now in `CHECKPOINT_GAIA_PROFILE`,
parsed by `parse_gaia_route_table`, and the walk has been removed. See the topology
section of the [README](../README.md) for the full account. The PAN-OS half is still
open, pending a real capture of the op command's XML response.

### 3. The Gaia password-policy parser matches parameters Gaia does not emit — fixed

Documented in [parser-validation.md](parser-validation.md). Three NCM fields never
populated on any Check Point device, and the fixture encoded the same invented syntax so
the tests passed.

> **Re-verified 2026-09-26.** The vendor half is confirmed against the Gaia
> Administration Guide's *Configuring Password Policy – Gaia Clish*: the real parameters
> are `history-length`, `password-expiration` (accepting the literal `never`),
> `deny-on-fail failures-allowed` and `deny-on-nonuse allowed-days`, so the three names
> the parser used genuinely do not exist. **Actioned in `2c360b0`** — the parser now
> uses the documented names and the fixture was rewritten with them.

### 4. Check Point rulebase requests are unparameterised

`CollectionCommand.as_body()` sends `{"command": "<name>"}` and nothing else — no `layer`,
`package`, `limit` or `offset`. `limit` is valid 1–500 with `offset` paging, so rulebases
come back **truncated at the server default** and the 5,000-rule target in our own README
is unreachable. `show-hits: true` is free and unused, and `SecurityRule.hit_count` already
exists to receive it.

> **Re-verified 2026-09-26 against Check Point's published schema and examples.**
> `limit` (1–500, **default 50**), `offset` (default 0), `package`, `show-hits` and the
> reply's `from`/`to`/`total` are all confirmed. `show-threat-rulebase` genuinely has no
> `show-hits`. **`layer` is wrong** — no such field exists on the rulebase queries; the
> access layer is passed as `name`.
>
> **And that is the important part, because we send neither.** Every official
> `show-access-rulebase` example sends `"name": "<layer>"`; every `show-nat-rulebase`
> example sends `"package": "<package>"`. `as_body()` sends only `command`, `limit` and
> `offset`. The schema's own `required` flags say False for everything, which
> contradicts the examples, so this is a strong inference rather than a certainty — but
> the likely position is that **the Check Point rulebase requests have never worked
> against a real management server**, and the pagination below is correct machinery
> aimed at a request that does not return a rulebase.
>
> It fails loudly rather than silently: `show-access-rulebase` is `required=True` in
> the profile, so a rejection aborts the collection with an error. That is the one
> piece of luck here.
>
> Fixing it means discovering the names first — `show-access-layers` and
> `show-packages`, which page with the same contract — then issuing one request per
> layer. **This is the next Check Point task and it outranks everything else in this
> section.** Only a real management server can settle it.

**Paging actioned** — `CollectionCommand.page_size` and `adapters/paging.py` now walk
`show-access-rulebase` and `show-nat-rulebase` to the end, merging the pages into the
response shape the parser already reads. The cursor advances by the server's own `to`
rather than by our page size, because Check Point may return fewer objects than the
`limit` asked for and adding the limit would then skip whatever did not arrive. A server
that stops advancing raises rather than reporting a short rulebase. `layer`, `package`
and `show-hits` remain unused.

Two traps if that is built: hit counting is a **global toggle**, so an estate with it
disabled must report "hit counting is off" rather than "this rule is unused"; and
`show-threat-rulebase` does not support `show-hits` at all.

### 4a. The API platforms were handed an artefact their parsers cannot read

Found while implementing §4, and larger than it. Check Point, ISE and FortiAuthenticator
have no configuration file — their configuration is every response together, and all
three parsers look responses up by endpoint. The collector assigned the body of the one
command marked `yields_config` to `config_text`, so each parser received a single
response and searched inside it for a key naming a different one.

A Check Point management server therefore collected in production parsed to **zero
security rules and zero NAT rules**, with `parse_failed` False. Not a failure — a
firewall with no policy, reported confidently.

**Actioned** — `CollectionProfile.bundled` now files every response under its endpoint.
`test_bundled_collection_shape.py` asserts the seam, which nothing did: every parser
test feeds a bundle, and the only test of `_collect_profile` used Cisco IOS over SSH.

Two ISE divergences surfaced and are **open**, because only a real deployment settles
either:

- The profile fetches `GET /api/v1/system-settings/admin-access`; the parser reads
  `admin/settings`. They are keyed to agree so the response is not discarded, but one of
  the two names is wrong about ISE's API.
- The parser reads five endpoints no profile collects — `internaluser`,
  `networkdevicegroup`, `repository`, `guestsettings` and
  `backup-restore/config/last-backup-status` — so those NCM fields are always empty in
  production, whatever the deployment contains.

### 4b. Two Cisco hardening controls were verified and deliberately not built

Both were on the implementation list and both were dropped after checking the vendor
documentation rather than after writing them. Recorded so they are not re-proposed.

**Control Plane Policing.** Cisco's IOS XE documentation describes disabling the
*default* CoPP policy with `no service-policy input policy-default-autocopp`, so on the
Catalyst platforms CoPP can be active without any `control-plane` block appearing in the
running configuration. A check asserting "CoPP is configured" would therefore report a
finding against devices that are already protected, and there is no way to tell the two
apart from configuration text. Cisco's hardening guide gives no CLI for it either.

**Unicast RPF.** Built as far as the parser and no further.
`interfaces.security.urpf_mode` now records `rx` or `any` — it was previously consumed
with the interface body and extracted into nothing, so a router with strict uRPF and one
that had never heard of it produced identical NCMs, with full parse coverage for both.

No check reads it, on purpose. Strict uRPF drops legitimate traffic on any interface
carrying an asymmetric path, so "every routed interface should have it" is wrong advice
in most real topologies. Cisco recommends it at the edge facing single-homed customers,
and NetSecOps cannot yet tell an edge interface from a core one — `Interface.zone`
exists and nothing populates it for IOS. The check becomes possible the day it does.

**Also found while doing this**, and fixed: the `snmp-server community` line was read
positionally, so `community X view V RW` parsed as read-only with an access list named
`view`. `snmp-no-write-community` passed on writable communities and
`cisco-snmp-community-acl` passed on unrestricted ones, on every device that had
configured a view.

### 5. The deny-list blocks a command we want

`adapters/readonly.py` denies `diagnose\s(?!sys|hardware)`, so `diagnose autoupdate
versions` cannot be sent today. That command is the best single source of FortiGuard
contract expiry and signature age.

> **Re-verified 2026-09-26.** Two corrections. **The ordering is backwards**: the
> allow-list is consulted *first* (`readonly.py:217-248`) and the deny-list is Layer 3
> after it, so the command is rejected today by the allow-list — the FortiGate entry
> admits only `diagnose sys top` from the whole tree. The practical conclusion survives:
> allow-listing alone is not enough, because the deny-list still fires unless the entry
> is `session_only`. And **Fortinet does not document it as "view-only"** — no Fortinet
> CLI reference classifies commands that way. It documents what it prints, "Dump
> database and engine versions" (Container FortiOS 7.2.2 CLI Reference). The command
> string is confirmed; the vendor-endorsement wording was ours, not theirs.
>
> Found alongside: the comment in `readonly.py` asserting that `diagnose sys` is
> read-only was wrong — `diagnose sys kill` terminates a process. Corrected in place;
> the allow-list, not the lookahead, is what contains that.

---

## Cisco

**`openVuln` is materially better than CPE/NVD matching, and free.** Two independent
research passes converged on this. `GET /security/advisories/v2/OSType/{type}?version=`
returns a `firstFixed` array — the actual release strings that remediate an advisory for
the release train asked about:

```json
"firstFixed": ["17.3.1w", "17.3.2a", "17.3.6", "17.3.4b", "17.3.5a"]
```

CPE ranges cannot express Cisco release-train semantics — rebuilds, lettered maintenance
releases, SMUs — and NVD carries no fixed-version data at all.

- OAuth2 client credentials, token from `id.cisco.com`, **free cisco.com account, no
  service contract**. This is the key difference from the EoX and Bug APIs, which require
  SNTC/PSS entitlement and cannot be self-registered.
- Rate limit **30 calls/minute** is the binding constraint. Dedupe by version tuple, not
  per device — a 5,000-device estate typically has under 100 distinct versions.
- `firstFixed` is returned **only** by the version endpoints. A CVE-first design silently
  loses the data that makes this worth doing.
- No `OSType` value exists for **WLC AireOS or ISE**, so two of our six Cisco platforms
  cannot use the precise endpoint.
- `csaf_20.xml` is an unauthenticated RSS feed, usable as a cheap freshness trigger.

**Hardening controls we do not check**, from Cisco's own IOS and NX-OS hardening guides.
The highest-value are AAA **command authorization and accounting** (we verify servers
exist, not that privileged commands are authorised against them or logged), **password
hash type** (type 7 is reversible and type 5 is MD5; configs are exfiltrated far more often
than devices are owned interactively), **login lockout and login logging**, **config-change
logging and archive**, and **`secure boot-image` / `secure boot-config`**. Also CoPP,
uRPF, SNMP view restriction, management-plane protection and `transport output`, and the
L2 access-layer set — DHCP snooping, dynamic ARP inspection, IP source guard, BPDU guard,
port security.

---

## Palo Alto Networks

> **Re-verified 2026-09-26.** Corrections are marked inline. Two claims were wrong and
> one was stale; the rest hold.

~~**PAN-OS is our most under-checked platform: 6 checks against Cisco's 37.**~~
**Stale and overstated.** Cisco has **43**, not 37. PAN-OS has 6 — the same as Fortinet
and Check Point, so it is tied rather than worst. The count also understates the
evaluated surface: `common/` (36), `aaa/` (8) and `wireless/` (5) carry no platform key
and run against PAN-OS snapshots too.

~~**Rule hygiene is free.** `SecurityRule.profiles`, `log_end` and `applications` are
parsed today and **read by no check**.~~
**Wrong — already implemented**, in the rulebase analyser rather than the YAML library,
which is why a search of `checks/library/` suggested otherwise. `firewall/policy.py`
emits `NO_PROFILES` (medium), `NO_LOGGING` (high, from `log_start`/`log_end` via
`logs`/`logging_known`) and `NO_APPLICATION_IDENTITY` (medium). The last of those was
added the same morning this document was written. This is the "already implemented"
failure mode recorded against the Cisco section, a second time.

**Security profile contents are never parsed**, so a profile that alerts cannot be
distinguished from one that blocks. Palo Alto's Best Practice Assessment is almost entirely
about action values, not profile presence.

**Content currency is free too.** `show system info` is already collected and
`_parse_system_info` keeps three fields from it, discarding `threat-release-date`,
`av-release-date`, `app-release-date` and the rest. A firewall on current PAN-OS with
six-month-old threat content is materially unprotected and nothing would say so.

**The PSIRT feed premise in `vuln/fetch.py` is out of date.** Confirmed, and the comment
at `fetch.py:87` is wrong twice over for Palo Alto. `security.paloaltonetworks.com/json`
returns the corpus unauthenticated with `affected` and `fixed` — no index walk — and
that host publishes **no CSAF at all** (`/.well-known/csaf/provider-metadata.json` is a
404). Per-advisory responses are **CVE Record v5.0**, not CSAF: `affected[].versions[]`
with `status`/`lessThan`/`versionType`, plus an `x_affectedList` vendor extension. The
API is marked Beta, so treat it as a feed source with a schema guard.

~~**Do not build a `set`-format parser.** The API only ever returns XML …~~
**Right conclusion, wrong reason.** The PAN-OS REST API (9.0+) supports JSON and
defaults to it, and this repo's allow-list already permits `/restapi/v10.1/…`. The
accurate statement is narrower: the **XML API** (`type=config`, `type=op`) returns XML
only, and no API emits `set` format at all — `set cli config-output-format set` is an
interactive session setting. That is the reason not to build the parser.

The Tech Support File remains the better offline path — its configuration is sanitized,
with `phash`, `secret` and `key` values replaced by placeholders. **But that sanitization
would make `panos-no-md5-admin-hash` permanently unevaluable**, because the hash it
inspects is exactly what is stripped. A check that can never fire is the silent-emptiness
trap this document keeps recording, so adopting TSF means retiring that check knowingly
rather than discovering later that it reports nothing. Also stale: the manual On-Demand
BPA dashboard was scheduled for deprecation on 30 April 2026; the Posture API replaces it.

Also absent: decryption posture (a firewall with no decryption rules inspects almost
nothing on a modern gateway), zone and DoS protection, and the two implicit
`default-security-rules` which ship with logging disabled. Absence confirmed by search —
no PAN-OS path mentions any of them, though zones themselves are parsed.

The default-rule facts check out: `intrazone-default` (allow) and `interzone-default`
(deny) are predefined, log nothing by default, and must be overridden before their
logging can change. `default-security-rules` is confirmed as the configuration node,
though from the `set` CLI form rather than a published xpath table. **The decryption
rulebase xpath could not be confirmed in Palo Alto's documentation at all, and the
zone-protection one only from community sources** — so neither should be written into a
profile without a capture from a real device. That is the same position the PAN-OS route
command is in.

---

## Fortinet

> **Re-verified 2026-09-26.** Every claim in this section holds, and no string named
> here is absent from FortiOS 7.x — the four bad names from the first pass are the ones
> already called out at the end. Sourcing caveats are noted inline. Corrections to
> claim 5 are recorded above, with that claim.

**Certificate inspection silently defeats AV and IPS.** Fortinet states it plainly: cert-only
inspection cannot see payload. A policy carrying an AV profile, an IPS sensor *and*
`ssl-ssh-profile certificate-inspection` scores perfectly against our current checks while
inspecting nothing inside HTTPS. We already hold the policy-to-profile map; this is a check
against data we have.

> **Actioned.** `RuleIssue.INSPECTION_NOT_DECRYPTED`, medium — the same severity as
> `NO_PROFILES`, because the exposure is identical and only its visibility differs. Our
> own FortiOS fixture had carried exactly this shape since it was written and scored
> clean. Only the predefined `certificate-inspection` is matched: `deep-inspection`
> decrypts, and a custom profile's body is not parsed, so judging one by name would be a
> guess that tells somebody their inspection is broken when it works.

**SSL-VPN posture is unassessed, and it gates our CVE accuracy.** Every mass-exploited
FortiGate CVE — 2018-13379, 2022-42475, 2023-27997, 2024-21762 — requires SSL-VPN enabled,
and Fortinet's advisories say so explicitly. We match on version alone and do not parse
`config vpn ssl settings`, so we over-report. Parsing it both raises confidence on genuine
exposure and removes false positives.

> **Actioned, in part.** `features.ssl_vpn` is parsed and wired to `FeatureCondition`, so
> enabled gives Confirmed, disabled gives Not Affected and unknown stays Likely. Absent
> is deliberately not disabled.
>
> **Only `status` is read.** The port, source interfaces and minimum TLS version could
> not have their exact spellings confirmed — docs.fortinet.com renders its CLI reference
> in JavaScript and serves a table of contents to any fetch — and a misspelled key here
> reads as "not configured" for ever rather than failing.
>
> **The remaining half is curation, not parsing.** An advisory carries a condition only
> if somebody puts one on it, and the feed importer does not. The mechanism is proven
> and no imported advisory uses it, so the four CVEs above are still matched on version
> alone in practice.

**UTM profile bodies are not parsed** — IPS sensors in monitor mode, profiles defined and
referenced by no policy, unmodified shipped defaults are all invisible.

**FortiManager is used for inventory only.** `conf_status` (`outofsync` = changed directly
on the firewall, out of band) and `db_status` (`mod` = staged in FortiManager, never
pushed) grade an estate of hundreds of FortiGates with **zero contact with production
devices**. Confirmed absent from the codebase: `adapters/children.py` issues
`get /dvmdb/device` and reads only name, ip, sn, platform, version and `conn_status`.
The enum values are documented in Fortinet's own Ansible collection for `/dvmdb/device`
rather than on docs.fortinet.com, so treat the exact strings as correct but
semi-officially sourced until seen on a real FortiManager.

Note that several settings recommended in a first research pass do **not exist** in FortiOS
7.x — `config system settings / set inspection-mode` (it is per-policy), the antivirus
`set options` enum, and `set fortiai` (renamed `set fortindr`). Verify against the CLI
reference for the target version before writing a parser.

---

## Check Point

**Threat Prevention is the largest gap.** Our only signal is a boolean from
`show-gateways-and-servers`. A gateway can have the IPS blade on, a threat rule in place,
and prevent nothing — the profile can sit in Detect, severity and performance filters can
exclude most protections, newly-updated protections can be parked in `staging`, and
individual protections can be overridden to Inactive. The check passes in every one of
those cases. `show-threat-profiles` exposes all of it.

**Global properties are invisible.** `show-global-properties` governs every gateway the
management server owns, including implied rules — which permit traffic that never appears
in the rulebase we analyse, and whose logging is **disabled by default**. A rulebase report
today describes a policy the gateway does not actually enforce.

**Jumbo Hotfix take is never collected**, although `vuln/versions.py` already parses a Take
number in its GAIA version scheme. Check Point advisories express fixes as a Take, not a
version — sk182336 for CVE-2024-24919 names Take 65 / 150 / 99 for R81.20 / R81.10 / R81.
Without one we cannot distinguish a patched gateway from a vulnerable one.
`show installer packages installed` reads it from clish, no expert mode.

**Gaia SSH crypto is not parsed**, so three existing `ssh-weak-*` checks are permanently
*Not evaluated* on every Check Point device.

**Check Point publishes no CSAF.** `/.well-known/csaf/provider-metadata.json` returns 404
on both checkpoint.com and support.checkpoint.com. They are a CNA, so CVE records reach
NVD — that is the realistic machine-readable route. Note the trap: their CNA-declared
advisory URL redirects to the IPS protections archive for *third-party* products, which is
the wrong dataset entirely.

**Multi-Domain has a silent-emptiness trap.** Check Point documents that an unset domain
defaults to "System Data", which holds no customer policy. Pointing NetSecOps at an MDS
without a domain yields a successful login, a successful-looking collection and an empty
rulebase. `show-domains` enumerates the real ones.

**The API reference is machine-readable.** `sc1.checkpoint.com/documents/latest/APIs/data/v2.2/dynamic/apis.json`
carries every command with full request and reply schemas — 445 `show-*` operations in
v2.2 against 245 in v1.9. The operation catalogue could be generated as data rather than
hand-maintained. Do not hard-code an API-version-to-release mapping; call
`show-api-versions` at session start and gate on what the server advertises.

---

## Read-only: what was rejected during this research

Recorded because the reasoning is the valuable part, and because each of these reads like a
safe operation.

| Operation | Why it was rejected |
|---|---|
| `get-interfaces` (Check Point) | Fetches topology from the gateway and can **update the object**. The most read-like name in the set — the specific reason the guard predicate is `show-` only and not `get-`. |
| `/dvm/cmd/reload/dev-list` (FortiManager) | Documented under "how to retrieve config", actually **overwrites** FortiManager's device database and creates a revision. |
| `diagnose autoupdate downloadtest` (FortiOS) | Appears in no Fortinet documentation. Undocumented means no safety guarantee. |
| `diagnose debug rating` (FortiOS) | Contacts FortiGuard servers and exposes a resettable counter store. |
| `compliance-scan` (Check Point) | Triggers a scan. Correctly refused already — it does not begin with `show-`. |
| `diag report-runner trigger` (FortiOS) | `trigger` is an action verb. |
| Cisco Software Checker web tool | No supported API; scraping a JS-rendered page is not an interface. Use openVuln, which is the same backend. |

Our existing guards already refuse every one of these. That is worth recording as
**validated rather than assumed** — it was checked against the enumerated operation lists,
not inferred.
