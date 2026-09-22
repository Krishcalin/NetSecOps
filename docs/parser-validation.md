# Validating the parsers against configurations we did not write

Every parser, check and allow-list in this product is tested against fixtures in
[`backend/tests/fixtures`](../backend/tests/fixtures) — which we authored. They run from
1.5 to 14 KB. A real core switch or perimeter firewall runs from 100 KB to a couple of
megabytes. So the fixtures prove the parsers handle the syntax we thought of, and say
nothing about the syntax we did not.

[`scripts/parse_coverage.py`](../scripts/parse_coverage.py) closes as much of that loop as
can be closed without hardware.

```bash
python scripts/parse_coverage.py ~/corpus
python scripts/parse_coverage.py ~/corpus --platform cisco_ios --verbose
python scripts/parse_coverage.py ~/corpus --json report.json
```

It needs the backend virtualenv and touches no database and no device. Platform is taken
from a parent directory named after one (`corpus/cisco_ios/...`), then from content
signatures, then not at all — a file it cannot place is listed rather than guessed at.

## What it reports, in increasing order of usefulness

**Coverage** — the share of meaningful lines the parser consumed, the same figure the
snapshot service stores and the device page shows. A useful tripwire and a poor goal: a
parser can consume a line and extract nothing from it.

**Unparsed shapes** — each unrecognised line reduced to its grammar by replacing
addresses, numbers and quoted strings with placeholders, then counted. One row per
missing construct rather than ten thousand rows of noise, ranked by how often real
configurations contain it. This is the work queue.

**Field fill rates** — for each NCM field some check depends on, the share of
configurations in which it came out populated. This is the one that matters, and the one
coverage cannot substitute for. A check whose input is absent reports *Not evaluated*,
which is honest and also invisible: an estate where `management.services.ssh.ciphers`
never parses produces no findings about SSH ciphers and looks exactly like an estate with
good ciphers.

`EXPECTED_FIELDS` is checked against the live NCM at startup. The first draft was written
from memory and five of nineteen entries named fields that do not exist — `system.hostname`
for `device.hostname`, `crypto.ssh_ciphers` for `management.services.ssh.ciphers` — each of
which would have been reported as a parser that never populates it. A tool that
manufactures defects is worse than no tool, so that check is not optional.

## Getting a corpus

The corpus is **not** committed. It is an input to a measurement, not part of the
product, and vendoring someone else's test data would add a licence obligation for no
benefit.

[Batfish](https://github.com/batfish/batfish) (Apache-2.0) carries vendor grammar test
configurations that map onto five of our platforms:

| Batfish path | Our platform | Files |
|---|---|---:|
| `…/grammar/cisco/` | `cisco_ios` | ~220 |
| `…/grammar/cisco_asa/` | `cisco_asa` | ~64 |
| `…/grammar/fortios/` | `fortios` | ~56 |
| `…/grammar/palo_alto/` | `panos` | ~170 |
| `…/vendor/cisco_nxos/grammar/` | `cisco_nxos` | ~148 |

Be accurate about what this is. These are a competitor's grammar tests, not production
configurations: each is small and exercises a specific construct. That makes them good at
finding *breadth* gaps — constructs we do not recognise — and useless for *scale*
behaviour, which still needs real devices ([TEST-08](../README.md#where-the-project-stands)).

## What the first run found

Run 2026-09-22 against 311 Batfish configurations.

| Platform | Files | Unreadable | Median coverage |
|---|---:|---:|---:|
| `cisco_asa` | 29 | 0 | 100.0% |
| `fortios` | 51 | 0 | 100.0% |
| `cisco_ios` | 106 | 0 | 81.8% → 85.7% |
| `cisco_nxos` | 21 | 0 | 81.2% |
| `panos` | 104 | 104 | 0.0% |

**A wholesale parse failure scored 100%.** Four parsers — PAN-OS, Cisco ISE, Check Point
management, FortiAuthenticator — take an artefact meant to be XML or JSON and can fail to
read it entirely. They handle that well: one explanatory line in `raw_unparsed`, an NCM
carrying only vendor and platform, so every check reports *Not evaluated* rather than the
device being called clean. The defect was one layer up. Coverage is meaningful lines
minus unparsed lines, and a wholesale failure records *one* unparsed line however long the
input was — so a 200-line configuration that parsed into nothing scored **100%** and
rendered as a green "100% parsed" pill beside an empty NCM. `NormalisedConfig.parse_failed`
now carries the distinction and coverage is 0 in that case. Pinned by
`tests/test_parse_failure_coverage.py`.

Note the shape of that bug: the *first* run of this tool reported PAN-OS at 93.8% median
coverage with 22 of 22 expected fields populated in none of 104 files. Coverage said fine;
the field-fill lens said nothing was extracted. That disagreement is the reason the third
report exists.

**PAN-OS `set` format is not supported, and that is a limitation rather than a defect.**
The Batfish corpus is in `set` syntax; our parser reads the XML that the PAN-OS API
returns, which is what the collection profile fetches. It matters only on the upload path
(FR-COL-11), where a `set`-format file now yields a 0% snapshot naming the reason.

**`line aux` and numbered TTY lines were not parsed on IOS.** The parser read `line vty`
and `line con`. In the corpus, `line aux 0` and lines like `line 0/0/0 0/0/12` carry
`exec-timeout 0 0` — never time out — and none of it reached the NCM. An unsecured AUX
port is a CIS benchmark item, so no check could be written for one.

**Closed.** `management.session.async_lines` now carries them, and
`cisco-aux-port-disabled` asserts every AUX line has `no exec`. IOS median coverage went
from 81.8% to 85.7%, and the file that exposed it — the worst-covered in the corpus, at
0% — now parses completely.

Two distinctions that decide whether the check tells the truth, both pinned by
`tests/test_ios_async_lines.py`:

- **`no exec` is not an `exec-timeout`.** A timeout bounds a session that was allowed to
  start; only `no exec` stops one starting. The corpus has numbered lines carrying both,
  and treating the timeout as the control would pass a line that still opens a shell.
- **A device with no AUX line reports Not Applicable, never a pass.** This is what the
  check would have got wrong. `requires` tests for *null*, and an empty list satisfies it
  — so the expression would have yielded nothing, asserted clean, and reported "the
  auxiliary port has EXEC disabled" about a switch that never mentioned one.
  `applicability.requires_features` treats an empty list as missing, which is the
  behaviour wanted. Mutating the check back to `requires` fails that test with
  `assert 'pass' == 'not_applicable'`.

**The rest of the IOS and NX-OS misses are not security-relevant**: `ip sla` and its
`icmp-echo`/`local-address` children, and the MPLS/VRF stanzas `rd`, `route-target import`
and `address-family ipv4`. Worth recording, not worth prioritising — except that VRF
awareness does bear on topology, since `Route.vrf` exists and nothing fills it from these.

## Re-running it

Treat a fall in median coverage, or a field that stops being populated, the way you would
treat a drop in test coverage. The field-fill table is the part to watch: it is the only
one that distinguishes a check that passed from a check that never ran.
