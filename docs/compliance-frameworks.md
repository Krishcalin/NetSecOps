# HIPAA, NERC CIP and NIST 800-41 mappings — and the three frameworks we did not add

AlgoSec Firewall Analyzer advertises six regulatory frameworks NetSecOps did not:
HIPAA, NERC CIP, FISMA, SOX, NIST 800-41 and IAVA (see docs/algosec-parity.md, gap 4).
This page records which three were added, how each is cited, and why the other three
were considered and deliberately left out. It is the companion to
docs/compliance-india.md, which did the same for CERT-In and CEA.

The rule both pages serve is the one `tests/test_framework_coverage.py` enforces: a
framework is advertised as a compliance pivot **only** where real checks map to it, and
it is cited in the vocabulary its published source actually uses — never an invented
number that looks verifiable and is not.

## The three that were added

### HIPAA Security Rule — cited by § number
The Security Rule's Technical Safeguards (45 CFR §164.312) are numbered and citable, and
several are exactly what a device configuration evidences. Only these are used:

| Citation | Safeguard | Maps to checks about |
|---|---|---|
| `164.312(a)(1)` | Access Control | authorization, management ACLs, least-privilege admin |
| `164.312(a)(2)(iii)` | Automatic Logoff | session / exec / SSH timeouts, lockout |
| `164.312(b)` | Audit Controls | logging, syslog, command accounting |
| `164.312(d)` | Person or Entity Authentication | AAA authentication, passwords, MFA, SNMP auth |
| `164.312(e)(1)` | Transmission Security | SSH, TLS, SNMPv3 privacy, telnet disabled, strong crypto |

The Administrative and Physical Safeguards (§164.308, §164.310) are policy and premises
obligations a running-config cannot evidence, so they are not mapped — mapping them
would inflate a compliance percentage with controls that cannot fail for the right
reason. `TestTheThreeNewFrameworksAreCitedFromASource` pins the five § numbers above.

### NERC CIP — cited by standard and requirement
CIP requirement identifiers (`CIP-007-6 R5`) are real and citable. The ones a
configuration can evidence:

| Citation | Requirement | Maps to checks about |
|---|---|---|
| `CIP-005-7 R1` | Electronic Security Perimeter | boundary ACLs, permitted-IP, management-plane access control |
| `CIP-007-6 R1` | Ports and Services | disabling unnecessary services (small-servers, CDP, finger, BOOTP, Smart Install, HTTP server) |
| `CIP-007-6 R4` | Security Event Monitoring | logging, syslog, accounting, time synchronisation |
| `CIP-007-6 R5` | System Access Control | AAA, passwords, SSH, SNMPv3, banners, lockout |

CIP-007 R2 (patch management), R3 (malware prevention) and the CIP-002/003/004 people-
and-process standards are out of scope for the same reason the HIPAA administrative
safeguards are: no running-config evidences them.

### NIST SP 800-41r1 — cited by subject, never a number
"Guidelines on Firewalls and Firewall Policy" is prose, not a numbered control
catalogue — so, exactly as with CERT-In and CEA, a check cites the **subject** it
speaks to, not an invented clause number:

```yaml
references:
  nist_800_41: ["Firewall Management"]
```

The three subjects are `Firewall Management`, `Firewall Logging` and `Firewall Policy`.
800-41 is deliberately the narrowest of the three new frameworks: it addresses the
security-device management plane, its logging, and its access-control policy — so it is
mapped to those checks and **not** to the switching-layer (STP, DHCP snooping, ARP,
VLANs), wireless, or certificate-lifetime checks, which are outside what the document
covers. A framework that mapped to everything would be claiming a coverage its source
does not.

## The three that were deliberately not added

Advertising a framework the product cannot honestly evidence is the precise defect
`test_framework_coverage.py` exists to prevent. Each of these fails that bar:

- **FISMA.** FISMA mandates a security programme; it defines **no controls of its own**
  and is implemented through NIST 800-53, which NetSecOps already maps (110 of 111
  checks). A separate `fisma` pivot would either duplicate the 800-53 view exactly or
  invent a distinction that the law does not make. A reader wanting the FISMA view reads
  the NIST 800-53 view; that is not a gap, it is how FISMA works.

- **SOX.** The Sarbanes-Oxley Act has no technical control catalogue. Its IT relevance is
  through general controls — change management, segregation of duties, access review —
  assessed at the process level (COBIT / ITGC), not from a device configuration. There
  is no citation a check could carry that a SOX auditor would recognise, so a `sox` pivot
  would be a column of fabricated references.

- **IAVA.** DoD Information Assurance Vulnerability Alerts are keyed to specific
  advisories and CVEs, not to configuration controls. That is the vulnerability engine's
  domain (FR-VUL), where advisories are already matched by CVE — not the configuration-
  compliance pivot. Mapping IAVA here would file vulnerability findings under a
  compliance heading where they cannot be assessed as pass/fail against a config.

If a customer ever requires one of these three literally, the honest way to provide it
is a labelled *view over an existing mapping* (a "FISMA report" rendered from the 800-53
results), not a new framework field pretending to independent coverage. That option
stands; it was not taken here.
