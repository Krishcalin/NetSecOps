# ADR-002 — Check Point Gaia expert-mode read access

- **Status:** Accepted
- **Date:** 2026-09-13
- **Requirement:** SRS §8.2, FR-COL-01, FR-COL-05, Appendix D item 2
- **Decided by:** the customer, resolving the open question ahead of Phase 4

## Context

Check Point Gaia presents two shells. **clish** is the restricted management shell; it
answers `show` commands and is what a read-only administrative account normally gets.
**Expert mode** is a root Bash shell on the underlying Linux system, reached with the
`expert` command and a separate password.

Several things Phase 4 needs to assess are not visible from clish:

- the rulebase as the gateway actually holds it (`fw tab`, `$FWDIR/conf/`),
- SIC certificate state and expiry,
- `fw ctl` kernel parameters that affect inspection,
- the local policy files that reveal whether a gateway's installed policy matches what
  the management server believes it installed.

SRS §8.2 defines a separate `checkpoint_gaia_expert` allow-list precisely because the
reachable command set differs, and marks it default-off. Appendix D asked whether this
deployment permits it at all.

## Decision

**Expert-mode read access is permitted**, and remains **per-device opt-in**.

Being permitted for this deployment does not make it the default. The `allow_expert`
flag on each device stays `false` until an operator sets it, and
`Device.policy_platform` only then resolves to the `checkpoint_gaia_expert` policy:

```python
if self.platform == "checkpoint_gaia" and self.allow_expert:
    return "checkpoint_gaia_expert"
```

That per-device gate is the substance of this decision, not an implementation detail.
Expert mode is a root shell. A blanket enable would mean that any future defect in an
adapter, or any command mistakenly added to the allow-list, executes as root on a
security gateway. Requiring someone to turn it on for a named device keeps the blast
radius bounded to devices a human has considered.

## Consequences

- The `checkpoint_gaia_expert` allow-list in `adapters/policies.py` becomes reachable.
  Every command in it is still subject to the same four-layer guard as any other
  platform, and the conformance tests apply unchanged: SRS §8 is not relaxed by this
  decision, only the set of commands a reviewer has approved is larger.
- The allow-list must stay **read-only and narrow**. A root shell makes it trivially
  easy to add something convenient and destructive; `test_readonly.py` and
  `test_profiles.py` are what stop that, and they apply here with more force, not less.
- Expert mode needs its own credential. The device account guidance in
  `docs/device-accounts.md` must cover it before Phase 4 ships, including the point that
  the expert password is a second secret and belongs in the vault as such.
- Devices **without** `allow_expert` will report *Not Evaluated* for the checks that
  depend on expert-only data. That is the correct outcome and must not be softened into
  a pass — the whole "absent is not false" discipline applies.

## Alternatives considered

**Refuse expert mode entirely.** Simpler and safer, and was the default. Rejected
because it would leave a class of Check Point findings permanently unevaluable, and the
customer has judged the trade acceptable for their estate. The per-device gate preserves
this option for anyone who disagrees: leaving `allow_expert` false everywhere is
identical to refusing it.

**Enable it globally for Check Point devices.** Rejected. It removes the human decision
that bounds the risk, and gains only the convenience of not setting a flag.
