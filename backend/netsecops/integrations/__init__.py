"""Outbound integrations: notifications and SIEM forwarding (FR-INT-01, FR-INT-02).

Everything here sends data *out of* NetSecOps to somewhere else. That is the opposite
direction from the rest of the product, and it brings a risk the read-only guarantee does
not cover: what leaves, and whether it should have.

Two rules hold across the package.

**Nothing leaves unscrubbed.** Findings quote device configuration, and configuration
contains community strings, pre-shared keys and password hashes. The redaction that
protects the database and the logs has to protect the wire too, or a SIEM integration
becomes the one place every secret in the estate is sent in clear text.

**A destination that cannot be reached is recorded, not retried forever.** A SIEM outage
must not become a NetSecOps outage, and a queue that grows without bound is an outage
with extra steps.
"""

from __future__ import annotations
