"""The notification event vocabulary (FR-INT-01).

One taxonomy, shared by every outbound channel. Notifications and SIEM forwarding ask the
same question — *what happened, how bad is it, and what was it about* — and giving them
separate vocabularies means an event that reaches a SIEM and an event that reaches an
operator's inbox describe the same occurrence differently, which is precisely the
confusion an incident does not need.

**The events are a closed set, and deliberately short.** FR-INT-01 names eight triggers.
Every one of them is something an operator would want to be woken for or would want in
their morning digest; "a collection succeeded" is not, and adding it would train people
to filter the channel, which is the same as turning it off.

**Severity is the sender's, not the receiver's.** A subscription decides what to do with
a `high`; it does not get to relabel it. Otherwise two channels report the same event at
two severities and neither is wrong.
"""

from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any

from netsecops.core.redaction import redact_line


class EventKind(StrEnum):
    """The eight triggers FR-INT-01 names, plus one for wholesale audit forwarding.

    The distinction matters. FR-INT-01 *notifies a person*, so its set is closed and
    short: every member is something worth interrupting someone for. FR-INT-02 *feeds a
    SIEM*, which wants the entire audit trail — a login failure is not a notification but
    it is certainly an event a SOC correlates on. Those go out as `AUDIT`, carrying the
    real action in `signature` so a SIEM rule still keys on `login.failure` rather than
    on a lowest-common-denominator label.
    """

    JOB_COMPLETED = "job.completed"
    JOB_FAILED = "job.failed"
    #: A new Critical or High finding. Not every finding — see the module docstring.
    FINDING_OPENED = "finding.opened"
    #: A CVE match against the CISA KEV catalogue. Separate from `finding.opened`
    #: because "this is being exploited right now" is a different page at 3am from
    #: "this is severe".
    KEV_MATCHED = "vuln.kev_matched"
    DRIFT_DETECTED = "drift.detected"
    #: An SSH host key or TLS certificate that changed since it was pinned. Could be a
    #: legitimate rebuild; could be interception. Either way a person decides.
    DEVICE_IDENTITY_CHANGED = "device.identity_changed"
    CREDENTIAL_FAILED = "credential.failed"
    FEED_SYNC_FAILED = "feed.sync_failed"
    EXCEPTION_EXPIRING = "exception.expiring"
    #: An audit-log record forwarded to a SIEM (FR-INT-02). Never a notification.
    AUDIT = "audit"


class EventSeverity(StrEnum):
    """Severity as the *sender* sees it.

    Maps onto both the CEF 0–10 scale and syslog's 0–7, neither of which matches the
    other and neither of which matches the check engine's five levels. Keeping our own
    and converting at each boundary is what stops a `critical` finding arriving at a SIEM
    as an `informational` syslog line.
    """

    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


#: EventSeverity to CEF's 0–10 scale.
CEF_SEVERITY: dict[EventSeverity, int] = {
    EventSeverity.CRITICAL: 10,
    EventSeverity.HIGH: 8,
    EventSeverity.MEDIUM: 5,
    EventSeverity.LOW: 3,
    EventSeverity.INFO: 1,
}

#: EventSeverity to RFC 5424's numeric severity, where *lower is worse*.
#:
#: The inversion is the trap. A table written by analogy with CEF sends critical events
#: as `debug`, and they are dropped by the first relay that filters on severity — so the
#: integration looks healthy and the events nobody sees are exactly the urgent ones.
SYSLOG_SEVERITY: dict[EventSeverity, int] = {
    EventSeverity.CRITICAL: 2,  # critical
    EventSeverity.HIGH: 3,  # error
    EventSeverity.MEDIUM: 4,  # warning
    EventSeverity.LOW: 5,  # notice
    EventSeverity.INFO: 6,  # informational
}

#: How the check engine's severities map onto ours. `severity` on a finding is free text
#: in the database, so anything unrecognised becomes MEDIUM rather than vanishing.
FROM_FINDING: dict[str, EventSeverity] = {
    "critical": EventSeverity.CRITICAL,
    "high": EventSeverity.HIGH,
    "medium": EventSeverity.MEDIUM,
    "low": EventSeverity.LOW,
    "info": EventSeverity.INFO,
    "informational": EventSeverity.INFO,
}


def severity_of(raw: str | None) -> EventSeverity:
    return FROM_FINDING.get((raw or "").strip().lower(), EventSeverity.MEDIUM)


@dataclass(frozen=True, slots=True)
class Event:
    """One thing that happened, in the form every channel renders from."""

    kind: EventKind
    severity: EventSeverity
    #: A short line. Becomes the CEF `name`, the e-mail subject and the Slack heading, so
    #: it has to stand alone without the body.
    title: str
    #: The detail. May be multi-line; channels that cannot show that truncate it.
    message: str = ""
    occurred_at: datetime = field(default_factory=lambda: datetime.now(UTC))

    device_id: uuid.UUID | None = None
    device_hostname: str | None = None
    device_ip: str | None = None
    #: The finding, job, snapshot or feed this is about, for deep links.
    object_type: str | None = None
    object_id: str | None = None

    #: Anything channel-specific. Rendered into CEF extensions and JSON alike, so keys
    #: should be short and stable.
    attributes: dict[str, str] = field(default_factory=dict)

    #: What a SIEM rule keys on, when it should be finer than the kind. Set for forwarded
    #: audit records, where `audit` alone would collapse every action in the trail into
    #: one signature and make correlation impossible.
    signature: str | None = None

    @property
    def signature_id(self) -> str:
        return self.signature or self.kind.value

    def scrubbed(self) -> Event:
        """A copy with secrets removed from every free-text field.

        Findings quote configuration, and configuration carries community strings,
        pre-shared keys and password hashes. Without this a SIEM integration becomes the
        one place every secret in the estate is transmitted in clear — and it would look
        like it was working.

        Applied at construction of the *outbound* payload rather than trusted to the
        caller: a channel added later would otherwise have to remember, and the one that
        forgets is the one nobody notices.
        """
        return Event(
            kind=self.kind,
            severity=self.severity,
            title=redact_line(self.title)[0],
            message="\n".join(redact_line(line)[0] for line in self.message.splitlines()),
            occurred_at=self.occurred_at,
            device_id=self.device_id,
            device_hostname=self.device_hostname,
            device_ip=self.device_ip,
            object_type=self.object_type,
            object_id=self.object_id,
            attributes={k: redact_line(v)[0] for k, v in self.attributes.items()},
            signature=self.signature,
        )

    def as_dict(self) -> dict[str, Any]:
        """The JSON shape (FR-INT-02's second format, and the webhook body)."""
        return {
            "event": self.kind.value,
            "signature": self.signature_id,
            "severity": self.severity.value,
            "title": self.title,
            "message": self.message,
            "occurred_at": self.occurred_at.astimezone(UTC).isoformat(),
            "device": {
                "id": str(self.device_id) if self.device_id else None,
                "hostname": self.device_hostname,
                "ip": self.device_ip,
            },
            "object": {"type": self.object_type, "id": self.object_id},
            "attributes": dict(self.attributes),
            "product": "NetSecOps",
        }


__all__ = [
    "CEF_SEVERITY",
    "FROM_FINDING",
    "SYSLOG_SEVERITY",
    "Event",
    "EventKind",
    "EventSeverity",
    "severity_of",
]
