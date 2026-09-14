"""Reading certificate expiry dates out of the NCM (FR-AAA-06).

Every vendor writes the same instant differently, and NCM stores what the device said
rather than a normalised form — the provenance of a field is worth more than its
tidiness, and a parser that reformats a date is a parser that can silently reformat it
wrong. So interpretation happens here, once, where the formats can be listed and tested
together instead of being re-guessed by each consumer.

**A certificate whose date cannot be read is not a certificate that is fine.** This is
the whole reason the module exists. An expiry timeline built by dropping the dates it
could not parse shows an empty "expiring soon" column for an estate whose EAP
certificate expires on Friday, and it shows it confidently. Anything unreadable is
carried through to the caller as ``undated`` and counted, so the dashboard says "9
certificates, 2 of which I could not date" rather than "7 certificates".

The formats below are the ones our own parsers emit. Nothing here tries to be a general
date library: an unrecognised format must fail loudly into ``undated``, not be coerced
by a lenient parser into a plausible wrong answer.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime

from netsecops.ncm.models import Certificate

#: The non-ISO shapes, tried after ``datetime.fromisoformat`` has had a go.
#:
#: * ``Mar 12 09:14:22 2027 GMT`` — PAN-OS, which prints OpenSSL's ``ASN1_TIME``.
#: * ``Fri Mar 12 09:14:22 UTC 2027`` — Cisco ISE, which prints Java's ``Date.toString``.
_FORMATS: tuple[str, ...] = (
    "%b %d %H:%M:%S %Y %Z",
    "%a %b %d %H:%M:%S %Z %Y",
)


def parse_expiry(value: str | None) -> datetime | None:
    """One certificate date, or None when it cannot be read.

    None is a real answer here and the caller is expected to carry it, not discard the
    certificate that produced it.
    """
    if not value:
        return None

    token = value.strip()
    if not token:
        return None

    # An epoch, in seconds or milliseconds. FortiAuthenticator returns these for
    # certificate validity on some firmware.
    if token.isdigit():
        number = int(token)
        if number > 10_000_000_000:  # milliseconds
            number //= 1000
        try:
            return datetime.fromtimestamp(number, tz=UTC)
        except (OverflowError, OSError, ValueError):
            return None

    # ISO-8601 first, and through `fromisoformat` rather than a format string. The
    # variations inside ISO-8601 alone — fractional seconds or not, `Z` or `+00:00` or
    # `+0000`, date-only — would need six patterns below, and the first one anybody
    # forgot would be a certificate silently reported as undated.
    try:
        parsed = datetime.fromisoformat(token)
    except ValueError:
        pass
    else:
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)

    normalised = token.replace("Z", "+0000") if token.endswith("Z") else token

    for pattern in _FORMATS:
        try:
            parsed = datetime.strptime(normalised, pattern)
        except ValueError:
            continue
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)

    return None


@dataclass(frozen=True, slots=True)
class CertificateEntry:
    """One certificate on one device, placed on the timeline."""

    device_id: str
    device: str
    name: str | None
    subject: str | None
    issuer: str | None
    self_signed: bool | None
    usage: list[str]
    #: ISO-8601, normalised. None when the source date could not be interpreted.
    expires_at: str | None
    #: Negative when it has already expired. None alongside a None ``expires_at``.
    days_remaining: int | None

    @property
    def dated(self) -> bool:
        return self.days_remaining is not None

    @property
    def expired(self) -> bool:
        return self.days_remaining is not None and self.days_remaining < 0


def describe(
    certificate: Certificate,
    *,
    device_id: str,
    device: str,
    now: datetime | None = None,
) -> CertificateEntry:
    """Place one NCM certificate on the timeline, dated or not."""
    moment = now or datetime.now(UTC)
    expiry = parse_expiry(certificate.not_after)

    return CertificateEntry(
        device_id=device_id,
        device=device,
        name=certificate.name,
        subject=certificate.subject,
        issuer=certificate.issuer,
        self_signed=certificate.self_signed,
        usage=list(certificate.usage),
        expires_at=expiry.isoformat() if expiry else None,
        days_remaining=(expiry - moment).days if expiry else None,
    )


__all__ = ["CertificateEntry", "describe", "parse_expiry"]
