"""Scheduled report generation and e-mail delivery (FR-RPT-04).

Report *generation* has worked since Phase 7's reporting slice. What was missing is the
other half of the requirement: producing one on a schedule and sending it to somebody.

**A report is attached, not linked.** The people a compliance report is scheduled for are
frequently the ones without a console login — an auditor, a customer's security officer,
somebody's manager. A link they cannot open is not a delivery.

**A password-protected archive is encrypted or it is refused.** `zipfile` in the standard
library can *read* an encrypted archive and cannot write one, so the obvious
implementation produces a perfectly ordinary ZIP and reports success. The operator then
believes a file containing every finding in the estate is protected while it crosses two
mail systems in the clear. That failure is silent, total, and discovered by the wrong
person, so this uses AES-256 via `pyzipper` and refuses outright if it is unavailable.

**Retention is applied here rather than by a cron script.** A report is dated evidence; if
it is going to be deleted, the deletion belongs somewhere audited and testable rather than
in a `find -mtime` somebody wrote once.
"""

from __future__ import annotations

import io
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Final

from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from netsecops.core.errors import ValidationProblem
from netsecops.core.logging import get_logger
from netsecops.db.models.notifications import ChannelType, NotificationChannel
from netsecops.db.models.reporting import Report, ReportFormat, ReportStatus
from netsecops.integrations.channels import ChannelError, EmailChannel
from netsecops.services.report_render import content_type_for, filename_for, render

log = get_logger(__name__)

#: Largest attachment we will put on a message.
#:
#: Most mail systems reject somewhere between 10 and 25 MB, and a bounce arrives — if at
#: all — at a postmaster address nobody reads. Refusing here produces an error against the
#: report, which somebody does read.
MAX_ATTACHMENT_BYTES: Final[int] = 15 * 1024 * 1024

#: How long a generated report is kept when no retention is configured.
DEFAULT_RETENTION: Final[timedelta] = timedelta(days=365)


@dataclass(slots=True)
class DeliveryOutcome:
    report_id: str
    delivered_to: int = 0
    error: str | None = None


def package(report: Report, fmt: ReportFormat, *, password: str | None = None) -> tuple[str, bytes]:
    """Render a report, optionally into an encrypted archive.

    Returns ``(filename, bytes)``. With a password the result is an AES-256 ZIP; without
    one it is the rendered document itself, unwrapped — zipping an unprotected file buys
    nothing and costs the recipient a step.
    """
    body = render(report, fmt)
    name = filename_for(report, fmt)

    if password is None:
        return name, body

    # Both failures below are refusals, never downgrades. Falling back to a plain ZIP
    # would satisfy the call, look like a success, and put every finding in the estate
    # through two mail systems in the clear while the operator believed otherwise.
    try:
        import pyzipper
    except ImportError as exc:  # pragma: no cover - the dependency is declared
        raise ValidationProblem(
            "Password-protected delivery needs the `pyzipper` package, which is not "
            "installed. Refusing rather than sending an unencrypted archive."
        ) from exc

    try:
        buffer = io.BytesIO()
        with pyzipper.AESZipFile(
            buffer, "w", compression=pyzipper.ZIP_DEFLATED, encryption=pyzipper.WZ_AES
        ) as archive:
            archive.setpassword(password.encode())
            archive.writestr(name, body)
    except OSError as exc:
        # `pyzipper` imports cleanly and then fails at *use* when its pycryptodomex
        # backend cannot load its compiled extension — which is not hypothetical:
        # endpoint-protection software strips freshly written `.pyd`/`.so` files, and pip
        # reports a successful install either way. Caught separately from ImportError so
        # the operator is told encryption is broken rather than receiving a stack trace,
        # and so this can never fall through to writing a plaintext archive.
        raise ValidationProblem(
            "The AES backend for password-protected delivery could not be loaded "
            f"({exc}). Refusing rather than sending an unencrypted archive — check that "
            "pycryptodomex's compiled module survived installation."
        ) from exc

    return f"{name}.zip", buffer.getvalue()


class ReportDeliveryService:
    """Send finished reports, and retire old ones."""

    def __init__(self, session: AsyncSession, *, org_id: int = 1) -> None:
        self.session = session
        self.org_id = org_id

    async def deliver(
        self,
        report: Report,
        *,
        channel_name: str,
        fmt: ReportFormat = ReportFormat.PDF,
        password: str | None = None,
        sender: EmailChannel | None = None,
    ) -> DeliveryOutcome:
        """E-mail one report as an attachment."""
        outcome = DeliveryOutcome(report_id=str(report.id))

        if report.status != ReportStatus.READY.value:
            outcome.error = (
                f"Report {report.id} is {report.status}, not ready, so there is nothing to send."
            )
            return outcome

        channel = (
            await self.session.execute(
                select(NotificationChannel).where(
                    NotificationChannel.org_id == self.org_id,
                    NotificationChannel.name == channel_name,
                )
            )
        ).scalar_one_or_none()
        if channel is None and sender is None:
            outcome.error = f"No notification channel called {channel_name!r}."
            return outcome
        if channel is not None and channel.channel_type != ChannelType.EMAIL.value:
            outcome.error = (
                f"Channel {channel_name!r} is a {channel.channel_type} channel. A report is "
                "an attachment, so delivery needs an e-mail channel."
            )
            return outcome

        try:
            filename, payload = package(report, fmt, password=password)
        except ValidationProblem as exc:
            outcome.error = str(exc)
            return outcome

        if len(payload) > MAX_ATTACHMENT_BYTES:
            outcome.error = (
                f"{filename} is {len(payload) // 1024}KB, over the "
                f"{MAX_ATTACHMENT_BYTES // 1024}KB attachment limit. Most mail systems would "
                "reject it and the bounce would go to a postmaster address."
            )
            return outcome

        transport = sender or _email_channel(channel)
        try:
            await _send_with_attachment(
                transport,
                subject=f"NetSecOps report: {report.title}",
                body=_covering_note(report, password is not None),
                filename=filename,
                payload=payload,
                content_type=content_type_for(fmt),
            )
        except (ChannelError, OSError) as exc:
            outcome.error = f"{type(exc).__name__}: {exc}"
            log.warning("reports.delivery_failed", report_id=str(report.id), error=outcome.error)
            return outcome

        outcome.delivered_to = len(transport.recipients)
        log.info(
            "reports.delivered",
            report_id=str(report.id),
            recipients=outcome.delivered_to,
            encrypted=password is not None,
        )
        return outcome

    async def retire_expired(self, *, now: datetime | None = None) -> int:
        """Delete reports past their retention date (FR-RPT-04).

        Only reports that carry an explicit `expires_at`. A report with none is kept: the
        default for dated evidence is to keep it, and a retention sweep that invented a
        deadline would quietly destroy the thing somebody needs at audit.
        """
        moment = now or datetime.now(UTC)
        rows = list(
            (
                await self.session.execute(
                    select(Report).where(
                        Report.org_id == self.org_id,
                        Report.expires_at.is_not(None),
                        Report.expires_at <= moment,
                    )
                )
            ).scalars()
        )
        for row in rows:
            await self.session.delete(row)
        if rows:
            await self.session.flush()
            log.info("reports.retired", count=len(rows))
        return len(rows)


def _covering_note(report: Report, encrypted: bool) -> str:
    lines = [
        f"{report.title}",
        "",
        f"Generated: {report.generated_at.isoformat() if report.generated_at else 'unknown'}",
        f"Template:  {report.template}",
    ]
    if report.content_hash:
        # The hash is what makes the attachment checkable against the console copy, which
        # matters for a document that will be quoted back months later.
        lines.append(f"Content hash (SHA-256): {report.content_hash}")
    if encrypted:
        lines += ["", "The attachment is AES-encrypted. The password was agreed separately."]
    lines += ["", "NetSecOps performs read-only assessment. It never modifies a target device."]
    return "\n".join(lines)


def _email_channel(channel: NotificationChannel | None) -> EmailChannel:
    config = (channel.config if channel else None) or {}
    return EmailChannel(
        host=str(config.get("host") or ""),
        port=int(config.get("port") or 587),
        username=config.get("username"),
        use_starttls=bool(config.get("starttls", True)),
        use_ssl=bool(config.get("ssl", False)),
        sender=str(config.get("from") or "netsecops@localhost"),
        recipients=tuple(config.get("recipients") or ()),
    )


async def _send_with_attachment(
    channel: EmailChannel,
    *,
    subject: str,
    body: str,
    filename: str,
    payload: bytes,
    content_type: str,
) -> None:
    """Build and send a message carrying one attachment.

    Separate from `EmailChannel.send`, which sends a notification and has no attachment
    concept. Bolting one onto it would put report-shaped arguments on every notification.
    """
    import asyncio
    from email.message import EmailMessage

    if not channel.recipients:
        raise ChannelError("This e-mail channel has no recipients configured.")

    message = EmailMessage()
    message["Subject"] = subject
    message["From"] = channel.sender
    message["To"] = ", ".join(channel.recipients)
    message.set_content(body)

    maintype, _, subtype = content_type.partition("/")
    message.add_attachment(
        payload,
        maintype=maintype or "application",
        subtype=subtype or "octet-stream",
        filename=filename,
    )

    await asyncio.to_thread(channel._send_blocking, message)


__all__ = [
    "DEFAULT_RETENTION",
    "MAX_ATTACHMENT_BYTES",
    "DeliveryOutcome",
    "ReportDeliveryService",
    "package",
]
