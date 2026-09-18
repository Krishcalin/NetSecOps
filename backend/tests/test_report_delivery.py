"""Scheduled report delivery (FR-RPT-04).

The load-bearing assertion here is that a password-protected archive is *actually*
encrypted. The standard library can read an encrypted ZIP and cannot write one, so the
obvious implementation produces an ordinary archive and reports success — and the
operator then believes a document containing every finding in the estate is protected
while it crosses two mail systems in the clear.

So these tests read the bytes and try to open the archive without the password, rather
than trusting that a function called `package` packaged anything.
"""

from __future__ import annotations

import io
import uuid
from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from netsecops.db.models.reporting import Report, ReportFormat, ReportStatus
from netsecops.integrations.channels import ChannelError, EmailChannel
from netsecops.services.report_delivery import (
    ReportDeliveryService,
    package,
)

SECRET_TITLE = "Telnet enabled on core-sw-01"
PASSWORD = "correct horse battery staple"


def _aes_available() -> bool:
    """Whether AES archive writing actually works on this machine.

    `pyzipper` imports fine and fails at *use* when pycryptodomex's compiled extension is
    missing. That happens on developer machines whose endpoint-protection software strips
    freshly written `.pyd` files — pip reports a clean install and the module is gone. CI
    and the container image run Linux and are unaffected, so the encryption tests are
    skipped rather than deleted: they are the assertions that matter most in this file and
    must keep running where they can.
    """
    try:
        import pyzipper

        buf = io.BytesIO()
        with pyzipper.AESZipFile(
            buf, "w", compression=pyzipper.ZIP_DEFLATED, encryption=pyzipper.WZ_AES
        ) as archive:
            archive.setpassword(b"probe")
            archive.writestr("probe", b"probe")
    except (ImportError, OSError):
        return False
    return True


needs_aes = pytest.mark.skipif(
    not _aes_available(),
    reason="pycryptodomex's compiled extension is unavailable (stripped by endpoint protection?)",
)


def make_report(**overrides) -> Report:
    base = {
        "org_id": 1,
        "template": "executive_summary",
        "title": "Quarterly compliance",
        "status": ReportStatus.READY.value,
        "parameters": {},
        "content": {
            "summary": {"total_findings": 1},
            "rows": [{"title": SECRET_TITLE, "severity": "critical"}],
        },
        "content_hash": "a" * 64,
        "generated_at": datetime(2026, 9, 18, 9, 0, tzinfo=UTC),
    }
    report = Report(**{**base, **overrides})
    report.id = overrides.get("id", uuid.uuid4())
    return report


class Recorder(EmailChannel):
    """An e-mail channel that records the message instead of sending it."""

    def __init__(self, **kwargs) -> None:
        super().__init__(**kwargs)
        object.__setattr__(self, "messages", [])

    def _send_blocking(self, message) -> None:  # type: ignore[no-untyped-def]
        self.messages.append(message)  # type: ignore[attr-defined]


def recorder(**kwargs) -> Recorder:
    return Recorder(host="smtp.test", recipients=("auditor@example.test",), **kwargs)


# ════════════════════════════ the encryption ═════════════════════════════════


class TestPackaging:
    def test_without_a_password_the_document_is_sent_as_is(self) -> None:
        # Zipping an unprotected file buys nothing and costs the recipient a step.
        name, body = package(make_report(), ReportFormat.JSON)
        assert not name.endswith(".zip")
        assert body[:1] in (b"{", b"[")

    def test_a_broken_aes_backend_refuses_rather_than_downgrading(self) -> None:
        """The failure that must never produce a plaintext archive.

        Runs everywhere, including where AES *is* available, because the property under
        test is the refusal path rather than the encryption.
        """
        import netsecops.services.report_delivery as delivery
        from netsecops.core.errors import ValidationProblem

        class Broken:
            ZIP_DEFLATED = 8
            WZ_AES = 2

            @staticmethod
            def AESZipFile(*_a, **_k):
                raise OSError("Cannot load native module 'Cryptodome.Hash._SHA1'")

        import sys

        sys.modules["pyzipper"] = Broken  # type: ignore[assignment]
        try:
            with pytest.raises(ValidationProblem) as caught:
                delivery.package(make_report(), ReportFormat.JSON, password=PASSWORD)
        finally:
            del sys.modules["pyzipper"]

        assert "unencrypted" in str(caught.value)

    @needs_aes
    def test_with_a_password_the_content_is_not_in_the_bytes(self) -> None:
        _name, body = package(make_report(), ReportFormat.JSON, password=PASSWORD)
        assert SECRET_TITLE.encode() not in body

    @needs_aes
    def test_the_archive_cannot_be_opened_without_the_password(self) -> None:
        """The assertion that distinguishes encryption from a ZIP with a password field."""
        import pyzipper

        _name, body = package(make_report(), ReportFormat.JSON, password=PASSWORD)

        with pyzipper.AESZipFile(io.BytesIO(body)) as archive:
            entry = archive.namelist()[0]
            with pytest.raises(RuntimeError):
                archive.read(entry)

    @needs_aes
    def test_it_opens_with_the_password(self) -> None:
        import pyzipper

        _name, body = package(make_report(), ReportFormat.JSON, password=PASSWORD)

        with pyzipper.AESZipFile(io.BytesIO(body)) as archive:
            archive.setpassword(PASSWORD.encode())
            assert SECRET_TITLE.encode() in archive.read(archive.namelist()[0])

    @needs_aes
    def test_the_archive_is_named_as_one(self) -> None:
        name, _body = package(make_report(), ReportFormat.JSON, password=PASSWORD)
        assert name.endswith(".zip")


# ════════════════════════════ the delivery ═══════════════════════════════════


class TestDelivery:
    async def test_a_ready_report_is_attached(self, session: AsyncSession) -> None:
        report = make_report()
        session.add(report)
        await session.flush()

        sender = recorder()
        outcome = await ReportDeliveryService(session).deliver(
            report, channel_name="mail", fmt=ReportFormat.JSON, sender=sender
        )

        assert outcome.error is None
        assert outcome.delivered_to == 1
        attachments = list(sender.messages[0].iter_attachments())
        assert len(attachments) == 1

    async def test_the_covering_note_carries_the_content_hash(self, session: AsyncSession) -> None:
        # The hash is what lets a recipient check the attachment against the console copy
        # months later, when the report is being quoted back at somebody.
        report = make_report()
        session.add(report)
        await session.flush()

        sender = recorder()
        await ReportDeliveryService(session).deliver(
            report, channel_name="mail", fmt=ReportFormat.JSON, sender=sender
        )
        body = sender.messages[0].get_body(preferencelist=("plain",)).get_content()
        assert "a" * 64 in body

    async def test_an_unfinished_report_is_not_sent(self, session: AsyncSession) -> None:
        report = make_report(status=ReportStatus.PENDING.value)
        session.add(report)
        await session.flush()

        sender = recorder()
        outcome = await ReportDeliveryService(session).deliver(
            report, channel_name="mail", sender=sender
        )

        assert outcome.error is not None
        assert sender.messages == []

    async def test_an_oversized_attachment_is_refused_rather_than_bounced(
        self, session: AsyncSession
    ) -> None:
        """A bounce goes to a postmaster address nobody reads; this goes on the job."""
        report = make_report(content={"rows": [{"title": "x" * 200, "severity": "low"}] * 200_000})
        session.add(report)
        await session.flush()

        sender = recorder()
        outcome = await ReportDeliveryService(session).deliver(
            report, channel_name="mail", fmt=ReportFormat.JSON, sender=sender
        )

        assert outcome.error is not None
        assert "limit" in outcome.error
        assert sender.messages == []

    async def test_a_channel_with_no_recipients_is_an_error(self, session: AsyncSession) -> None:
        report = make_report()
        session.add(report)
        await session.flush()

        empty = Recorder(host="smtp.test", recipients=())
        outcome = await ReportDeliveryService(session).deliver(
            report, channel_name="mail", fmt=ReportFormat.JSON, sender=empty
        )
        assert outcome.error is not None

    async def test_a_transport_failure_is_reported_not_raised(self, session: AsyncSession) -> None:
        class Broken(Recorder):
            def _send_blocking(self, message) -> None:  # type: ignore[no-untyped-def]
                raise ChannelError("SMTP to smtp.test:587 failed: connection refused")

        report = make_report()
        session.add(report)
        await session.flush()

        outcome = await ReportDeliveryService(session).deliver(
            report,
            channel_name="mail",
            fmt=ReportFormat.JSON,
            sender=Broken(host="smtp.test", recipients=("a@example.test",)),
        )
        assert outcome.error is not None
        assert "connection refused" in outcome.error


# ════════════════════════════ retention ══════════════════════════════════════


class TestRetention:
    async def test_an_expired_report_is_retired(self, session: AsyncSession) -> None:
        session.add(make_report(expires_at=datetime.now(UTC) - timedelta(days=1)))
        await session.flush()

        assert await ReportDeliveryService(session).retire_expired() == 1
        assert (await session.execute(select(Report))).scalars().all() == []

    async def test_a_report_with_no_expiry_is_kept(self, session: AsyncSession) -> None:
        """The default for dated evidence is to keep it.

        A sweep that invented a deadline would quietly destroy the thing somebody needs
        at audit, which is the one moment nobody can reconstruct it.
        """
        session.add(make_report(expires_at=None))
        await session.flush()

        assert await ReportDeliveryService(session).retire_expired() == 0
        assert len((await session.execute(select(Report))).scalars().all()) == 1

    async def test_a_report_not_yet_expired_is_kept(self, session: AsyncSession) -> None:
        session.add(make_report(expires_at=datetime.now(UTC) + timedelta(days=30)))
        await session.flush()

        assert await ReportDeliveryService(session).retire_expired() == 0
