"""``netsecops-cli import-feed`` — the offline bundle path from a shell (FR-VUL-08).

FR-VUL-08 exists for deployments with no route to the internet. Those are precisely the
deployments where an operator has a shell on the box and a file on removable media
rather than a browser session and a CSRF token, and where the first load is several
bundles in a row — KEV, then an end-of-life list per vendor, then advisories — that
somebody wants to put in a script. The console had an upload control and the API had an
endpoint; the one place the requirement is *for* had no surface at all.

These tests stop short of the database on purpose. The command opens its own
`session_scope`, which is a second engine on a second event loop, and driving it from a
test that holds an open transaction on the shared test database is how two pytest
processes end up fighting over the same schema. The ingest behaviour is covered against
a real session in `test_feed_import.py`; what is left here is the part that belongs to
the command — what it does before it touches anything, and what it shows when the
import is refused.
"""

from __future__ import annotations

import contextlib
from pathlib import Path
from types import SimpleNamespace
from typing import Any

import pytest
from typer.testing import CliRunner

from netsecops.cli import app
from netsecops.core.errors import ValidationProblem

runner = CliRunner()


@pytest.fixture
def bundle(tmp_path: Path) -> Path:
    path = tmp_path / "kev.json"
    path.write_text('{"catalogVersion": "2026.09.29", "vulnerabilities": []}', encoding="utf-8")
    return path


class TestTheCommandIsReachable:
    """The defect being guarded is a capability with no surface.

    `record_facts` in this codebase was written, documented against its requirement and
    called by nothing, and it took months and an empty vulnerability table to notice. A
    command that exists only in the console fails the same way for an air-gapped site:
    the feature is present, the requirement is unmet, and nothing reports an error.
    """

    def test_import_feed_is_registered(self) -> None:
        assert "import-feed" in {command.name for command in app.registered_commands}

    def test_its_help_names_the_formats_an_operator_will_be_holding(self) -> None:
        result = runner.invoke(app, ["import-feed", "--help"])

        assert result.exit_code == 0
        for fmt in ("NVD", "CSAF", "KEV", "EPSS", "EoL"):
            assert fmt in result.stdout

    def test_it_accepts_a_digest_and_an_eol_vendor(self) -> None:
        """Both are load-bearing rather than conveniences.

        The digest is the only thing standing between an operator and a bundle altered
        on the machine that downloaded it. The vendor is required for an end-of-life
        list, which carries release cycles and nothing saying whose they are — filing
        Cisco's dates under Fortinet would mark a supported estate as dead.
        """
        result = runner.invoke(app, ["import-feed", "--help"])

        for option in ("--sha256", "--vendor", "--product", "--feed"):
            assert option in result.stdout


class TestItRefusesBeforeItOpensAnything:
    def test_a_missing_file(self, tmp_path: Path) -> None:
        result = runner.invoke(app, ["import-feed", str(tmp_path / "absent.json")])

        assert result.exit_code == 2
        assert "No such file" in result.stdout

    def test_a_directory_is_not_a_bundle(self, tmp_path: Path) -> None:
        result = runner.invoke(app, ["import-feed", str(tmp_path)])

        assert result.exit_code == 2

    def test_an_empty_file(self, tmp_path: Path) -> None:
        """Nought bytes reads as a truncated copy, not as a bundle of nothing.

        Worth its own message: passed through, it would be refused later by the format
        detector with a sentence about JSON shapes, which sends the operator looking at
        the contents of a file that has none.
        """
        empty = tmp_path / "empty.json"
        empty.write_bytes(b"")

        result = runner.invoke(app, ["import-feed", str(empty)])

        assert result.exit_code == 2
        assert "empty" in result.stdout.lower()

    def test_neither_refusal_reaches_the_database(self, tmp_path: Path, monkeypatch) -> None:
        """A refused import must not even record a sync.

        These two are decided on the local file before any connection is opened, so a
        `session_scope` that raises on use is the assertion: if either path grew a
        database call, this fails rather than silently writing a failed-sync row for a
        file that was never a bundle.
        """
        import netsecops.db.session as db_session

        def explode() -> Any:
            raise AssertionError("a pre-flight refusal must not open a session")

        monkeypatch.setattr(db_session, "session_scope", explode)

        assert runner.invoke(app, ["import-feed", str(tmp_path / "absent.json")]).exit_code == 2

        empty = tmp_path / "empty.json"
        empty.write_bytes(b"")
        assert runner.invoke(app, ["import-feed", str(empty)]).exit_code == 2


class TestARefusedImportReadsAsARefusal:
    """Not as a crash.

    Every way this import can legitimately fail — a digest that does not match, a file
    that is not a bundle, an end-of-life list with no vendor — arrives as a
    `ValidationProblem` carrying a sentence written for the operator. Unhandled, that
    sentence appears as the last line of a traceback, which reads as a broken tool
    rather than a rejected file, and the operator's next move is to report a bug instead
    of to check the media they copied the bundle from.
    """

    @pytest.fixture
    def refusing_service(self, monkeypatch) -> None:
        import netsecops.db.session as db_session
        import netsecops.services.feeds as feeds_module

        @contextlib.asynccontextmanager
        async def fake_scope():
            yield object()

        class RefusingService:
            def __init__(self, session: Any) -> None:
                pass

            async def import_bundle(self, raw: bytes, **kwargs: Any) -> Any:
                raise ValidationProblem(
                    "This bundle's SHA-256 is abc, not the def that was expected. "
                    "Nothing has been imported."
                )

        monkeypatch.setattr(db_session, "session_scope", fake_scope)
        monkeypatch.setattr(feeds_module, "FeedImportService", RefusingService)

    def test_the_operator_sees_the_sentence_not_a_stack_trace(
        self, bundle: Path, refusing_service: None
    ) -> None:
        result = runner.invoke(app, ["import-feed", str(bundle), "--sha256", "0" * 64])

        assert result.exit_code == 1
        assert result.exception is None or isinstance(result.exception, SystemExit)
        assert "Nothing has been imported" in result.output
        assert "Traceback" not in result.output


class TestAPartialImportIsNotReportedAsSuccess:
    """Nine thousand of ten thousand records is nine thousand answers and a thousand
    blind spots. A script that only checks the exit status has to be able to tell.

    The service already treats `partial` as its own state rather than a shade of
    success; this is the command honouring that. Reported *after* the counts, not
    instead of them — what did load is still loaded, and the operator needs to know
    both halves.
    """

    @pytest.fixture
    def partial_service(self, monkeypatch) -> None:
        import netsecops.db.session as db_session
        import netsecops.services.feeds as feeds_module
        from netsecops.services.feeds import BundleKind, ImportResult, SyncStatus

        @contextlib.asynccontextmanager
        async def fake_scope():
            yield object()

        class PartialService:
            def __init__(self, session: Any) -> None:
                pass

            async def import_bundle(self, raw: bytes, **kwargs: Any) -> ImportResult:
                sync = SimpleNamespace(status=SyncStatus.PARTIAL.value, error_message=None)
                return ImportResult(
                    sync=sync,  # type: ignore[arg-type]
                    kind=BundleKind.NVD,
                    cves=9_600,
                    advisories=9_600,
                    rejected=400,
                )

        monkeypatch.setattr(db_session, "session_scope", fake_scope)
        monkeypatch.setattr(feeds_module, "FeedImportService", PartialService)

    def test_it_exits_non_zero_and_says_how_many_were_lost(
        self, bundle: Path, partial_service: None
    ) -> None:
        result = runner.invoke(app, ["import-feed", str(bundle)])

        assert result.exit_code == 1, "a script must not read partial as success"
        assert "partial" in result.output
        assert "400" in result.output

    def test_it_still_reports_what_did_load(self, bundle: Path, partial_service: None) -> None:
        result = runner.invoke(app, ["import-feed", str(bundle)])

        assert "9,600" in result.output or "9600" in result.output
