"""Snapshots, diff and drift (FR-DRIFT-01 … FR-DRIFT-03, FR-COL-03, FR-COL-11, SEC-09).

The question these tests are really asking is: *does this system distinguish a change
from noise?* A drift detector that fires on an NVRAM timestamp is worse than none,
because it teaches operators to ignore drift. So the volatile-line handling and the
de-duplication get as much attention here as the diff itself.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from netsecops.core.crypto import SecretVault
from netsecops.core.errors import ConflictError, ValidationProblem
from netsecops.core.rbac import Principal, Role, Scope
from netsecops.db.models import AuditLog, Device, Finding
from netsecops.db.models.collection import ArtifactKind, FindingKind, FindingSeverity, FindingStatus
from netsecops.db.models.inventory import DeviceClass, Vendor
from netsecops.services.inventory import InventoryService
from netsecops.services.snapshots import (
    SnapshotService,
    config_hash,
    diff_configs,
    diff_ncm,
    normalise_config,
)
from tests.conftest import make_user

FIXTURES = Path(__file__).parent / "fixtures"
HARDENED = FIXTURES / "cisco/ios/17.9/hardened_switch.cfg"
WEAK = FIXTURES / "cisco/ios/15.2/weak_switch.cfg"


def read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


@pytest.fixture
async def actor(session: AsyncSession) -> Principal:
    user = await make_user(session, username="snapshot_analyst", roles={Role.SECURITY_ANALYST})
    return Principal(id=user.id, username=user.username, roles=user.role_set, scope=Scope.all())


@pytest.fixture
async def device(session: AsyncSession, actor: Principal) -> Device:
    return await InventoryService(session).create_device(
        mgmt_ip="198.51.100.7",
        actor=actor,
        hostname="core-sw-01",
        vendor=Vendor.CISCO,
        platform="cisco_ios",
        device_class=DeviceClass.SWITCH,
    )


@pytest.fixture
def snapshots(session: AsyncSession, vault: SecretVault) -> SnapshotService:
    return SnapshotService(session, vault=vault)


# ───────────────────────── normalisation and hashing ─────────────────────────


class TestVolatileLines:
    """FR-DRIFT-01. These lines change on every poll without anything being changed."""

    @pytest.mark.parametrize(
        "line",
        [
            "! Last configuration change at 09:14:02 UTC Mon Sep 8 2026 by netops",
            "! NVRAM config last updated at 09:14:05 UTC Mon Sep 8 2026",
            "ntp clock-period 17179860",
            "Current configuration : 8421 bytes",
            "Building configuration...",
            "Cryptochecksum:1a2b3c4d5e6f7890",
            "!Running configuration last done at: Mon Sep  8 09:14:02 2026",
            "!Time: Tue Sep  9 03:41:55 2026",
        ],
    )
    def test_volatile_line_does_not_change_the_hash(self, line: str) -> None:
        base = "hostname sw1\nno ip http server\n"
        assert config_hash(base) == config_hash(f"{line}\n{base}")

    def test_a_real_change_does_change_the_hash(self) -> None:
        """The obverse: if everything were normalised away, nothing would ever drift."""
        assert config_hash("hostname sw1\nip http server\n") != config_hash(
            "hostname sw1\nno ip http server\n"
        )

    def test_trailing_whitespace_is_ignored(self) -> None:
        assert config_hash("hostname sw1   \n") == config_hash("hostname sw1\n")

    def test_normalisation_is_idempotent(self) -> None:
        once = normalise_config(read(HARDENED))
        assert normalise_config(once) == once

    def test_the_fixtures_hash_differently(self) -> None:
        assert config_hash(read(HARDENED)) != config_hash(read(WEAK))


# ───────────────────────────────── diffing ───────────────────────────────────


class TestTextDiff:
    def test_identical_configurations_show_no_change(self) -> None:
        diff = diff_configs(read(HARDENED), read(HARDENED))
        assert not diff.changed
        assert diff.unified == ""

    def test_added_and_removed_lines_are_separated(self) -> None:
        diff = diff_configs("hostname a\nno ip http server\n", "hostname a\nip http server\n")
        assert "ip http server" in diff.added
        assert "no ip http server" in diff.removed

    def test_volatile_lines_never_appear_in_a_diff(self) -> None:
        """Otherwise every daily diff would open with a timestamp change and the real
        change would be below the fold."""
        before = "! Last configuration change at 09:00:00\nhostname sw1\n"
        after = "! Last configuration change at 17:30:00\nhostname sw1\n"
        assert not diff_configs(before, after).changed

    def test_summary_counts_both_directions(self) -> None:
        diff = diff_configs("hostname a\nline1\n", "hostname a\nline2\nline3\n")
        assert diff.summary == f"{len(diff.added)} added, {len(diff.removed)} removed"


class TestSemanticDiff:
    def test_reports_the_path_that_changed(self) -> None:
        before = {"management": {"services": {"telnet": {"enabled": False}}}}
        after = {"management": {"services": {"telnet": {"enabled": True}}}}

        changes = diff_ncm(before, after)
        assert [c.path for c in changes] == ["management.services.telnet.enabled"]
        assert changes[0].before is False
        assert changes[0].after is True

    def test_describes_a_boolean_in_words(self) -> None:
        """ "changed False → True" tells an operator less than "changed disabled →
        enabled", and this text goes straight into a finding."""
        before = {"management": {"services": {"telnet": {"enabled": False}}}}
        after = {"management": {"services": {"telnet": {"enabled": True}}}}
        assert "disabled → enabled" in diff_ncm(before, after)[0].describe()

    def test_provenance_changes_are_ignored(self) -> None:
        """Line numbers shift whenever anything above them changes. Counting that as a
        semantic change would make every snapshot differ from the last."""
        before = {"provenance": {"entries": {"a": 1}}, "device": {"hostname": "sw1"}}
        after = {"provenance": {"entries": {"a": 99}}, "device": {"hostname": "sw1"}}
        assert diff_ncm(before, after) == []

    def test_reordering_a_list_is_not_a_change(self) -> None:
        """An interface inserted at position two would otherwise report every later
        interface as changed — noise, not information."""
        before = {"users": [{"name": "a"}, {"name": "b"}]}
        after = {"users": [{"name": "b"}, {"name": "a"}]}
        assert diff_ncm(before, after) == []

    def test_adding_a_list_member_is_a_change(self) -> None:
        before = {"users": [{"name": "a"}]}
        after = {"users": [{"name": "a"}, {"name": "root"}]}
        assert [c.path for c in diff_ncm(before, after)] == ["users"]

    def test_a_new_key_reads_as_set_not_as_changed(self) -> None:
        changes = diff_ncm({}, {"ntp": {"authenticated": True}})
        assert "set to" in changes[0].describe()

    def test_a_removed_key_says_so(self) -> None:
        changes = diff_ncm({"ntp": {"authenticated": True}}, {})
        assert "removed" in changes[0].describe()

    def test_the_real_fixtures_produce_meaningful_changes(self) -> None:
        from netsecops.parsers.base import ParseContext
        from netsecops.parsers.registry import get_parser

        parser = get_parser("cisco_ios")
        before = parser.parse(ParseContext(text=read(HARDENED))).to_storage()
        after = parser.parse(ParseContext(text=read(WEAK))).to_storage()

        paths = {c.path for c in diff_ncm(before, after)}
        assert "management.services.telnet.enabled" in paths


# ──────────────────────────── snapshot storage ───────────────────────────────


class TestSnapshotStorage:
    async def test_creating_a_snapshot_parses_and_redacts(
        self, snapshots: SnapshotService, device: Device
    ) -> None:
        snapshot = await snapshots.create_snapshot(device, config_text=read(HARDENED))

        assert snapshot.ncm["device"]["hostname"] == "core-sw-01"
        assert snapshot.parse_coverage is not None and snapshot.parse_coverage >= 90
        assert "T4c4csK3y!Secret" not in snapshot.config_redacted
        assert "T4c4csK3y!Secret" not in str(snapshot.ncm)

    async def test_identical_configuration_is_deduplicated(
        self, snapshots: SnapshotService, device: Device, session: AsyncSession
    ) -> None:
        """FR-DRIFT-01. A device polled daily for a year that never changed should cost
        one row, not 365."""
        first = await snapshots.create_snapshot(device, config_text=read(HARDENED))
        second = await snapshots.create_snapshot(device, config_text=read(HARDENED))

        assert second.id == first.id
        assert second.seen_count == 2
        assert second.last_seen_at is not None

        rows, total = await snapshots.list_for_device(device)
        assert total == 1
        assert len(rows) == 1

    async def test_a_volatile_only_change_deduplicates(
        self, snapshots: SnapshotService, device: Device
    ) -> None:
        first = await snapshots.create_snapshot(device, config_text=read(HARDENED))
        second = await snapshots.create_snapshot(
            device,
            config_text="! Last configuration change at 17:30:00 UTC\n" + read(HARDENED),
        )
        assert second.id == first.id

    async def test_a_real_change_creates_a_second_snapshot(
        self, snapshots: SnapshotService, device: Device
    ) -> None:
        first = await snapshots.create_snapshot(device, config_text=read(HARDENED))
        second = await snapshots.create_snapshot(device, config_text=read(WEAK))

        assert second.id != first.id
        _, total = await snapshots.list_for_device(device)
        assert total == 2

    async def test_latest_returns_the_newest(
        self, snapshots: SnapshotService, device: Device
    ) -> None:
        await snapshots.create_snapshot(device, config_text=read(HARDENED))
        second = await snapshots.create_snapshot(device, config_text=read(WEAK))
        latest = await snapshots.latest(device)
        assert latest is not None and latest.id == second.id

    async def test_rows_written_in_one_transaction_still_order_correctly(
        self, snapshots: SnapshotService, device: Device, session: AsyncSession
    ) -> None:
        """`created_at` defaults to clock_timestamp(), not now().

        PostgreSQL's now() is transaction_timestamp(): every row written in one
        transaction gets an identical value, so ordering by it is a tie broken however
        the planner likes. `latest()` decides which snapshot drift is measured against,
        so an arbitrary answer there is a wrong answer. This surfaced as an intermittent
        test failure before it was understood.
        """
        first = await snapshots.create_snapshot(device, config_text=read(HARDENED))
        second = await snapshots.create_snapshot(device, config_text=read(WEAK))
        third = await snapshots.create_snapshot(
            device, config_text=read(WEAK).replace("hostname core-sw-01", "hostname core-sw-02")
        )

        assert first.created_at < second.created_at < third.created_at

        # And the ordering holds through the query `latest()` actually runs.
        rows, _ = await snapshots.list_for_device(device)
        assert [r.id for r in rows] == [third.id, second.id, first.id]

    async def test_a_device_without_a_platform_is_refused(
        self, snapshots: SnapshotService, session: AsyncSession, actor: Principal
    ) -> None:
        """Parsing an unclassified device would mean guessing the vendor, and a wrong
        guess produces confident nonsense."""
        unclassified = await InventoryService(session).create_device(
            mgmt_ip="198.51.100.8", actor=actor, vendor=Vendor.CISCO
        )
        with pytest.raises(ValidationProblem, match="platform"):
            await snapshots.create_snapshot(unclassified, config_text=read(HARDENED))


class TestArtifactStorage:
    async def test_response_is_encrypted_at_rest_and_redacted_for_display(
        self, snapshots: SnapshotService, device: Device, session: AsyncSession
    ) -> None:
        """FR-COL-03 and FR-COL-13. Two copies with two different jobs: the sealed
        original is evidence, the redacted copy is what a UI may show."""
        from netsecops.db.models.collection import Collection

        collection = Collection(org_id=device.org_id, device_id=device.id, adapter="cisco_ios")
        session.add(collection)
        await session.flush()

        artifact = await snapshots.store_artifact(
            collection, command="show running-config", response=read(HARDENED)
        )

        assert b"T4c4csK3y!Secret" not in artifact.response_encrypted
        assert "T4c4csK3y!Secret" not in artifact.response_redacted
        assert snapshots.open_artifact(artifact) == read(HARDENED)

    async def test_hash_is_of_the_original_not_the_redacted_copy(
        self, snapshots: SnapshotService, device: Device, session: AsyncSession
    ) -> None:
        """The hash is evidentiary. Hashing the redacted text would prove only that
        redaction is reproducible."""
        import hashlib

        from netsecops.db.models.collection import Collection

        collection = Collection(org_id=device.org_id, device_id=device.id, adapter="cisco_ios")
        session.add(collection)
        await session.flush()

        artifact = await snapshots.store_artifact(
            collection, command="show running-config", response=read(HARDENED)
        )
        assert artifact.sha256 == hashlib.sha256(read(HARDENED).encode()).hexdigest()


# ─────────────────────────────── baselines ───────────────────────────────────


class TestBaselines:
    async def test_pinning_records_who_and_when(
        self, snapshots: SnapshotService, device: Device, actor: Principal
    ) -> None:
        snapshot = await snapshots.create_snapshot(device, config_text=read(HARDENED))
        pinned = await snapshots.pin_baseline(snapshot, actor=actor)

        assert pinned.is_baseline is True
        assert pinned.baseline_pinned_at is not None
        assert pinned.baseline_pinned_by_id == actor.id

    async def test_pinning_a_second_snapshot_unpins_the_first(
        self, snapshots: SnapshotService, device: Device, actor: Principal
    ) -> None:
        """The database enforces one baseline per device with a partial unique index,
        so failing to unpin would raise rather than silently produce two."""
        first = await snapshots.create_snapshot(device, config_text=read(HARDENED))
        await snapshots.pin_baseline(first, actor=actor)

        second = await snapshots.create_snapshot(device, config_text=read(WEAK))
        await snapshots.pin_baseline(second, actor=actor)

        assert first.is_baseline is False
        assert second.is_baseline is True
        current = await snapshots.baseline(device)
        assert current is not None and current.id == second.id

    async def test_pinning_the_same_snapshot_twice_is_a_no_op(
        self, snapshots: SnapshotService, device: Device, actor: Principal
    ) -> None:
        snapshot = await snapshots.create_snapshot(device, config_text=read(HARDENED))
        await snapshots.pin_baseline(snapshot, actor=actor)
        again = await snapshots.pin_baseline(snapshot, actor=actor)
        assert again.id == snapshot.id

    async def test_pinning_is_audited(
        self, snapshots: SnapshotService, device: Device, actor: Principal, session: AsyncSession
    ) -> None:
        """Pinning decides what counts as drift for this device from now on, so the
        decision and its author belong in the trail."""
        snapshot = await snapshots.create_snapshot(device, config_text=read(HARDENED))
        await snapshots.pin_baseline(snapshot, actor=actor)
        await session.flush()

        actions = (await session.execute(select(AuditLog.action))).scalars().all()
        assert "baseline.pinned" in actions

    async def test_clearing_without_a_baseline_is_a_conflict(
        self, snapshots: SnapshotService, device: Device, actor: Principal
    ) -> None:
        with pytest.raises(ConflictError, match="no baseline"):
            await snapshots.clear_baseline(device, actor=actor)

    async def test_clearing_removes_it_and_is_audited(
        self, snapshots: SnapshotService, device: Device, actor: Principal, session: AsyncSession
    ) -> None:
        snapshot = await snapshots.create_snapshot(device, config_text=read(HARDENED))
        await snapshots.pin_baseline(snapshot, actor=actor)
        await snapshots.clear_baseline(device, actor=actor)
        await session.flush()

        assert await snapshots.baseline(device) is None
        actions = (await session.execute(select(AuditLog.action))).scalars().all()
        assert "baseline.cleared" in actions


# ───────────────────────────────── drift ─────────────────────────────────────


class TestDriftDetection:
    async def test_no_baseline_means_no_drift(
        self, snapshots: SnapshotService, device: Device
    ) -> None:
        """A device whose baseline has never been pinned should produce silence on its
        first collection, not a finding saying everything changed."""
        snapshot = await snapshots.create_snapshot(device, config_text=read(HARDENED))
        drift = await snapshots.detect_drift(device, snapshot)

        assert drift.changed is False
        assert await snapshots.record_drift_finding(device, snapshot, drift) is None

    async def test_the_baseline_does_not_drift_from_itself(
        self, snapshots: SnapshotService, device: Device, actor: Principal
    ) -> None:
        snapshot = await snapshots.create_snapshot(device, config_text=read(HARDENED))
        await snapshots.pin_baseline(snapshot, actor=actor)
        assert (await snapshots.detect_drift(device, snapshot)).changed is False

    async def test_a_changed_configuration_drifts(
        self, snapshots: SnapshotService, device: Device, actor: Principal
    ) -> None:
        baseline = await snapshots.create_snapshot(device, config_text=read(HARDENED))
        await snapshots.pin_baseline(baseline, actor=actor)

        later = await snapshots.create_snapshot(device, config_text=read(WEAK))
        drift = await snapshots.detect_drift(device, later)

        assert drift.changed is True
        assert drift.diff is not None and drift.diff.changed
        assert drift.semantic

    async def test_a_security_relevant_change_is_high_severity(
        self, snapshots: SnapshotService, device: Device, actor: Principal
    ) -> None:
        """ "Somebody turned Telnet on" and "somebody edited a description" must not
        arrive looking the same."""
        baseline = await snapshots.create_snapshot(device, config_text=read(HARDENED))
        await snapshots.pin_baseline(baseline, actor=actor)

        later = await snapshots.create_snapshot(device, config_text=read(WEAK))
        drift = await snapshots.detect_drift(device, later)

        assert drift.severity is FindingSeverity.HIGH
        assert drift.semantic[0].path.startswith(
            ("management", "aaa", "snmp", "users", "acls", "logging", "ntp", "features")
        )

    async def test_a_cosmetic_change_is_low_severity(
        self, snapshots: SnapshotService, device: Device, actor: Principal
    ) -> None:
        base = read(HARDENED)
        baseline = await snapshots.create_snapshot(device, config_text=base)
        await snapshots.pin_baseline(baseline, actor=actor)

        cosmetic = base.replace("description UPLINK TO DIST-01", "description UPLINK TO DIST-01A")
        assert cosmetic != base, "the fixture no longer contains the line this test edits"

        later = await snapshots.create_snapshot(device, config_text=cosmetic)
        drift = await snapshots.detect_drift(device, later)

        assert drift.changed is True
        assert drift.severity is FindingSeverity.LOW

    async def test_snapshots_from_different_devices_cannot_be_compared(
        self, snapshots: SnapshotService, device: Device, actor: Principal, session: AsyncSession
    ) -> None:
        other = await InventoryService(session).create_device(
            mgmt_ip="198.51.100.9", actor=actor, vendor=Vendor.CISCO, platform="cisco_ios"
        )
        a = await snapshots.create_snapshot(device, config_text=read(HARDENED))
        b = await snapshots.create_snapshot(other, config_text=read(WEAK))

        with pytest.raises(ValidationProblem, match="different devices"):
            await snapshots.diff(a, b)


class TestDriftFindings:
    @pytest.fixture
    async def drifted(
        self, snapshots: SnapshotService, device: Device, actor: Principal
    ) -> Finding:
        baseline = await snapshots.create_snapshot(device, config_text=read(HARDENED))
        await snapshots.pin_baseline(baseline, actor=actor)
        later = await snapshots.create_snapshot(device, config_text=read(WEAK))
        drift = await snapshots.detect_drift(device, later)
        finding = await snapshots.record_drift_finding(device, later, drift)
        assert finding is not None
        return finding

    async def test_the_finding_describes_itself(self, drifted: Finding) -> None:
        assert drifted.kind == FindingKind.DRIFT.value
        assert drifted.status == FindingStatus.NEW.value
        assert "core-sw-01" in drifted.title
        assert drifted.remediation

    async def test_the_diff_is_attached_as_evidence(self, drifted: Finding) -> None:
        """FR-DRIFT-03. A drift finding without its diff asks an operator to take the
        conclusion on trust."""
        assert drifted.evidence["added"] or drifted.evidence["removed"]
        assert drifted.evidence["unified_diff"]
        assert drifted.evidence["semantic_changes"]

    async def test_the_evidence_carries_no_secrets(self, drifted: Finding) -> None:
        """A finding is exported, emailed and pasted into tickets. It travels further
        than the configuration ever did."""
        blob = str(drifted.evidence)
        for secret in ("T4c4csK3y!Secret", "R4d1usK3y!Secret", "cisco123", "VtpP4ssw0rd"):
            assert secret not in blob

    async def test_repeated_drift_updates_one_finding(
        self, snapshots: SnapshotService, device: Device, actor: Principal, drifted: Finding
    ) -> None:
        """FR-FIND-01. The same problem on the same device is one finding with an
        occurrence count, not a new row per scan."""
        later = await snapshots.latest(device)
        assert later is not None
        drift = await snapshots.detect_drift(device, later)
        again = await snapshots.record_drift_finding(device, later, drift)

        assert again is not None and again.id == drifted.id
        assert again.occurrences == 2

    async def test_returning_to_the_baseline_resolves_the_finding(
        self, snapshots: SnapshotService, device: Device, drifted: Finding
    ) -> None:
        resolved = await snapshots.resolve_drift_finding(device)
        assert resolved is not None
        assert resolved.status == FindingStatus.RESOLVED.value
        assert resolved.resolved_at is not None

    async def test_drifting_again_reopens_rather_than_duplicating(
        self, snapshots: SnapshotService, device: Device, actor: Principal, drifted: Finding
    ) -> None:
        await snapshots.resolve_drift_finding(device)

        later = await snapshots.latest(device)
        assert later is not None
        drift = await snapshots.detect_drift(device, later)
        reopened = await snapshots.record_drift_finding(device, later, drift)

        assert reopened is not None
        assert reopened.id == drifted.id
        assert reopened.status == FindingStatus.REOPENED.value
        assert reopened.resolved_at is None


# ────────────────────────── offline upload (FR-COL-11) ───────────────────────


class TestOfflineUpload:
    async def test_upload_produces_a_snapshot_without_touching_the_device(
        self, snapshots: SnapshotService, device: Device, actor: Principal
    ) -> None:
        result = await snapshots.ingest_config(
            device, config_text=read(HARDENED), filename="core-sw-01.cfg", actor=actor
        )

        assert result.snapshot.parse_coverage is not None
        assert result.artifact.kind == ArtifactKind.UPLOAD.value
        assert result.deduplicated is False
        assert result.collection.finished_at is not None

    async def test_the_artefact_records_that_nothing_was_asked_of_a_device(
        self, snapshots: SnapshotService, device: Device, actor: Principal
    ) -> None:
        """The trail must not imply a command was sent to equipment that was never
        contacted."""
        result = await snapshots.ingest_config(
            device, config_text=read(HARDENED), filename="core-sw-01.cfg", actor=actor
        )
        assert result.artifact.request_text == "upload:core-sw-01.cfg"

    async def test_uploading_the_same_file_twice_deduplicates(
        self, snapshots: SnapshotService, device: Device, actor: Principal
    ) -> None:
        first = await snapshots.ingest_config(
            device, config_text=read(HARDENED), filename="a.cfg", actor=actor
        )
        second = await snapshots.ingest_config(
            device, config_text=read(HARDENED), filename="b.cfg", actor=actor
        )

        assert second.deduplicated is True
        assert second.snapshot.id == first.snapshot.id

    async def test_upload_detects_drift_against_a_pinned_baseline(
        self, snapshots: SnapshotService, device: Device, actor: Principal
    ) -> None:
        baseline = await snapshots.create_snapshot(device, config_text=read(HARDENED))
        await snapshots.pin_baseline(baseline, actor=actor)

        result = await snapshots.ingest_config(
            device, config_text=read(WEAK), filename="weak.cfg", actor=actor
        )

        assert result.drift.changed is True
        assert result.finding is not None
        assert result.finding.kind == FindingKind.DRIFT.value

    async def test_upload_is_audited(
        self, snapshots: SnapshotService, device: Device, actor: Principal, session: AsyncSession
    ) -> None:
        await snapshots.ingest_config(
            device, config_text=read(HARDENED), filename="core-sw-01.cfg", actor=actor
        )
        await session.flush()

        rows = (await session.execute(select(AuditLog))).scalars().all()
        uploads = [r for r in rows if r.command_text == "upload:core-sw-01.cfg"]
        assert uploads, "an uploaded configuration was not audited"
        assert uploads[0].device_id == device.id

    async def test_no_secret_reaches_the_audit_log(
        self, snapshots: SnapshotService, device: Device, actor: Principal, session: AsyncSession
    ) -> None:
        await snapshots.ingest_config(
            device, config_text=read(HARDENED), filename="core-sw-01.cfg", actor=actor
        )
        await session.flush()

        rows = (await session.execute(select(AuditLog))).scalars().all()
        for row in rows:
            haystack = f"{row.command_text} {row.details}"
            assert "T4c4csK3y!Secret" not in haystack
