"""Phase 2 acceptance (SRS §12).

    parser coverage ≥90%; drift finding generated on changed fixture.

Proved twice, because the two paths that reach a snapshot must both work:

- **Live collection** — a job runs the platform's collection profile against a fake
  device, stores artefacts and a snapshot, and raises a drift finding when the device's
  configuration changes underneath a pinned baseline.
- **Offline upload** — the same chain driven through the HTTP API with no device
  contact at all (FR-COL-11), which is how an air-gapped site is assessed.

Written as continuous paths rather than isolated assertions: the criterion is that the
chain works end to end. The individual links have their own tests in test_parsers.py,
test_snapshots.py and test_profiles.py.
"""

from __future__ import annotations

from pathlib import Path

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from netsecops.adapters.profiles import get_profile
from netsecops.core.crypto import SecretVault
from netsecops.core.rbac import Principal, Role, Scope
from netsecops.db.models import AuditLog, Device, Finding, User
from netsecops.db.models.collection import Artifact, Collection, FindingKind, FindingSeverity
from netsecops.db.models.inventory import CredentialType, DeviceClass, Vendor
from netsecops.db.models.jobs import JobStatus, JobType
from netsecops.parsers.base import ParseContext
from netsecops.parsers.registry import get_parser, supported_platforms
from netsecops.services.audit import AuditService
from netsecops.services.credentials import CredentialService
from netsecops.services.inventory import InventoryService
from netsecops.services.jobs import JobScope, JobService
from netsecops.services.snapshots import SnapshotService
from netsecops.workers.runner import execute_job
from tests.conftest import make_user
from tests.fake_device import fake_device
from tests.test_parsers import CORPUS, meaningful_lines

FIXTURES = Path(__file__).parent / "fixtures"
HARDENED = (FIXTURES / "cisco/ios/17.9/hardened_switch.cfg").read_text(encoding="utf-8")
WEAK = (FIXTURES / "cisco/ios/15.2/weak_switch.cfg").read_text(encoding="utf-8")

DEVICE_USER = "netsecops"
DEVICE_PASSWORD = "device-pass"

#: A secret planted in the hardened fixture. It must not reach any redacted surface.
PLANTED_SECRET = "S3cr3tVtpPass"


# ─────────────────── criterion 1: parser coverage ≥ 90% ──────────────────────


class TestParserCoverageCriterion:
    """The first half of the acceptance criterion, stated plainly."""

    @pytest.mark.parametrize("fixture", CORPUS, ids=lambda f: f.id)
    def test_each_fixture_is_at_least_90_percent_parsed(self, fixture) -> None:
        ncm = fixture.parse()
        total = len(meaningful_lines(fixture.text()))
        coverage = 100 * (total - len(ncm.raw_unparsed)) / total

        assert coverage >= 90, (
            f"{fixture.id}: {coverage:.1f}% — below the Phase 2 floor. Unparsed:\n  "
            + "\n  ".join(ncm.raw_unparsed[:20])
        )

    def test_every_phase_2_platform_has_a_parser(self) -> None:
        """Phase 2 is Cisco IOS/IOS-XE, NX-OS and ASA (SRS §12)."""
        assert set(supported_platforms()) >= {
            "cisco_ios",
            "cisco_iosxe",
            "cisco_nxos",
            "cisco_asa",
        }


# ──────────────────── criterion 2, path A: live collection ───────────────────


@pytest.fixture
async def device_server():
    """A fake switch that answers with the hardened configuration."""
    async for server in fake_device(
        username=DEVICE_USER,
        password=DEVICE_PASSWORD,
        responses={"show running-config": HARDENED},
    ):
        yield server


@pytest.fixture
async def analyst(session: AsyncSession) -> Principal:
    user = await make_user(session, username="phase2_analyst", roles={Role.SECURITY_ANALYST})
    return Principal(id=user.id, username=user.username, roles=user.role_set, scope=Scope.all())


async def _onboard(session: AsyncSession, server, actor: Principal, vault: SecretVault) -> Device:
    inventory = InventoryService(session)
    credentials = CredentialService(session, vault=vault)

    device = await inventory.create_device(
        mgmt_ip=server.host,
        actor=actor,
        hostname="core-sw-01",
        vendor=Vendor.CISCO,
        platform="cisco_ios",
        device_class=DeviceClass.SWITCH,
        ssh_port=server.port,
    )
    credential = await credentials.create(
        name="phase2-readonly",
        credential_type=CredentialType.SSH_PASSWORD,
        secret_data={"username": DEVICE_USER, "password": DEVICE_PASSWORD},
        actor=actor,
    )
    await credentials.assign(credential, device_id=device.id, actor=actor)
    return device


async def _collect(session: AsyncSession, device: Device, actor: Principal, vault: SecretVault):
    jobs = JobService(session)
    job = await jobs.create(
        job_type=JobType.COLLECT, scope=JobScope(device_ids=(device.id,)), actor=actor
    )
    return await execute_job(session, job.id, vault=vault)


class TestLiveCollectionProducesDrift:
    async def test_the_whole_chain(
        self,
        session: AsyncSession,
        device_server,
        analyst: Principal,
        vault: SecretVault,
    ) -> None:
        snapshots = SnapshotService(session, vault=vault)
        device = await _onboard(session, device_server, analyst, vault)

        # ── 1. collect ───────────────────────────────────────────────────
        completed = await _collect(session, device, analyst, vault)
        assert completed.status == JobStatus.SUCCEEDED.value

        profile = get_profile("cisco_ios")
        assert device_server.received == list(profile.all_commands())

        # ── 2. the collection produced evidence and a snapshot ───────────
        collection = (
            await session.execute(select(Collection).where(Collection.device_id == device.id))
        ).scalar_one()
        assert collection.finished_at is not None
        # The fake device answers only some of the profile, which is the realistic
        # case: the collection is partial but still assessable (FR-COL-08).
        assert collection.partial is True
        assert collection.error_message and "show port-security" in collection.error_message

        artifacts = (
            (await session.execute(select(Artifact).where(Artifact.collection_id == collection.id)))
            .scalars()
            .all()
        )
        assert len(artifacts) == len(profile.commands)

        snapshot = await snapshots.latest(device)
        assert snapshot is not None
        assert snapshot.parse_coverage is not None and snapshot.parse_coverage >= 90
        assert snapshot.ncm["device"]["hostname"] == "core-sw-01"

        # ── 3. nothing collected leaks a secret on the redacted path ─────
        assert PLANTED_SECRET not in snapshot.config_redacted
        assert PLANTED_SECRET not in str(snapshot.ncm)
        for artifact in artifacts:
            assert PLANTED_SECRET not in artifact.response_redacted
            assert PLANTED_SECRET.encode() not in artifact.response_encrypted

        # ── 4. pin it as the baseline ────────────────────────────────────
        await snapshots.pin_baseline(snapshot, actor=analyst)

        # Collecting again with nothing changed must stay silent, and must not store a
        # second copy of an identical configuration (FR-DRIFT-01).
        await _collect(session, device, analyst, vault)
        assert (await snapshots.detect_drift(device, snapshot)).changed is False
        _, total = await snapshots.list_for_device(device)
        assert total == 1

        # ── 5. the device changes underneath us ──────────────────────────
        device_server.set_response("show running-config", WEAK)
        await _collect(session, device, analyst, vault)

        latest = await snapshots.latest(device)
        assert latest is not None and latest.id != snapshot.id

        # ── 6. …and that produces a drift finding ────────────────────────
        finding = (
            await session.execute(select(Finding).where(Finding.device_id == device.id))
        ).scalar_one()

        assert finding.kind == FindingKind.DRIFT.value
        assert finding.severity == FindingSeverity.HIGH.value
        assert finding.snapshot_id == latest.id
        assert finding.evidence["unified_diff"]
        assert any("telnet" in change for change in finding.evidence["semantic_changes"]), (
            finding.evidence["semantic_changes"]
        )
        assert PLANTED_SECRET not in str(finding.evidence)

        # ── 7. the audit trail survived all of it ────────────────────────
        await session.flush()
        verification = await AuditService(session).verify_chain()
        assert verification.valid, verification.reason

    async def test_the_device_is_never_asked_to_change_anything(
        self,
        session: AsyncSession,
        device_server,
        analyst: Principal,
        vault: SecretVault,
    ) -> None:
        """SRS §8 — the constraint that overrides every other requirement."""
        device = await _onboard(session, device_server, analyst, vault)
        await _collect(session, device, analyst, vault)

        device_server.assert_never_received(
            "configure",
            "write",
            "copy",
            "reload",
            "clear",
            "delete",
            "erase",
            "set ",
            "commit",
            "no ",
        )


# ─────────────────── criterion 2, path B: the HTTP API ───────────────────────


@pytest.fixture
async def api_user(session: AsyncSession) -> User:
    return await make_user(session, username="phase2_api", roles={Role.SECURITY_ANALYST})


@pytest.fixture
async def api_device(session: AsyncSession, api_user: User) -> Device:
    actor = Principal(
        id=api_user.id, username=api_user.username, roles=api_user.role_set, scope=Scope.all()
    )
    return await InventoryService(session).create_device(
        mgmt_ip="198.51.100.21",
        actor=actor,
        hostname="core-sw-01",
        vendor=Vendor.CISCO,
        platform="cisco_ios",
        device_class=DeviceClass.SWITCH,
    )


def upload(text: str, name: str = "config.cfg") -> dict:
    return {"files": {"file": (name, text.encode("utf-8"), "text/plain")}}


class TestOfflineUploadProducesDrift:
    async def test_the_whole_chain_through_the_api(
        self,
        client: AsyncClient,
        session: AsyncSession,
        authenticate,
        api_user: User,
        api_device: Device,
    ) -> None:
        authenticate(api_user)
        device_id = str(api_device.id)

        # ── 1. upload the hardened configuration ─────────────────────────
        first = await client.post(
            f"/api/v1/devices/{device_id}/configs", **upload(HARDENED, "hardened.cfg")
        )
        assert first.status_code == 201, first.text
        body = first.json()
        assert body["parse_coverage"] >= 90
        assert body["deduplicated"] is False
        assert body["drift"]["changed"] is False
        assert "no baseline" in body["drift"]["headline"].lower()

        baseline_id = body["snapshot_id"]

        # ── 2. pin it ────────────────────────────────────────────────────
        pinned = await client.post(f"/api/v1/snapshots/{baseline_id}/baseline")
        assert pinned.status_code == 200, pinned.text
        assert pinned.json()["is_baseline"] is True

        # ── 3. upload the changed configuration ──────────────────────────
        second = await client.post(
            f"/api/v1/devices/{device_id}/configs", **upload(WEAK, "weak.cfg")
        )
        assert second.status_code == 201, second.text
        drift = second.json()["drift"]

        assert drift["changed"] is True
        assert drift["severity"] == "high"
        assert drift["finding_id"] is not None
        assert drift["added"] and drift["removed"]

        # ── 4. the drift finding exists, with its diff ───────────────────
        finding = (
            await session.execute(select(Finding).where(Finding.device_id == api_device.id))
        ).scalar_one()
        assert finding.kind == FindingKind.DRIFT.value
        assert str(finding.id) == drift["finding_id"]

        # ── 5. the diff endpoint answers for the UI (IF-UI-05) ───────────
        changed_id = second.json()["snapshot_id"]
        diff = await client.get(f"/api/v1/snapshots/{changed_id}/diff")
        assert diff.status_code == 200, diff.text
        payload = diff.json()

        assert payload["from_snapshot_id"] == baseline_id
        assert payload["changed"] is True
        assert payload["unified"]
        assert payload["before_lines"] and payload["after_lines"]
        assert any("telnet" in c["path"] for c in payload["semantic"])
        assert PLANTED_SECRET not in diff.text

        # ── 6. the device's drift view agrees ────────────────────────────
        status = await client.get(f"/api/v1/devices/{device_id}/drift")
        assert status.status_code == 200
        assert status.json()["changed"] is True
        assert status.json()["baseline_snapshot_id"] == baseline_id

    async def test_snapshot_history_is_listed(
        self, client: AsyncClient, authenticate, api_user: User, api_device: Device
    ) -> None:
        authenticate(api_user)
        device_id = str(api_device.id)

        await client.post(f"/api/v1/devices/{device_id}/configs", **upload(HARDENED))
        await client.post(f"/api/v1/devices/{device_id}/configs", **upload(WEAK))

        listed = await client.get(f"/api/v1/devices/{device_id}/snapshots")
        assert listed.status_code == 200
        assert listed.json()["meta"]["total"] == 2

    async def test_uploading_the_same_file_twice_does_not_store_it_twice(
        self, client: AsyncClient, authenticate, api_user: User, api_device: Device
    ) -> None:
        authenticate(api_user)
        device_id = str(api_device.id)

        first = await client.post(f"/api/v1/devices/{device_id}/configs", **upload(HARDENED))
        second = await client.post(f"/api/v1/devices/{device_id}/configs", **upload(HARDENED))

        assert second.json()["deduplicated"] is True
        assert second.json()["snapshot_id"] == first.json()["snapshot_id"]

    async def test_an_empty_file_is_rejected_with_a_readable_message(
        self, client: AsyncClient, authenticate, api_user: User, api_device: Device
    ) -> None:
        authenticate(api_user)
        response = await client.post(
            f"/api/v1/devices/{api_device.id}/configs", **upload("   \n", "empty.cfg")
        )
        assert response.status_code == 422
        assert "empty" in response.json()["detail"].lower()

    async def test_clearing_the_baseline_works(
        self, client: AsyncClient, authenticate, api_user: User, api_device: Device
    ) -> None:
        authenticate(api_user)
        device_id = str(api_device.id)

        uploaded = await client.post(f"/api/v1/devices/{device_id}/configs", **upload(HARDENED))
        await client.post(f"/api/v1/snapshots/{uploaded.json()['snapshot_id']}/baseline")

        cleared = await client.delete(f"/api/v1/devices/{device_id}/baseline")
        assert cleared.status_code == 204

        again = await client.delete(f"/api/v1/devices/{device_id}/baseline")
        assert again.status_code == 409


# ──────────────────── redaction at the API boundary (SEC-09) ─────────────────


class TestRedactionAtTheApiBoundary:
    @pytest.fixture
    async def uploaded(
        self, client: AsyncClient, authenticate, api_user: User, api_device: Device
    ) -> dict:
        authenticate(api_user)
        response = await client.post(f"/api/v1/devices/{api_device.id}/configs", **upload(HARDENED))
        return response.json()

    async def test_the_snapshot_view_is_redacted(self, client: AsyncClient, uploaded: dict) -> None:
        response = await client.get(f"/api/v1/snapshots/{uploaded['snapshot_id']}")
        assert response.status_code == 200
        assert PLANTED_SECRET not in response.text
        # …but it is still a readable configuration (IF-UI-04).
        assert "hostname core-sw-01" in response.json()["config_redacted"]

    async def test_the_artefact_view_is_redacted(self, client: AsyncClient, uploaded: dict) -> None:
        response = await client.get(f"/api/v1/artifacts/{uploaded['artifact_id']}")
        assert response.status_code == 200
        assert response.json()["redacted"] is True
        assert PLANTED_SECRET not in response.text

    async def test_the_raw_view_returns_the_original_and_audits_it(
        self, client: AsyncClient, session: AsyncSession, uploaded: dict
    ) -> None:
        """The one route the original may leave by — permissioned and audited."""
        response = await client.get(f"/api/v1/artifacts/{uploaded['artifact_id']}/raw")
        assert response.status_code == 200
        assert response.json()["redacted"] is False
        assert PLANTED_SECRET in response.json()["response"]

        actions = (await session.execute(select(AuditLog.action))).scalars().all()
        assert "config.viewed_unredacted" in actions

    async def test_a_network_engineer_cannot_see_the_original(
        self,
        client: AsyncClient,
        session: AsyncSession,
        authenticate,
        uploaded: dict,
    ) -> None:
        """SRS §2.3 — owning the device does not confer the right to read its secrets."""
        engineer = await make_user(
            session, username="phase2_engineer", roles={Role.NETWORK_ENGINEER}
        )
        authenticate(engineer)

        redacted = await client.get(f"/api/v1/artifacts/{uploaded['artifact_id']}")
        assert redacted.status_code == 200

        raw = await client.get(f"/api/v1/artifacts/{uploaded['artifact_id']}/raw")
        assert raw.status_code == 403


# ────────────────────────── determinism across paths ─────────────────────────


class TestUploadAndCollectionAgree:
    async def test_the_same_configuration_hashes_the_same_either_way(
        self,
        session: AsyncSession,
        device_server,
        analyst: Principal,
        vault: SecretVault,
    ) -> None:
        """A configuration assessed offline and the same one collected live must agree
        about the configuration, or the two paths would disagree about drift.

        They no longer agree about *everything*, and that is deliberate. Since Phase 6
        wired operational artefacts through to the parsers (FR-VUL-01), a live collection
        also runs `show version` and learns the image version, hardware model and serial
        — none of which appear in a running configuration, and none of which an uploaded
        file can ever supply. The collected NCM is therefore richer, and its
        ``normalized_hash`` legitimately differs.

        What must still hold is the part drift actually depends on. ``detect_drift``
        gates on ``config_hash``, so equal configuration text means no drift whichever
        path produced it. The NCM comparison below is kept rather than dropped, narrowed
        to assert that the divergence is confined to those operational fields: if the two
        paths ever disagree about the *configuration* itself, this still catches it.
        """
        snapshots = SnapshotService(session, vault=vault)

        collected_device = await _onboard(session, device_server, analyst, vault)
        await _collect(session, collected_device, analyst, vault)
        collected = await snapshots.latest(collected_device)

        uploaded_device = await InventoryService(session).create_device(
            mgmt_ip="198.51.100.22",
            actor=analyst,
            vendor=Vendor.CISCO,
            platform="cisco_ios",
        )
        result = await snapshots.ingest_config(
            uploaded_device, config_text=HARDENED, filename="same.cfg", actor=analyst
        )

        assert collected is not None
        assert collected.config_hash == result.snapshot.config_hash, (
            "the configuration is the same, so drift must see them as identical"
        )

        # The collected device learned its version from `show version`; the upload could
        # only read the configuration's own `version` directive. The difference between
        # the two values is precisely the precision a CVE match needs: `17.09.04a` names
        # a rebuild, `17.9` names a release train containing dozens of them.
        assert collected.ncm["device"]["version"] == "17.09.04a"
        assert result.snapshot.ncm["device"]["version"] == "17.9"

        operational = {"version", "model", "serials"}
        collected_device = {
            k: v for k, v in collected.ncm["device"].items() if k not in operational
        }
        uploaded_device = {
            k: v for k, v in result.snapshot.ncm["device"].items() if k not in operational
        }
        assert collected_device == uploaded_device, (
            "outside the operational fields the two paths must read the configuration identically"
        )

        for section in ("management", "aaa", "snmp", "users", "features", "acls"):
            assert collected.ncm[section] == result.snapshot.ncm[section], (
                f"{section} is parsed from the configuration alone and cannot differ "
                "between an upload and a collection"
            )

    def test_parsing_the_fixture_is_stable_across_runs(self) -> None:
        parser = get_parser("cisco_ios")
        first = parser.parse(ParseContext(text=HARDENED)).to_storage()
        second = parser.parse(ParseContext(text=HARDENED)).to_storage()
        assert first == second
