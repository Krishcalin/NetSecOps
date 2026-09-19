"""Inventory and credential-vault service tests (FR-INV, FR-CRED)."""

from __future__ import annotations

import uuid

import pytest
from sqlalchemy.ext.asyncio import AsyncSession

from netsecops.core.crypto import SecretVault
from netsecops.core.errors import ConflictError, NotFoundError, ValidationProblem
from netsecops.core.rbac import Principal, Role, Scope
from netsecops.db.models.inventory import CredentialType, Criticality, DeviceClass, Vendor
from netsecops.services.credentials import CredentialService
from netsecops.services.inventory import InventoryService
from tests.conftest import make_group, make_user


@pytest.fixture
async def actor(session: AsyncSession) -> Principal:
    user = await make_user(session, username="inv_actor", roles={Role.SECURITY_ANALYST})
    return Principal(id=user.id, username=user.username, roles=user.role_set, scope=Scope.all())


@pytest.fixture
def inventory(session: AsyncSession) -> InventoryService:
    return InventoryService(session)


@pytest.fixture
def credentials(session: AsyncSession, vault: SecretVault) -> CredentialService:
    return CredentialService(session, vault=vault)


class TestDeviceCrud:
    async def test_create(self, inventory: InventoryService, actor: Principal) -> None:
        device = await inventory.create_device(
            mgmt_ip="192.0.2.10",
            actor=actor,
            hostname="core-sw-01",
            vendor=Vendor.CISCO,
            platform="cisco_ios",
            device_class=DeviceClass.SWITCH,
            criticality=Criticality.HIGH,
        )
        assert str(device.mgmt_ip) == "192.0.2.10"
        assert device.criticality == "high"

    async def test_duplicate_ip_is_refused(
        self, inventory: InventoryService, actor: Principal
    ) -> None:
        await inventory.create_device(mgmt_ip="192.0.2.11", actor=actor)
        with pytest.raises(ConflictError, match="already exists"):
            await inventory.create_device(mgmt_ip="192.0.2.11", actor=actor)

    async def test_invalid_ip_is_refused(
        self, inventory: InventoryService, actor: Principal
    ) -> None:
        with pytest.raises(ValidationProblem, match="not a valid IP"):
            await inventory.create_device(mgmt_ip="not-an-ip", actor=actor)

    async def test_unknown_platform_is_refused(
        self, inventory: InventoryService, actor: Principal
    ) -> None:
        """A device we cannot describe is a device we must not touch (SRS §8.1)."""
        with pytest.raises(ValidationProblem, match="Unknown platform"):
            await inventory.create_device(
                mgmt_ip="192.0.2.12", actor=actor, platform="acme_router_9000"
            )

    async def test_ipv6_is_accepted(self, inventory: InventoryService, actor: Principal) -> None:
        device = await inventory.create_device(mgmt_ip="2001:db8::1", actor=actor)
        assert str(device.mgmt_ip) == "2001:db8::1"

    async def test_update_changes_fields(
        self, inventory: InventoryService, actor: Principal
    ) -> None:
        device = await inventory.create_device(mgmt_ip="192.0.2.13", actor=actor)
        updated = await inventory.update_device(
            device, actor=actor, hostname="renamed", criticality=Criticality.CRITICAL
        )
        assert updated.hostname == "renamed"
        assert updated.criticality == "critical"

    async def test_archive_keeps_the_row(
        self, inventory: InventoryService, actor: Principal
    ) -> None:
        device = await inventory.create_device(mgmt_ip="192.0.2.14", actor=actor)
        archived = await inventory.archive_device(device, actor=actor)

        assert archived.status == "archived"
        assert await inventory.get_device(device.id) is not None

    async def test_tags_are_created_on_first_use(
        self, inventory: InventoryService, actor: Principal
    ) -> None:
        await inventory.create_device(mgmt_ip="192.0.2.15", actor=actor, tags=["dmz", "pci"])
        assert {t.name for t in await inventory.list_tags()} == {"dmz", "pci"}


class TestDeviceGroups:
    async def test_root_group_path(self, inventory: InventoryService, actor: Principal) -> None:
        group = await inventory.create_group(name="HQ", actor=actor)
        assert group.path == f"g{group.id.hex}"

    async def test_child_path_embeds_the_parent(
        self, inventory: InventoryService, actor: Principal
    ) -> None:
        parent = await inventory.create_group(name="HQ", actor=actor)
        child = await inventory.create_group(name="Core", actor=actor, parent_id=parent.id)

        assert child.path.startswith(f"{parent.path}.")

    async def test_move_rewrites_the_whole_subtree(
        self, inventory: InventoryService, actor: Principal
    ) -> None:
        """A path embeds its ancestors, so a move is never a single-row update."""
        old_parent = await inventory.create_group(name="OldSite", actor=actor)
        new_parent = await inventory.create_group(name="NewSite", actor=actor)
        middle = await inventory.create_group(name="Zone", actor=actor, parent_id=old_parent.id)
        leaf = await inventory.create_group(name="Rack", actor=actor, parent_id=middle.id)

        await inventory.move_group(middle, new_parent_id=new_parent.id, actor=actor)

        assert middle.path.startswith(f"{new_parent.path}.")
        assert leaf.path.startswith(f"{middle.path}."), "the descendant must move too"

    async def test_cannot_move_under_own_descendant(
        self, inventory: InventoryService, actor: Principal
    ) -> None:
        parent = await inventory.create_group(name="Parent", actor=actor)
        child = await inventory.create_group(name="Child", actor=actor, parent_id=parent.id)

        with pytest.raises(ValidationProblem, match="own descendant"):
            await inventory.move_group(parent, new_parent_id=child.id, actor=actor)

    async def test_cannot_be_its_own_parent(
        self, inventory: InventoryService, actor: Principal
    ) -> None:
        group = await inventory.create_group(name="Solo", actor=actor)
        with pytest.raises(ValidationProblem, match="its own parent"):
            await inventory.move_group(group, new_parent_id=group.id, actor=actor)

    async def test_listing_by_group_includes_the_subtree(
        self, inventory: InventoryService, actor: Principal
    ) -> None:
        site = await inventory.create_group(name="Site", actor=actor)
        rack = await inventory.create_group(name="Rack", actor=actor, parent_id=site.id)

        await inventory.create_device(mgmt_ip="192.0.2.20", actor=actor, group_ids=[rack.id])

        _, total = await inventory.list_devices(scope=Scope.all(), group_id=site.id)
        assert total == 1, "targeting a site should reach devices in its racks"


class TestScopeFiltering:
    """FR-AUTH-05 — the query, not the caller, enforces visibility."""

    async def test_unrestricted_sees_everything(
        self, inventory: InventoryService, actor: Principal
    ) -> None:
        await inventory.create_device(mgmt_ip="192.0.2.30", actor=actor)
        _, total = await inventory.list_devices(scope=Scope.all())
        assert total == 1

    async def test_scoped_sees_only_its_groups(
        self, inventory: InventoryService, actor: Principal, session: AsyncSession
    ) -> None:
        mine = await make_group(session, name="mine")
        theirs = await make_group(session, name="theirs")

        visible = await inventory.create_device(
            mgmt_ip="192.0.2.31", actor=actor, group_ids=[mine.id]
        )
        await inventory.create_device(mgmt_ip="192.0.2.32", actor=actor, group_ids=[theirs.id])

        scope = Scope(unrestricted=False, device_group_ids=frozenset({mine.id}))
        rows, total = await inventory.list_devices(scope=scope)

        assert total == 1
        assert rows[0].id == visible.id

    async def test_scope_includes_descendant_groups(
        self, inventory: InventoryService, actor: Principal, session: AsyncSession
    ) -> None:
        """Granting a site grants everything beneath it, or the grant is useless."""
        site = await make_group(session, name="granted-site")
        rack = await make_group(session, name="granted-rack", parent=site)

        await inventory.create_device(mgmt_ip="192.0.2.33", actor=actor, group_ids=[rack.id])

        scope = Scope(unrestricted=False, device_group_ids=frozenset({site.id}))
        _, total = await inventory.list_devices(scope=scope)
        assert total == 1

    async def test_scope_with_no_groups_sees_nothing(
        self, inventory: InventoryService, actor: Principal
    ) -> None:
        """Fail closed: an empty scope must not mean 'everything'."""
        await inventory.create_device(mgmt_ip="192.0.2.34", actor=actor)

        scope = Scope(unrestricted=False, device_group_ids=frozenset())
        _, total = await inventory.list_devices(scope=scope)
        assert total == 0

    async def test_out_of_scope_device_reads_as_missing(
        self, inventory: InventoryService, actor: Principal, session: AsyncSession
    ) -> None:
        """Not 'forbidden': confirming a device exists is itself a disclosure."""
        hidden_group = await make_group(session, name="hidden")
        device = await inventory.create_device(
            mgmt_ip="192.0.2.35", actor=actor, group_ids=[hidden_group.id]
        )

        scope = Scope(unrestricted=False, device_group_ids=frozenset({uuid.uuid4()}))
        with pytest.raises(NotFoundError):
            await inventory.get_device(device.id, scope=scope)


class TestCsvImport:
    """FR-INV-02 — validate, preview, then apply."""

    async def test_preview_reports_creates(self, inventory: InventoryService) -> None:
        csv_text = "mgmt_ip,hostname,vendor\n192.0.2.40,sw-01,cisco\n192.0.2.41,sw-02,cisco\n"
        preview = await inventory.preview_import(csv_text)

        assert preview.ok
        assert preview.creates == 2 and preview.updates == 0

    async def test_preview_writes_nothing(
        self, inventory: InventoryService, actor: Principal
    ) -> None:
        await inventory.preview_import("mgmt_ip\n192.0.2.42\n")
        _, total = await inventory.list_devices(scope=Scope.all())
        assert total == 0, "a dry run must not create anything"

    async def test_existing_device_is_an_update(
        self, inventory: InventoryService, actor: Principal
    ) -> None:
        await inventory.create_device(mgmt_ip="192.0.2.43", actor=actor)
        preview = await inventory.preview_import("mgmt_ip,hostname\n192.0.2.43,renamed\n")

        assert preview.updates == 1 and preview.creates == 0

    async def test_invalid_ip_is_reported_with_its_line(self, inventory: InventoryService) -> None:
        preview = await inventory.preview_import("mgmt_ip\n192.0.2.44\nnonsense\n")

        assert not preview.ok
        bad = next(r for r in preview.rows if not r.valid)
        assert bad.line == 3
        assert "not a valid IP" in bad.errors[0]

    async def test_duplicate_within_the_file_is_caught(self, inventory: InventoryService) -> None:
        preview = await inventory.preview_import("mgmt_ip\n192.0.2.45\n192.0.2.45\n")
        assert not preview.ok
        assert any("duplicate" in e for r in preview.rows for e in r.errors)

    async def test_bad_enum_value_lists_the_alternatives(self, inventory: InventoryService) -> None:
        preview = await inventory.preview_import("mgmt_ip,vendor\n192.0.2.46,acme\n")
        errors = preview.rows[0].errors
        assert any("is not one of" in e and "cisco" in e for e in errors)

    async def test_missing_mgmt_ip_column_is_rejected(self, inventory: InventoryService) -> None:
        with pytest.raises(ValidationProblem, match="mgmt_ip"):
            await inventory.preview_import("hostname\nsw-01\n")

    async def test_empty_file_is_rejected(self, inventory: InventoryService) -> None:
        with pytest.raises(ValidationProblem, match="no data rows"):
            await inventory.preview_import("mgmt_ip\n")

    async def test_apply_creates_devices_groups_and_tags(
        self, inventory: InventoryService, actor: Principal
    ) -> None:
        csv_text = (
            "mgmt_ip,hostname,vendor,platform,site,groups,tags\n"
            "192.0.2.47,sw-01,cisco,cisco_ios,HQ,Core|Access,dmz|pci\n"
        )
        preview = await inventory.preview_import(csv_text)
        result = await inventory.apply_import(preview, actor=actor)

        assert result == {"created": 1, "updated": 0}
        assert {s.name for s in await inventory.list_sites()} == {"HQ"}
        assert {g.name for g in await inventory.list_groups()} == {"Core", "Access"}
        assert {t.name for t in await inventory.list_tags()} == {"dmz", "pci"}

    async def test_apply_refuses_an_invalid_preview(
        self, inventory: InventoryService, actor: Principal
    ) -> None:
        """All-or-nothing: a half-imported inventory is worse than a rejected one."""
        preview = await inventory.preview_import("mgmt_ip\nnonsense\n")

        with pytest.raises(ValidationProblem, match="validation errors"):
            await inventory.apply_import(preview, actor=actor)

        _, total = await inventory.list_devices(scope=Scope.all())
        assert total == 0


class TestCredentialVault:
    async def test_secret_is_sealed_and_openable(
        self, credentials: CredentialService, actor: Principal
    ) -> None:
        credential = await credentials.create(
            name="switch-ro",
            credential_type=CredentialType.SSH_PASSWORD,
            secret_data={"username": "ro", "password": "s3cret"},
            actor=actor,
        )

        assert b"s3cret" not in credential.encrypted_blob
        assert credentials.open_secret(credential) == {"password": "s3cret"}

    async def test_public_fields_stay_readable(
        self, credentials: CredentialService, actor: Principal
    ) -> None:
        credential = await credentials.create(
            name="switch-ro-2",
            credential_type=CredentialType.SSH_PASSWORD,
            secret_data={"username": "ro", "password": "s3cret"},
            actor=actor,
        )
        assert credential.metadata_ == {"username": "ro"}

    async def test_missing_required_field_is_refused(
        self, credentials: CredentialService, actor: Principal
    ) -> None:
        with pytest.raises(ValidationProblem, match="requires"):
            await credentials.create(
                name="incomplete",
                credential_type=CredentialType.SSH_PASSWORD,
                secret_data={"username": "ro"},
                actor=actor,
            )

    async def test_unknown_field_is_refused(
        self, credentials: CredentialService, actor: Principal
    ) -> None:
        """Stops a secret being smuggled into metadata under an unrecognised name."""
        with pytest.raises(ValidationProblem, match="Unexpected field"):
            await credentials.create(
                name="sneaky",
                credential_type=CredentialType.SSH_PASSWORD,
                secret_data={"username": "ro", "password": "p", "extra_secret": "leak"},
                actor=actor,
            )

    async def test_rotation_replaces_only_the_given_field(
        self, credentials: CredentialService, actor: Principal
    ) -> None:
        credential = await credentials.create(
            name="rotate-me",
            credential_type=CredentialType.SSH_PASSWORD,
            secret_data={"username": "ro", "password": "old"},
            actor=actor,
        )
        await credentials.update(credential, actor=actor, secret_data={"password": "new"})

        assert credentials.open_secret(credential) == {"password": "new"}
        assert credential.metadata_["username"] == "ro", "username should be preserved"

    async def test_duplicate_name_is_refused(
        self, credentials: CredentialService, actor: Principal
    ) -> None:
        for _ in range(1):
            await credentials.create(
                name="taken",
                credential_type=CredentialType.SNMP_V2C,
                secret_data={"community": "public"},
                actor=actor,
            )
        with pytest.raises(ConflictError, match="already exists"):
            await credentials.create(
                name="taken",
                credential_type=CredentialType.SNMP_V2C,
                secret_data={"community": "other"},
                actor=actor,
            )

    async def test_assigned_credential_cannot_be_deleted(
        self,
        credentials: CredentialService,
        inventory: InventoryService,
        actor: Principal,
    ) -> None:
        credential = await credentials.create(
            name="in-use",
            credential_type=CredentialType.SSH_PASSWORD,
            secret_data={"username": "ro", "password": "p"},
            actor=actor,
        )
        device = await inventory.create_device(mgmt_ip="192.0.2.50", actor=actor)
        await credentials.assign(credential, device_id=device.id, actor=actor)

        with pytest.raises(ConflictError, match="still assigned"):
            await credentials.delete(credential, actor=actor)

    async def test_assignment_needs_exactly_one_target(
        self, credentials: CredentialService, actor: Principal
    ) -> None:
        credential = await credentials.create(
            name="ambiguous",
            credential_type=CredentialType.SSH_PASSWORD,
            secret_data={"username": "ro", "password": "p"},
            actor=actor,
        )
        with pytest.raises(ValidationProblem, match="exactly one"):
            await credentials.assign(credential, actor=actor)


class TestReadingAssignments:
    """FR-CRED-04 — a binding that cannot be enumerated cannot be revoked.

    `unassign` takes an assignment id, and until this existed nothing emitted one except
    the response to the POST that created it. So an assignment made last month could not
    be withdrawn at all, and "which devices does this credential reach?" — the first
    question asked when a credential is suspected of being compromised — had no answer.
    """

    async def test_it_reports_both_device_and_group_bindings(
        self,
        credentials: CredentialService,
        inventory: InventoryService,
        actor: Principal,
        session: AsyncSession,
    ) -> None:
        group = await make_group(session, name="read-assign-group")
        device = await inventory.create_device(mgmt_ip="192.0.2.61", actor=actor)
        credential = await credentials.create(
            name="reachable",
            credential_type=CredentialType.SSH_PASSWORD,
            secret_data={"username": "ro", "password": "p"},
            actor=actor,
        )
        await credentials.assign(credential, group_id=group.id, actor=actor)
        await credentials.assign(credential, device_id=device.id, actor=actor)

        rows = await credentials.assignments(credential)

        assert {r.device_id for r in rows} == {device.id, None}
        assert {r.group_id for r in rows} == {group.id, None}

    async def test_device_bindings_are_listed_before_inherited_ones(
        self,
        credentials: CredentialService,
        inventory: InventoryService,
        actor: Principal,
        session: AsyncSession,
    ) -> None:
        """The list reads as the fallback order it governs, not an arbitrary set."""
        group = await make_group(session, name="order-group")
        device = await inventory.create_device(mgmt_ip="192.0.2.62", actor=actor)
        credential = await credentials.create(
            name="ordered",
            credential_type=CredentialType.SSH_PASSWORD,
            secret_data={"username": "ro", "password": "p"},
            actor=actor,
        )
        await credentials.assign(credential, group_id=group.id, actor=actor)
        await credentials.assign(credential, device_id=device.id, actor=actor)

        rows = await credentials.assignments(credential)

        assert rows[0].device_id == device.id, "the inherited binding was listed first"

    async def test_another_credentials_bindings_are_not_included(
        self,
        credentials: CredentialService,
        inventory: InventoryService,
        actor: Principal,
    ) -> None:
        device = await inventory.create_device(mgmt_ip="192.0.2.63", actor=actor)
        mine = await credentials.create(
            name="mine",
            credential_type=CredentialType.SSH_PASSWORD,
            secret_data={"username": "a", "password": "p"},
            actor=actor,
        )
        theirs = await credentials.create(
            name="theirs",
            credential_type=CredentialType.SSH_PASSWORD,
            secret_data={"username": "b", "password": "p"},
            actor=actor,
        )
        await credentials.assign(theirs, device_id=device.id, actor=actor)

        assert await credentials.assignments(mine) == []

    async def test_an_unassigned_credential_reports_nothing(
        self, credentials: CredentialService, actor: Principal
    ) -> None:
        """Which is the state a credential is in immediately after being stored.

        It reaches no device until it is bound, and a job against one of those devices
        fails with "no credential is assigned" rather than with an auth error.
        """
        credential = await credentials.create(
            name="unbound",
            credential_type=CredentialType.SSH_PASSWORD,
            secret_data={"username": "ro", "password": "p"},
            actor=actor,
        )

        assert await credentials.assignments(credential) == []


class TestCredentialResolution:
    """FR-CRED-04 — device assignments win; group ones are inherited."""

    async def test_device_assignment_comes_first(
        self,
        credentials: CredentialService,
        inventory: InventoryService,
        actor: Principal,
        session: AsyncSession,
    ) -> None:
        group = await make_group(session, name="creds-group")
        device = await inventory.create_device(
            mgmt_ip="192.0.2.51", actor=actor, group_ids=[group.id]
        )

        group_credential = await credentials.create(
            name="group-cred",
            credential_type=CredentialType.SSH_PASSWORD,
            secret_data={"username": "g", "password": "p"},
            actor=actor,
        )
        device_credential = await credentials.create(
            name="device-cred",
            credential_type=CredentialType.SSH_PASSWORD,
            secret_data={"username": "d", "password": "p"},
            actor=actor,
        )
        await credentials.assign(group_credential, group_id=group.id, actor=actor)
        await credentials.assign(device_credential, device_id=device.id, actor=actor)

        resolved = await credentials.resolve_for_device(device)

        assert [r.source for r in resolved] == ["device", "group"]
        assert resolved[0].credential.id == device_credential.id

    async def test_priority_orders_the_fallback_list(
        self,
        credentials: CredentialService,
        inventory: InventoryService,
        actor: Principal,
    ) -> None:
        device = await inventory.create_device(mgmt_ip="192.0.2.52", actor=actor)

        for name, priority in (("third", 30), ("first", 10), ("second", 20)):
            credential = await credentials.create(
                name=name,
                credential_type=CredentialType.SSH_PASSWORD,
                secret_data={"username": name, "password": "p"},
                actor=actor,
            )
            await credentials.assign(
                credential, device_id=device.id, priority=priority, actor=actor
            )

        resolved = await credentials.resolve_for_device(device)
        assert [r.credential.name for r in resolved] == ["first", "second", "third"]

    async def test_ancestor_group_credential_is_inherited(
        self,
        credentials: CredentialService,
        inventory: InventoryService,
        actor: Principal,
        session: AsyncSession,
    ) -> None:
        """A credential on a parent site applies to devices in its child racks."""
        site = await make_group(session, name="cred-site")
        rack = await make_group(session, name="cred-rack", parent=site)
        device = await inventory.create_device(
            mgmt_ip="192.0.2.53", actor=actor, group_ids=[rack.id]
        )

        credential = await credentials.create(
            name="site-wide",
            credential_type=CredentialType.SSH_PASSWORD,
            secret_data={"username": "ro", "password": "p"},
            actor=actor,
        )
        await credentials.assign(credential, group_id=site.id, actor=actor)

        resolved = await credentials.resolve_for_device(device)
        assert [r.credential.id for r in resolved] == [credential.id]

    async def test_device_with_no_credential_resolves_empty(
        self, credentials: CredentialService, inventory: InventoryService, actor: Principal
    ) -> None:
        device = await inventory.create_device(mgmt_ip="192.0.2.54", actor=actor)
        assert list(await credentials.resolve_for_device(device)) == []
