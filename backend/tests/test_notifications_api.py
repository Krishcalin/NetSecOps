"""The notification and settings APIs (FR-INT-01, FR-ADM-01).

Two properties carry this file, and both are about what the API refuses.

A channel's secret must never come back out. A Slack incoming-webhook URL is a bearer
credential, so an endpoint that echoed it would turn everyone who can list channels into
someone who can post as NetSecOps — and it would look like a helpful feature.

A managed setting must not be writable. The forwarding watermarks live in the settings
table because that is what they are, but hand-editing one silently skips or repeats a
stretch of the audit trail, and neither leaves a trace.
"""

from __future__ import annotations

import pytest
from httpx import AsyncClient
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from netsecops.db.models.notifications import NotificationChannel
from netsecops.integrations.forwarding import WATERMARK_AUDIT

SLACK_URL = "https://hooks.slack.test/services/T000/B000/XXXXsecretXXXX"


@pytest.fixture
async def admin_client(client: AsyncClient, authenticate, super_admin) -> AsyncClient:
    """The API as the platform owner.

    Uses the principal override rather than logging in: the login flow has its own tests,
    and these should not fail for a reason that has nothing to do with notifications.
    """
    authenticate(super_admin)
    return client


async def make_channel(client: AsyncClient, *, name: str = "ops-slack") -> dict:
    response = await client.post(
        "/api/v1/notifications/channels",
        json={
            "name": name,
            "channel_type": "slack",
            "config": {"workspace": "ops"},
            "secret": {"url": SLACK_URL},
        },
    )
    assert response.status_code == 201, response.text
    return response.json()


class TestChannelSecrets:
    async def test_the_secret_is_not_echoed_on_create(self, admin_client: AsyncClient) -> None:
        body = await make_channel(admin_client)
        assert SLACK_URL not in str(body)
        assert body["has_secret"] is True

    async def test_the_secret_is_not_in_the_list(self, admin_client: AsyncClient) -> None:
        await make_channel(admin_client)
        response = await admin_client.get("/api/v1/notifications/channels")

        assert response.status_code == 200
        assert SLACK_URL not in response.text

    async def test_it_is_actually_stored_sealed(
        self, admin_client: AsyncClient, session: AsyncSession
    ) -> None:
        # Not merely omitted from the response: the bytes in the row must not be the URL.
        await make_channel(admin_client)
        row = (await session.execute(select(NotificationChannel))).scalars().first()

        assert row is not None
        assert row.encrypted_blob is not None
        assert SLACK_URL.encode() not in row.encrypted_blob
        assert row.key_id

    async def test_the_non_secret_config_is_returned(self, admin_client: AsyncClient) -> None:
        # The other half of the contract: config is for things that may be shown.
        body = await make_channel(admin_client)
        assert body["config"] == {"workspace": "ops"}


class TestChannelLifecycle:
    async def test_a_channel_can_be_disabled(self, admin_client: AsyncClient) -> None:
        channel = await make_channel(admin_client)
        response = await admin_client.patch(
            f"/api/v1/notifications/channels/{channel['id']}", json={"enabled": False}
        )
        assert response.status_code == 200
        assert response.json()["enabled"] is False

    async def test_updating_without_a_secret_keeps_the_stored_one(
        self, admin_client: AsyncClient
    ) -> None:
        # Otherwise renaming a channel silently unsets its credential.
        channel = await make_channel(admin_client)
        response = await admin_client.patch(
            f"/api/v1/notifications/channels/{channel['id']}", json={"name": "renamed"}
        )
        assert response.json()["has_secret"] is True

    async def test_a_test_notification_goes_through_the_real_queue(
        self, admin_client: AsyncClient
    ) -> None:
        """Queued, not sent inline.

        Sending here would exercise a different path from real notifications, so a test
        that passed would prove very little.
        """
        channel = await make_channel(admin_client)
        response = await admin_client.post(f"/api/v1/notifications/channels/{channel['id']}/test")

        assert response.status_code == 202
        assert response.json()["status"] == "queued"

        listed = await admin_client.get("/api/v1/notifications/deliveries")
        assert len(listed.json()) == 1

    async def test_a_subscription_needs_a_real_channel(self, admin_client: AsyncClient) -> None:
        import uuid

        response = await admin_client.post(
            "/api/v1/notifications/subscriptions",
            json={"channel_id": str(uuid.uuid4()), "min_severity": "high"},
        )
        assert response.status_code == 404

    async def test_deleting_a_channel_takes_its_subscriptions(
        self, admin_client: AsyncClient
    ) -> None:
        channel = await make_channel(admin_client)
        await admin_client.post(
            "/api/v1/notifications/subscriptions",
            json={"channel_id": channel["id"], "min_severity": "high"},
        )

        await admin_client.delete(f"/api/v1/notifications/channels/{channel['id']}")
        remaining = await admin_client.get("/api/v1/notifications/subscriptions")
        assert remaining.json() == []


class TestSettings:
    async def test_a_setting_round_trips(self, admin_client: AsyncClient) -> None:
        put = await admin_client.put(
            "/api/v1/settings/retention.snapshots",
            json={"value": {"days": 365}, "description": "How long snapshots are kept"},
        )
        assert put.status_code == 200

        got = await admin_client.get("/api/v1/settings/retention.snapshots")
        assert got.json()["value"] == {"days": 365}

    async def test_a_managed_watermark_is_refused_with_a_reason(
        self, admin_client: AsyncClient, session: AsyncSession
    ) -> None:
        """Editing one silently skips or repeats part of the forwarded stream."""
        response = await admin_client.put(
            f"/api/v1/settings/{WATERMARK_AUDIT}", json={"value": {"at": 0}}
        )

        assert response.status_code == 422
        assert "maintained by NetSecOps" in response.text

    async def test_a_managed_setting_is_still_readable_and_flagged(
        self, admin_client: AsyncClient, session: AsyncSession
    ) -> None:
        # Refusing the write must not mean hiding the value: an operator debugging
        # forwarding needs to see where it has reached.
        from netsecops.db.models.audit import Setting

        session.add(Setting(org_id=1, key=WATERMARK_AUDIT, value={"at": 42}))
        await session.flush()

        response = await admin_client.get(f"/api/v1/settings/{WATERMARK_AUDIT}")
        assert response.json()["managed"] is True
        assert response.json()["value"] == {"at": 42}

    async def test_an_unknown_setting_is_not_found(self, admin_client: AsyncClient) -> None:
        assert (await admin_client.get("/api/v1/settings/nope")).status_code == 404
