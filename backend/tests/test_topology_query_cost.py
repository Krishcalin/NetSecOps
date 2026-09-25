"""Building the graph must not cost a query per device (NFR-PERF-01).

`TopologyService._nodes` fetched every active device, then ran a separate query inside the
loop for each one's latest snapshot. On the 2,000-device tier this product publishes
sizing for that is 2,001 round trips to answer one path question — and each of those rows
carried `config_redacted`, the entire running configuration, which nothing in the graph
reads. The graph needs two columns per device: the snapshot's id and its NCM.

The assertion is deliberately a *comparison* rather than a fixed number. Pinning "six
queries" would fail on any unrelated refactor and teach nobody anything; asserting that
four devices cost the same as one is the actual property — no work proportional to the
size of the estate.

Timing is not asserted at all. This machine's DB-heavy timings vary by more than the
effect being measured, and a query count is exact on any hardware.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from typing import Any

import pytest
from sqlalchemy import event
from sqlalchemy.ext.asyncio import AsyncSession

from netsecops.core.rbac import Principal, Role, Scope
from netsecops.db.models import User
from netsecops.services.topology import TopologyService
from tests.conftest import make_user
from tests.test_topology_api import add_device, static


@pytest.fixture
async def actor(session: AsyncSession) -> Principal:
    user: User = await make_user(session, username="topo_cost", roles={Role.SECURITY_ANALYST})
    return Principal(id=user.id, username=user.username, roles=user.role_set, scope=Scope.all())


@contextmanager
def counted(session: AsyncSession) -> Iterator[list[str]]:
    """Record every statement the session issues inside the block."""
    statements: list[str] = []
    # The test session is bound to a Connection rather than an Engine, because the
    # fixture wraps each test in a transaction it rolls back. The event works on either.
    bind = session.get_bind()

    def before(conn: Any, cursor: Any, statement: str, *_: Any) -> None:
        statements.append(statement)

    event.listen(bind, "before_cursor_execute", before)
    try:
        yield statements
    finally:
        event.remove(bind, "before_cursor_execute", before)


async def estate(session: AsyncSession, actor: Principal, *, count: int, offset: int) -> None:
    for index in range(count):
        number = offset + index
        await add_device(
            session,
            actor,
            hostname=f"cost-{number:03d}",
            mgmt_ip=f"10.80.{number // 250}.{number % 250 + 1}",
            ncm_body={
                "ncm_version": "1.1",
                "routing": {"routes": [static("10.0.0.0/8", via="10.80.0.254")]},
                "interfaces": [{"name": "outside", "ip_addresses": ["10.80.0.1/24"]}],
            },
        )


class TestGraphQueryCost:
    async def test_the_query_count_does_not_grow_with_the_estate(
        self, session: AsyncSession, actor: Principal
    ) -> None:
        """The regression: this was one query per device, plus one.

        Four devices against one. Before the fix that is a difference of three; after it,
        zero — the snapshots arrive in a single `DISTINCT ON` regardless of how many
        devices there are.
        """
        await estate(session, actor, count=1, offset=0)
        with counted(session) as small:
            await TopologyService(session).graph()

        await estate(session, actor, count=3, offset=1)
        with counted(session) as larger:
            await TopologyService(session).graph()

        assert len(larger) == len(small), (
            f"building the graph cost {len(small)} queries for 1 device and "
            f"{len(larger)} for 4. A query per device means a 2,000-device estate "
            "makes 2,001 round trips to answer one path question.\n"
            + "\n".join(f"  {s.splitlines()[0][:100]}" for s in larger)
        )

    async def test_the_configuration_text_is_not_fetched(
        self, session: AsyncSession, actor: Principal
    ) -> None:
        """`config_redacted` is the largest column in the schema and the graph never reads it.

        Loading it for every device is invisible in a test that only checks correctness,
        and is most of the memory a large graph build would hold.
        """
        await estate(session, actor, count=2, offset=10)

        with counted(session) as statements:
            await TopologyService(session).graph()

        selected = " ".join(statements).lower()
        assert "config_redacted" not in selected

    async def test_the_graph_is_still_correct(
        self, session: AsyncSession, actor: Principal
    ) -> None:
        """A faster wrong answer is not the goal.

        `DISTINCT ON` must return each device's *latest* snapshot, and a device without
        one must still become a node — it is what the missing-device report points at.
        """
        await estate(session, actor, count=2, offset=20)
        await add_device(session, actor, hostname="cost-nosnap", mgmt_ip="10.81.0.1", ncm_body=None)

        graph = await TopologyService(session).graph()
        nodes = {node.hostname: node for node in graph.nodes.values()}

        assert "cost-nosnap" in nodes
        assert nodes["cost-nosnap"].snapshot_id is None
        assert nodes["cost-nosnap"].ncm_version is None
        assert nodes["cost-020"].routes, "a device with a snapshot must carry its routes"
