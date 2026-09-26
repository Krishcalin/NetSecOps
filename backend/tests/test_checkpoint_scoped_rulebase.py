"""The rulebase query has to name a policy (FR-COL-08, FR-FW-01).

`show-access-rulebase` takes the access layer as `name` and `show-nat-rulebase` takes
the `package`. Every one of Check Point's published examples passes them. NetSecOps
passed neither — it sent `{"command": ..., "limit": 500, "offset": 0}` and named no
policy at all, so the request was very likely rejected and the pagination around it read
nothing.

Both names are the customer's, so neither can be declared in a profile. They are
discovered from the management server — `show-access-layers` and `show-packages`, which
page with the same `limit`/`offset`/`from`/`to`/`total` contract — and the operation is
then issued once per name.

**Each layer's rules carry the layer they came from.** A combined response holds only
the first layer's `name`, so without a per-rule tag every rule would be filed under one
layer, and the analyser — which compares rules sharing an enforcement context — would
report shadowing between two policies that never see the same packet.
"""

from __future__ import annotations

import json
from typing import Any

import pytest

from netsecops.adapters.paging import PAGED_COLLECTIONS, PagingError, fetch_all_pages
from netsecops.adapters.profiles import get_profile
from netsecops.parsers.base import ParseContext
from netsecops.parsers.checkpoint.mgmt import SCOPE_KEY
from netsecops.parsers.registry import get_parser


def command(operation: str):  # type: ignore[no-untyped-def]
    return next(
        c for c in get_profile("checkpoint_mgmt").commands if c.key_in_bundle() == operation
    )


# ── the request body ────────────────────────────────────────────────────────


def test_the_access_rulebase_names_its_layer() -> None:
    body = command("show-access-rulebase").as_body(offset=0, scope={"name": "Network"})

    assert body == {
        "command": "show-access-rulebase",
        "limit": 500,
        "offset": 0,
        "name": "Network",
    }


def test_the_nat_rulebase_names_its_package() -> None:
    body = command("show-nat-rulebase").as_body(offset=500, scope={"package": "Standard"})

    assert body == {
        "command": "show-nat-rulebase",
        "limit": 500,
        "offset": 500,
        "package": "Standard",
    }


def test_both_rulebase_commands_declare_what_scopes_them() -> None:
    """Without this the collector silently falls back to the unscoped request.

    Which is the defect: a request naming no policy, which reads as a plain paged
    fetch and returns nothing.
    """
    assert command("show-access-rulebase").scoped_by == (
        "name",
        "show-access-layers",
        "access-layers",
    )
    assert command("show-nat-rulebase").scoped_by == ("package", "show-packages", "packages")


def test_unscoped_commands_are_unchanged() -> None:
    assert command("show-administrators").as_body() == {"command": "show-administrators"}


# ── discovery paging ────────────────────────────────────────────────────────


def layers_server(names: list[str], page: int = 2):  # type: ignore[no-untyped-def]
    asked: list[int] = []

    async def request(offset: int) -> dict[str, Any]:
        asked.append(offset)
        end = min(offset + page, len(names))
        return {
            "access-layers": [{"uid": f"u{i}", "name": names[i]} for i in range(offset, end)],
            "from": offset + 1,
            "to": end,
            "total": len(names),
        }

    return request, asked


@pytest.mark.asyncio
async def test_layer_discovery_pages_to_the_end() -> None:
    """A management server with more layers than one page holds loses none of them."""
    request, asked = layers_server(["A", "B", "C", "D", "E"])

    merged = await fetch_all_pages(request, page_size=2, operation="show-access-layers")

    assert [entry["name"] for entry in merged["access-layers"]] == ["A", "B", "C", "D", "E"]
    assert asked == [0, 2, 4]


def test_each_paged_operation_declares_its_list_key() -> None:
    """A missing entry pages into nothing, which is the failure mode being avoided.

    `show-access-layers` answers under `access-layers` and `show-packages` under
    `packages` — not under `rulebase`, which is what the merge defaults to.
    """
    assert PAGED_COLLECTIONS["show-access-layers"] == ("access-layers",)
    assert PAGED_COLLECTIONS["show-packages"] == ("packages",)
    assert PAGED_COLLECTIONS["show-access-rulebase"] == ("rulebase", "objects-dictionary")


@pytest.mark.asyncio
async def test_a_discovery_server_that_stalls_raises() -> None:
    async def stuck(offset: int) -> dict[str, Any]:
        return {"access-layers": [{"name": "A"}], "from": 1, "to": 2, "total": 99}

    with pytest.raises(PagingError, match="did not advance"):
        await fetch_all_pages(stuck, page_size=2, operation="show-access-layers")


# ── the layer tag ───────────────────────────────────────────────────────────


def rule(name: str, scope: str | None) -> dict[str, Any]:
    entry: dict[str, Any] = {
        "type": "access-rule",
        "name": name,
        "enabled": True,
        "action": {"name": "Accept"},
        "source": [{"name": "Any"}],
        "destination": [{"name": "Any"}],
        "service": [{"name": "Any"}],
    }
    if scope is not None:
        entry[SCOPE_KEY] = scope
    return entry


def parse_bundle(rules: list[dict[str, Any]], response_name: str | None = None) -> Any:
    response: dict[str, Any] = {"rulebase": rules, "total": len(rules)}
    if response_name is not None:
        response["name"] = response_name
    bundle = {"show-access-rulebase": response}
    return get_parser("checkpoint_mgmt").parse(ParseContext(text=json.dumps(bundle)))


def test_rules_are_filed_under_the_layer_they_came_from() -> None:
    """The reason the tag exists.

    Two layers merged into one response, which carries only one `name`. Without the
    per-rule tag both rules land in the same enforcement context and the analyser
    compares policies that never meet.
    """
    ncm = parse_bundle([rule("a", "Network"), rule("b", "DMZ")], response_name="Network")

    zones = [r.src_zones for r in ncm.firewall.security_rules]
    assert zones == [["Network"], ["DMZ"]]


def test_every_layer_is_recorded_as_a_zone() -> None:
    ncm = parse_bundle([rule("a", "Network"), rule("b", "DMZ")], response_name="Network")

    assert set(ncm.firewall.zones) == {"Network", "DMZ"}


def test_an_untagged_rule_falls_back_to_the_response_name() -> None:
    """An offline bundle somebody uploaded, or a single-layer fetch.

    The tag is ours; a response that never went through our collector will not carry
    it, and that must still parse rather than losing the layer entirely.
    """
    ncm = parse_bundle([rule("a", None)], response_name="Network")

    assert ncm.firewall.security_rules[0].src_zones == ["Network"]


def test_no_layer_anywhere_leaves_the_rule_unzoned() -> None:
    """None, not an invented name."""
    ncm = parse_bundle([rule("a", None)])

    assert ncm.firewall.security_rules[0].src_zones == []
