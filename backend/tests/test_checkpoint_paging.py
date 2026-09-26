"""Reading a whole Check Point rulebase, not the server's first page (FR-COL-08).

`show-access-rulebase` returns one page. Sending no `limit` gets the server's default,
so a large policy arrives truncated with nothing in the body looking wrong — which is
worse than an empty one. An empty rulebase is obviously broken and somebody
investigates; fifty rules out of five hundred analyse perfectly cleanly and produce a
confident report about a tenth of a firewall, every sentence of it true.

`rules_not_retrieved` already *detects* that. This is the other half: actually fetching
the rest.
"""

from __future__ import annotations

from typing import Any

import pytest

from netsecops.adapters.paging import MAX_PAGES, PagingError, fetch_all_pages
from netsecops.adapters.profiles import get_profile
from netsecops.adapters.readonly import _body_permitted


def server(total: int, page_size: int, *, objects_per_page: int | None = None):  # type: ignore[no-untyped-def]
    """A management server that pages honestly.

    Records the offsets it was asked for, so a test can assert the walk advanced the
    way the API documents rather than only that it arrived somewhere plausible.
    """
    asked: list[int] = []

    async def request(offset: int) -> dict[str, Any]:
        asked.append(offset)
        start = offset
        end = min(offset + page_size, total)
        return {
            "uid": "policy-uid",
            "name": "Corporate-Policy Network",
            "total": total,
            "from": start + 1,
            "to": end,
            "rulebase": [{"uid": f"rule-{n}", "type": "access-rule"} for n in range(start, end)],
            "objects-dictionary": [{"uid": f"obj-{offset}"}] * (objects_per_page or 1),
        }

    return request, asked


def test_a_paged_body_is_still_a_read() -> None:
    """Adding page parameters must not widen what the guard permits (SRS §8).

    `offset` and `limit` are read parameters, but the check that matters is that the
    body still satisfies the predicate that enforces the read-only guarantee, rather
    than that it looks harmless.
    """
    entry = next(
        command
        for command in get_profile("checkpoint_mgmt").commands
        if command.key_in_bundle() == "show-access-rulebase"
    )

    body = entry.as_body(offset=500)

    assert body == {"command": "show-access-rulebase", "limit": 500, "offset": 500}
    assert _body_permitted("checkpoint_show_only", body) is True


def test_an_unpaged_command_sends_exactly_what_it_sent_before() -> None:
    """No `offset: 0` appears on operations that do not page.

    An omitted parameter and a zero are not the same request to an API that does not
    document the parameter, and most of these operations do not.
    """
    entry = next(
        command
        for command in get_profile("checkpoint_mgmt").commands
        if command.key_in_bundle() == "show-administrators"
    )

    assert entry.as_body() == {"command": "show-administrators"}


@pytest.mark.asyncio
async def test_a_rulebase_that_fits_in_one_page_is_one_request() -> None:
    request, asked = server(total=40, page_size=500)

    merged = await fetch_all_pages(request, page_size=500)

    assert len(merged["rulebase"]) == 40
    assert asked == [0]


@pytest.mark.asyncio
async def test_every_rule_of_a_large_policy_arrives() -> None:
    """The case the whole change exists for: 1,200 rules behind a 500-rule page."""
    request, _asked = server(total=1200, page_size=500)

    merged = await fetch_all_pages(request, page_size=500)

    assert len(merged["rulebase"]) == 1200
    assert [rule["uid"] for rule in merged["rulebase"][:2]] == ["rule-0", "rule-1"]
    assert merged["rulebase"][-1]["uid"] == "rule-1199"


@pytest.mark.asyncio
async def test_the_cursor_follows_the_servers_own_position() -> None:
    """Advanced by `to`, never by the page size we asked for.

    Adding `limit` to the offset assumes the server returned exactly what was
    requested. When it does not — and Check Point's own guidance is that it may return
    less — that assumption skips rules silently.
    """
    request, asked = server(total=1200, page_size=500)

    await fetch_all_pages(request, page_size=500)

    assert asked == [0, 500, 1000]


def short_paging_server(total: int, returned: int):  # type: ignore[no-untyped-def]
    """A server that returns fewer objects per page than it was asked for.

    Check Point's own guidance says a page may come back smaller than the requested
    `limit`, and this is the case that tells the two possible cursor rules apart. With
    `offset = to` the walk is correct; with `offset += limit` it skips every rule
    between what arrived and what was asked for, which is a policy missing 400 rules in
    the middle while still reporting the right `total`.

    Without this, both rules behave identically and the test suite cannot see the
    difference — two mutations of the cursor arithmetic survived until it existed.
    """
    asked: list[int] = []

    async def request(offset: int) -> dict[str, Any]:
        asked.append(offset)
        end = min(offset + returned, total)
        return {
            "uid": "policy-uid",
            "total": total,
            "from": offset + 1,
            "to": end,
            "rulebase": [{"uid": f"rule-{n}", "type": "access-rule"} for n in range(offset, end)],
            "objects-dictionary": [],
        }

    return request, asked


@pytest.mark.asyncio
async def test_a_short_page_does_not_skip_the_rules_it_did_not_return() -> None:
    """Asked for 500, given 200: the next request must start at 200, not at 500."""
    request, asked = short_paging_server(total=1000, returned=200)

    merged = await fetch_all_pages(request, page_size=500)
    uids = [rule["uid"] for rule in merged["rulebase"]]

    assert asked == [0, 200, 400, 600, 800]
    assert len(uids) == 1000
    assert uids == [f"rule-{n}" for n in range(1000)]


@pytest.mark.asyncio
async def test_a_short_page_is_not_mistaken_for_the_end() -> None:
    """A page smaller than the limit means the server gave less, not that it finished.

    Stopping there would truncate the policy exactly as the unpaged request did, which
    is the thing being fixed.
    """
    request, _ = short_paging_server(total=1000, returned=200)

    merged = await fetch_all_pages(request, page_size=500)

    assert len(merged["rulebase"]) == 1000
    assert merged["total"] == 1000


@pytest.mark.asyncio
async def test_no_duplicate_rules_across_the_page_boundary() -> None:
    """Off-by-one in either direction is a wrong policy, not a slow one."""
    request, _ = server(total=1200, page_size=500)

    merged = await fetch_all_pages(request, page_size=500)
    uids = [rule["uid"] for rule in merged["rulebase"]]

    assert len(uids) == len(set(uids))


@pytest.mark.asyncio
async def test_the_rulebases_identity_comes_from_the_first_page_not_the_last() -> None:
    """`uid`, `name` and `total` describe the policy, not the page."""
    request, _ = server(total=1200, page_size=500)

    merged = await fetch_all_pages(request, page_size=500)

    assert merged["total"] == 1200
    assert merged["name"] == "Corporate-Policy Network"


@pytest.mark.asyncio
async def test_the_objects_dictionary_accumulates_too() -> None:
    """Rules reference objects by uid, and the definitions arrive page by page.

    Merging the rules without the dictionary would leave later rules referring to
    objects nothing defines, which resolves to an empty address set — a rule that
    permits nothing, where the device permits something.
    """
    request, _ = server(total=1200, page_size=500)

    merged = await fetch_all_pages(request, page_size=500)

    assert len(merged["objects-dictionary"]) == 3


@pytest.mark.asyncio
async def test_a_server_that_stops_advancing_raises() -> None:
    """The lesson the retired SNMP route walk left behind.

    That walk counted "a response arrived" as progress rather than "the cursor moved",
    so a stalling agent spent the whole budget and then reported a *truncated* table —
    a partial answer where it actually had a broken peer. A rulebase that stopped
    half-way is not a short rulebase, and must not be reported as one.
    """

    async def stuck(offset: int) -> dict[str, Any]:
        return {"total": 1200, "from": 1, "to": 500, "rulebase": [{"uid": "rule-0"}]}

    with pytest.raises(PagingError, match="did not advance"):
        await fetch_all_pages(stuck, page_size=500)


@pytest.mark.asyncio
async def test_a_server_that_never_reports_the_end_raises() -> None:
    """Rather than paging forever against a management server."""

    async def endless(offset: int) -> dict[str, Any]:
        return {
            "total": 10**9,
            "from": offset + 1,
            "to": offset + 500,
            "rulebase": [{"uid": f"rule-{offset}"}],
        }

    with pytest.raises(PagingError, match=f"{MAX_PAGES} pages"):
        await fetch_all_pages(endless, page_size=500)


@pytest.mark.asyncio
async def test_a_response_without_paging_fields_is_taken_as_complete() -> None:
    """An older server, or an operation that does not page.

    Taken as the whole answer rather than retried: the parser's own shortfall check
    still compares `total` against what it parsed, so a genuinely short response is
    still reported as short.
    """
    calls = 0

    async def unpaged(offset: int) -> dict[str, Any]:
        nonlocal calls
        calls += 1
        return {"rulebase": [{"uid": "rule-0"}], "objects-dictionary": []}

    merged = await fetch_all_pages(unpaged, page_size=500)

    assert calls == 1
    assert len(merged["rulebase"]) == 1
