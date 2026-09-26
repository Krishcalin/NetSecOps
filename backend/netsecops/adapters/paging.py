"""Paged reads from the Check Point Management API (FR-COL-08).

`show-access-rulebase` and `show-nat-rulebase` return one page. A request that sends no
`limit` gets the server's default, so a large policy arrives truncated with nothing in
the body looking wrong — fifty rules out of five hundred analyse perfectly cleanly and
produce a confident report about a tenth of a firewall.

The API pages with `offset` and `limit` (1–500) and answers with `from`, `to` and
`total`. This walks that until the server says it has nothing further, and merges the
pages into the single response shape the parser already understands.

**The cursor advances by the server's own `to`, never by our page size.** Adding `limit`
to an offset assumes the server returned exactly what was asked for, which is the sort
of assumption that silently skips a rule when it does not hold. `to` is what the server
says it actually reached.

**A server that stops advancing ends the walk.** This is the lesson the SNMP route walk
left behind before it was retired: it counted "a response arrived" as progress rather
than "the cursor moved", so a stalling agent would have spent the whole budget and then
reported a *truncated* table — a partial answer where it really had a broken peer. Here
that case raises, because a rulebase that stopped mid-way is not a short rulebase.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any, Final

from netsecops.core.logging import get_logger

log = get_logger(__name__)

#: Refuse to page forever. At the 500 maximum this is 100,000 rules, which is far past
#: any real policy and well past the 5,000 the README targets.
MAX_PAGES: Final[int] = 200

#: The keys whose lists are concatenated across pages. Everything else is taken from
#: the first page, because it describes the rulebase rather than the page: `uid`,
#: `name` and `total` are the same in every response.
_MERGED: Final[tuple[str, ...]] = ("rulebase", "objects-dictionary")


class PagingError(RuntimeError):
    """The server stopped making progress before delivering the whole rulebase."""


def _as_int(value: Any) -> int | None:
    return value if isinstance(value, int) and not isinstance(value, bool) else None


async def fetch_all_pages(
    request: Callable[[int], Awaitable[dict[str, Any]]],
    *,
    page_size: int,
    operation: str = "rulebase",
) -> dict[str, Any]:
    """Read every page and return them merged into one response.

    ``request`` is called with an offset and returns one decoded response body.
    """
    merged: dict[str, Any] = {}
    offset = 0
    pages = 0

    for _attempt in range(MAX_PAGES):
        page = await request(offset)
        pages += 1

        if not merged:
            # The first page carries the identity of the rulebase itself.
            merged = {key: value for key, value in page.items() if key not in _MERGED}
            for key in _MERGED:
                merged[key] = list(page.get(key) or [])
        else:
            for key in _MERGED:
                extend = page.get(key)
                if isinstance(extend, list):
                    existing = merged.setdefault(key, [])
                    if isinstance(existing, list):
                        existing.extend(extend)

        total = _as_int(page.get("total"))
        to = _as_int(page.get("to"))

        if total is None or to is None:
            # An unpaged response, or one from a server that does not report its
            # position. One page is all there is to have, and the parser's own
            # shortfall check still compares `total` against what it parsed.
            break

        if to >= total:
            break

        if to <= offset:
            raise PagingError(
                f"{operation}: the management server reported reaching object {to} of "
                f"{total} but the cursor did not advance past {offset}, so the rest of "
                f"the policy cannot be read."
            )

        offset = to
    else:
        raise PagingError(
            f"{operation}: stopped after {MAX_PAGES} pages of {page_size} without the "
            f"server reporting the end of the rulebase."
        )

    log.info(
        "collect.rulebase_paged",
        operation=operation,
        pages=pages,
        rules=len(merged.get("rulebase") or []),
        total=merged.get("total"),
    )
    return merged


__all__ = ["MAX_PAGES", "PagingError", "fetch_all_pages"]
