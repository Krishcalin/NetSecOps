"""Fetching feeds over the network (FR-VUL-07).

Every request in this file is served by `httpx.MockTransport`. Nothing here reaches CISA,
FIRST or NVD: a test suite that hammered three free public services on every CI run would
be rude, flaky, and would fail in exactly the environment the product is most often
deployed into.

The assertions are shaped around the ways this can be wrong *quietly*. A feed subsystem
that raises is fine — somebody fixes it. A feed subsystem that reports success while
having fetched nothing, or having skipped three months of revisions, produces a
vulnerability page that looks clean because it is empty.
"""

from __future__ import annotations

import gzip
import json
from datetime import UTC, datetime, timedelta

import httpx
import pytest

from netsecops.core.config import Settings
from netsecops.vuln.fetch import (
    DEFAULT_SOURCES,
    MAX_NVD_PAGES,
    MAX_NVD_WINDOW,
    MAX_RESPONSE_BYTES,
    FeedFetchError,
    fetch_nvd,
    fetch_simple,
)


def settings(**overrides) -> Settings:
    base = {
        "secret_key": "x" * 48,
        "master_key": "y" * 48,
        "database_url": "postgresql+asyncpg://u:p@localhost/db",
    }
    return Settings(**{**base, **overrides})


def client_returning(handler) -> httpx.AsyncClient:
    return httpx.AsyncClient(transport=httpx.MockTransport(handler))


def always(status: int = 200, content: bytes = b"{}"):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(status, content=content)

    return handler


# ───────────────────────── the air-gap guarantee ─────────────────────────


class TestOfflineModeRefuses:
    """C-7, as a switch. The single most important behaviour in this module."""

    async def test_a_simple_fetch_refuses(self) -> None:
        with pytest.raises(FeedFetchError) as caught:
            await fetch_simple(DEFAULT_SOURCES["kev"], settings(feeds_offline_mode=True))

        assert "offline feed mode" in str(caught.value)

    async def test_nvd_refuses(self) -> None:
        with pytest.raises(FeedFetchError):
            await fetch_nvd(settings(feeds_offline_mode=True))

    async def test_it_raises_rather_than_returning_nothing(self) -> None:
        """A silent no-op is the failure this exists to prevent.

        Returning `b""` would import cleanly as zero records, mark the sync succeeded, and
        leave an air-gapped operator believing their feeds are current. Raising surfaces
        as a failed sync with a stated reason, which is what they need to see.
        """
        request_made = False

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal request_made
            request_made = True
            return httpx.Response(200, content=b"{}")

        with pytest.raises(FeedFetchError):
            await fetch_simple(
                DEFAULT_SOURCES["kev"],
                settings(feeds_offline_mode=True),
                client=client_returning(handler),
            )
        assert request_made is False, "offline mode still sent a request"


# ──────────────────────────── single-file feeds ──────────────────────────


class TestFetchSimple:
    async def test_it_returns_the_body_unchanged(self) -> None:
        payload = json.dumps({"vulnerabilities": [], "catalogVersion": "2026.09.18"}).encode()
        raw = await fetch_simple(
            DEFAULT_SOURCES["kev"], settings(), client=client_returning(always(content=payload))
        )
        assert raw == payload

    async def test_gzip_is_passed_through_undecompressed(self) -> None:
        # The EPSS reader decompresses. Doing it here too would hand the importer
        # something different from what an uploaded bundle looks like, which is the exact
        # divergence between the online and offline paths this design forbids.
        body = gzip.compress(b"cve,epss,percentile\nCVE-2026-1,0.5,0.9\n")
        raw = await fetch_simple(
            DEFAULT_SOURCES["epss"], settings(), client=client_returning(always(content=body))
        )
        assert raw[:2] == b"\x1f\x8b"

    async def test_an_error_status_names_the_cause(self) -> None:
        with pytest.raises(FeedFetchError) as caught:
            await fetch_simple(
                DEFAULT_SOURCES["kev"], settings(), client=client_returning(always(503))
            )
        assert "503" in str(caught.value)

    @pytest.mark.parametrize("status", [403, 429])
    async def test_rate_limiting_suggests_the_api_key(self, status: int) -> None:
        # The actionable half. "403" alone sends somebody to check their firewall; NVD
        # throttling unauthenticated clients is the actual cause almost every time.
        with pytest.raises(FeedFetchError) as caught:
            await fetch_simple(
                DEFAULT_SOURCES["nvd"], settings(), client=client_returning(always(status))
            )
        assert "NVD_API_KEY" in str(caught.value)

    async def test_an_oversized_body_is_refused(self) -> None:
        oversized = b"x" * (MAX_RESPONSE_BYTES + 1)
        with pytest.raises(FeedFetchError) as caught:
            await fetch_simple(
                DEFAULT_SOURCES["kev"],
                settings(),
                client=client_returning(always(content=oversized)),
            )
        assert "limit" in str(caught.value)

    async def test_a_transport_failure_is_reported_not_raised_raw(self) -> None:
        def handler(request: httpx.Request) -> httpx.Response:
            raise httpx.ConnectError("no route to host", request=request)

        with pytest.raises(FeedFetchError) as caught:
            await fetch_simple(
                DEFAULT_SOURCES["kev"], settings(), client=client_returning(handler)
            )
        assert "Could not reach" in str(caught.value)


# ──────────────────────────────── NVD paging ─────────────────────────────


def nvd_pages(total: int, page_size: int = 2_000):
    """A handler serving `total` CVEs across as many pages as that takes."""

    def handler(request: httpx.Request) -> httpx.Response:
        start = int(request.url.params.get("startIndex", 0))
        count = max(0, min(page_size, total - start))
        return httpx.Response(
            200,
            json={
                "resultsPerPage": count,
                "startIndex": start,
                "totalResults": total,
                "vulnerabilities": [
                    {"cve": {"id": f"CVE-2026-{start + i}"}} for i in range(count)
                ],
            },
        )

    return handler


class TestFetchNvd:
    async def test_a_single_page_comes_back_whole(self) -> None:
        raw = await fetch_nvd(settings(), client=client_returning(nvd_pages(5)))
        assert len(json.loads(raw)["vulnerabilities"]) == 5

    async def test_pages_are_merged_into_one_payload(self) -> None:
        # One `feed_syncs` row per sync, not per page — and the existing NVD reader gets
        # the shape it already understands rather than a new one.
        raw = await fetch_nvd(settings(), client=client_returning(nvd_pages(4_500)))
        payload = json.loads(raw)

        assert len(payload["vulnerabilities"]) == 4_500
        assert payload["totalResults"] == 4_500
        assert {c["cve"]["id"] for c in payload["vulnerabilities"][:1]} == {"CVE-2026-0"}

    async def test_it_asks_for_the_window_it_was_given(self) -> None:
        seen: list[httpx.QueryParams] = []

        def handler(request: httpx.Request) -> httpx.Response:
            seen.append(request.url.params)
            return httpx.Response(
                200, json={"totalResults": 0, "vulnerabilities": [], "startIndex": 0}
            )

        now = datetime(2026, 9, 18, 12, 0, tzinfo=UTC)
        since = now - timedelta(days=3)
        await fetch_nvd(settings(), since=since, now=now, client=client_returning(handler))

        assert seen[0]["lastModStartDate"].startswith("2026-09-15")
        assert seen[0]["lastModEndDate"].startswith("2026-09-18")

    async def test_a_window_wider_than_nvd_allows_is_clamped(self) -> None:
        # NVD rejects a window over 120 days outright, so an un-clamped request returns
        # nothing at all — a sync that silently imports zero.
        seen: list[httpx.QueryParams] = []

        def handler(request: httpx.Request) -> httpx.Response:
            seen.append(request.url.params)
            return httpx.Response(
                200, json={"totalResults": 0, "vulnerabilities": [], "startIndex": 0}
            )

        now = datetime(2026, 9, 18, 12, 0, tzinfo=UTC)
        await fetch_nvd(
            settings(),
            since=now - timedelta(days=400),
            now=now,
            client=client_returning(handler),
        )

        start = datetime.fromisoformat(seen[0]["lastModStartDate"]).replace(tzinfo=UTC)
        assert now - start <= MAX_NVD_WINDOW

    async def test_paging_stops_at_the_cap(self) -> None:
        # Guards against a misconfigured window turning a nightly sync into a full
        # re-download. The cap must bind before the pages run out.
        calls = 0

        def handler(request: httpx.Request) -> httpx.Response:
            nonlocal calls
            calls += 1
            start = int(request.url.params.get("startIndex", 0))
            return httpx.Response(
                200,
                json={
                    "resultsPerPage": 2_000,
                    "startIndex": start,
                    "totalResults": 10_000_000,
                    "vulnerabilities": [{"cve": {"id": f"CVE-2026-{start}"}}] * 2_000,
                },
            )

        await fetch_nvd(settings(), client=client_returning(handler))
        assert calls == MAX_NVD_PAGES

    async def test_a_non_json_body_is_reported_clearly(self) -> None:
        with pytest.raises(FeedFetchError) as caught:
            await fetch_nvd(
                settings(), client=client_returning(always(content=b"<html>down</html>"))
            )
        assert "not JSON" in str(caught.value)

    async def test_the_api_key_is_sent_when_configured(self) -> None:
        seen: list[str | None] = []

        def handler(request: httpx.Request) -> httpx.Response:
            seen.append(request.headers.get("apiKey"))
            return httpx.Response(
                200, json={"totalResults": 0, "vulnerabilities": [], "startIndex": 0}
            )

        await fetch_nvd(settings(nvd_api_key="secret-key"), client=client_returning(handler))
        assert seen == ["secret-key"]

    async def test_a_mirror_url_is_honoured(self) -> None:
        # The estates that most need current feed data are often the ones whose workers
        # have no egress; pointing at an internal mirror is how they square that.
        seen: list[str] = []

        def handler(request: httpx.Request) -> httpx.Response:
            seen.append(str(request.url.copy_with(query=None)))
            return httpx.Response(
                200, json={"totalResults": 0, "vulnerabilities": [], "startIndex": 0}
            )

        await fetch_nvd(
            settings(nvd_api_url="https://mirror.internal/nvd/2.0"),
            client=client_returning(handler),
        )
        assert seen[0] == "https://mirror.internal/nvd/2.0"
