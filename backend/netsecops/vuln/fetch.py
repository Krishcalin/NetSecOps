"""Fetching feed bundles over the network (FR-VUL-07).

The offline path came first and stays primary (C-7, FR-VUL-08). This module is the later
convenience, and it is deliberately shaped so that it **produces the same bytes an
operator would have carried in on a USB stick** — it fetches, and nothing else. Parsing,
counting, rejection accounting and the `feed_syncs` row all stay in `services.feeds`, on
exactly the code path an uploaded bundle takes.

That constraint is the whole design. If online sync had its own ingest, the two would
drift: the offline path is the one air-gapped customers run and the online path is the one
developers exercise, so the tested one and the shipped-to-the-hardest-customer one would
be different code. Here they differ only in where the bytes came from, which is recorded
as the sync's `mode`.

**Offline mode refuses loudly.** When `feeds_offline_mode` is set, every function here
raises rather than returning nothing. A silent no-op would leave an air-gapped deployment
with a scheduled sync that appears configured, never runs, and reports no error — which
is precisely the stale-feed-that-looks-fresh failure the whole feed subsystem is built to
avoid.

**Nothing here is trusted because it arrived over TLS.** The payloads are parsed by the
same readers that handle uploads, which reject what they cannot understand rather than
guessing. TLS authenticates the server; it says nothing about whether the body is the
shape we expect.
"""

from __future__ import annotations

import json
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from typing import Any, Final

import httpx

from netsecops.core.config import Settings
from netsecops.core.errors import ValidationProblem
from netsecops.core.logging import get_logger

log = get_logger(__name__)

#: Longest a single request may take. Feeds are large and occasionally slow; a worker
#: blocked forever on one is worse than a sync that fails and is retried tomorrow.
REQUEST_TIMEOUT: Final[float] = 120.0

#: Most bytes accepted from one response.
#:
#: EPSS is the largest at roughly 4 MB gzipped, so this is ample. It exists because an
#: unbounded read of a redirected or misconfigured URL is how a worker dies of memory
#: exhaustion while looking like a network problem.
MAX_RESPONSE_BYTES: Final[int] = 512 * 1024 * 1024

#: NVD returns 2,000 CVEs per page and this caps how many pages one sync will walk.
#:
#: 60 pages is 120,000 CVEs — far beyond any incremental window, and a deliberate stop
#: before a misconfigured `since` turns a daily sync into a full re-download of the
#: corpus. Hitting it is recorded, not silently truncated: the next sync resumes from
#: where this one reached.
MAX_NVD_PAGES: Final[int] = 60

#: NVD rejects a `lastModStartDate` window wider than 120 days.
MAX_NVD_WINDOW: Final[timedelta] = timedelta(days=119)

NVD_PAGE_SIZE: Final[int] = 2_000


@dataclass(frozen=True, slots=True)
class FeedSource:
    """Where one feed comes from.

    URLs are data rather than literals in the fetch functions so that a deployment can
    point at an internal mirror. That is not hypothetical: the estates that most want
    current vulnerability data are frequently the ones whose workers have no direct
    egress, and a mirror is how they square that.
    """

    name: str
    url: str
    purpose: str


#: The three feeds that are global, free and fetchable without a contract.
#:
#: Vendor PSIRT feeds (FR-VUL-02) are absent on purpose, but not for the reason this
#: comment used to give. Cisco's openVuln API does need an OAuth client credential.
#: Palo Alto does *not* need an index walk and does not publish CSAF at all:
#: `security.paloaltonetworks.com/json` returns the whole corpus unauthenticated with
#: `affected` and `fixed`, in CVE Record v5.0, and that host has no
#: `/.well-known/csaf/provider-metadata.json`. So adding Palo Alto is smaller work than
#: recorded here — a fetch and a schema guard, the API being marked Beta. The Fortinet
#: and Check Point halves of the original claim remain unverified.
DEFAULT_SOURCES: Final[dict[str, FeedSource]] = {
    "kev": FeedSource(
        name="kev",
        url="https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        purpose="CISA Known Exploited Vulnerabilities — what is being attacked right now",
    ),
    "epss": FeedSource(
        name="epss",
        url="https://epss.cyentia.com/epss_scores-current.csv.gz",
        purpose="FIRST EPSS — the probability each CVE is exploited in the next 30 days",
    ),
    "nvd": FeedSource(
        name="nvd",
        url="https://services.nvd.nist.gov/rest/json/cves/2.0",
        purpose="NVD CVE records, fetched incrementally by last-modified date",
    ),
}


class FeedFetchError(ValidationProblem):
    """A feed could not be retrieved.

    A `ValidationProblem` so it reaches the operator as a stated reason rather than a
    stack trace: "NVD returned 403" is actionable (the API key is wrong), where an
    internal error is not.
    """


def _guard_offline(settings: Settings) -> None:
    if settings.feeds_offline_mode:
        raise FeedFetchError(
            "This deployment is in offline feed mode, so NetSecOps will not reach out to "
            "the internet. Import a bundle instead (FR-VUL-08), or unset "
            "NETSECOPS_FEEDS_OFFLINE_MODE if outbound access is intended."
        )


@asynccontextmanager
async def _open(
    settings: Settings, client: httpx.AsyncClient | None
) -> AsyncIterator[httpx.AsyncClient]:
    """Yield a client, building one only if the caller did not supply it.

    A caller-supplied client is closed by the caller — a job syncing three feeds should
    not open and tear down three connections — and it is also what lets these functions
    be tested against `httpx.MockTransport` without adding a mocking library or, worse,
    reaching the real CISA and NVD endpoints from CI.
    """
    if client is not None:
        yield client
        return
    async with _client(settings) as owned:
        yield owned


def _client(settings: Settings) -> httpx.AsyncClient:
    """An HTTP client for the public internet.

    Deliberately not the device transport from `adapters/`. That one is wrapped in the
    read-only guard, which exists to constrain what may be sent *to a customer's
    equipment*; applying it here would be meaningless, and — worse — reusing it would
    blur the one boundary the product's core guarantee rests on. Feeds are a different
    kind of traffic to a different kind of host.
    """
    return httpx.AsyncClient(
        timeout=httpx.Timeout(REQUEST_TIMEOUT, connect=15.0),
        follow_redirects=True,
        # Feed hosts are public CAs; verification stays on, and there is deliberately no
        # setting to turn it off.
        verify=True,
        proxy=settings.feeds_proxy_url or None,
        headers={"User-Agent": "NetSecOps/1.0 (+read-only assessment)"},
    )


async def _get(
    client: httpx.AsyncClient,
    url: str,
    *,
    params: dict[str, Any] | None = None,
    api_key: str | None = None,
) -> bytes:
    headers = {"apiKey": api_key} if api_key else {}
    try:
        response = await client.get(url, params=params, headers=headers)
    except httpx.HTTPError as exc:
        raise FeedFetchError(f"Could not reach {url}: {exc}") from exc

    if response.status_code != 200:
        raise FeedFetchError(
            f"{url} returned HTTP {response.status_code}. "
            + (
                "NVD rate-limits unauthenticated clients heavily; setting NVD_API_KEY "
                "raises the limit."
                if response.status_code in {403, 429}
                else "The feed may be temporarily unavailable."
            )
        )

    body = response.content
    if len(body) > MAX_RESPONSE_BYTES:
        raise FeedFetchError(
            f"{url} returned {len(body)} bytes, beyond the {MAX_RESPONSE_BYTES}-byte "
            "limit. Refusing rather than reading it into memory."
        )
    return body


async def fetch_simple(
    source: FeedSource, settings: Settings, *, client: httpx.AsyncClient | None = None
) -> bytes:
    """Fetch a feed that is one file — KEV and EPSS.

    Returned as raw bytes, gzip included. The EPSS reader already decompresses, because
    that is what an operator downloading the same URL by hand would have uploaded, and
    decompressing here would mean the online and offline paths handed the importer
    different things.
    """
    _guard_offline(settings)
    async with _open(settings, client) as active:
        body = await _get(active, source.url)

    log.info("vuln.feed_fetched", feed=source.name, bytes=len(body))
    return body


async def fetch_nvd(
    settings: Settings,
    *,
    since: datetime | None = None,
    now: datetime | None = None,
    client: httpx.AsyncClient | None = None,
) -> bytes:
    """Fetch NVD CVE records changed since a point in time, as one NVD-shaped payload.

    **Incremental, not a full pull.** The corpus is around 300,000 CVEs; re-downloading it
    daily would be abusive to a free public service and would take hours. NVD's
    `lastModStartDate` is the supported way to ask "what changed", and a CVE whose CVSS
    score or affected ranges were revised comes back through it — which is the case a
    naive "only fetch new CVEs" design misses, and it matters because a revision is
    exactly when a device's status changes without the device changing.

    With no `since` — a first sync — the window is the maximum NVD permits rather than
    all of history. An empty database is better filled from a bundle; this path is for
    keeping a populated one current, and it says so instead of silently spending hours.

    The pages are merged into a single response-shaped dict so the existing NVD reader
    handles it unchanged, and so one sync produces one `feed_syncs` row instead of sixty.
    """
    _guard_offline(settings)

    moment = now or datetime.now(UTC)
    start = since or (moment - MAX_NVD_WINDOW)
    if moment - start > MAX_NVD_WINDOW:
        # NVD rejects the request outright rather than clamping it, so clamp here and say
        # so: a sync that silently covered only part of the gap it was asked for would
        # leave CVEs missing with nothing to show for it.
        log.warning(
            "vuln.nvd_window_clamped",
            requested_days=(moment - start).days,
            clamped_days=MAX_NVD_WINDOW.days,
        )
        start = moment - MAX_NVD_WINDOW

    api_key = settings.nvd_api_key.get_secret_value() if settings.nvd_api_key else None
    merged: list[Any] = []
    truncated = False

    async with _open(settings, client) as active:
        index = 0
        for page in range(MAX_NVD_PAGES):
            params = {
                "lastModStartDate": start.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.000"),
                "lastModEndDate": moment.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%S.000"),
                "resultsPerPage": NVD_PAGE_SIZE,
                "startIndex": index,
            }
            body = await _get(active, source_url(settings), params=params, api_key=api_key)

            try:
                payload = json.loads(body)
            except json.JSONDecodeError as exc:
                raise FeedFetchError(f"NVD returned a body that is not JSON: {exc}") from exc

            items = payload.get("vulnerabilities") or []
            merged.extend(items)

            total = int(payload.get("totalResults") or 0)
            index += len(items)
            if not items or index >= total:
                break

            if page == MAX_NVD_PAGES - 1:
                truncated = True
        else:  # pragma: no cover - the loop always breaks or sets truncated
            truncated = True

    if truncated:
        log.warning("vuln.nvd_truncated", fetched=len(merged), pages=MAX_NVD_PAGES)

    log.info("vuln.feed_fetched", feed="nvd", records=len(merged), since=start.isoformat())
    return json.dumps(
        {
            "resultsPerPage": len(merged),
            "startIndex": 0,
            "totalResults": len(merged),
            "vulnerabilities": merged,
        }
    ).encode()


def source_url(settings: Settings) -> str:
    """The NVD endpoint, overridable so a mirror can serve it."""
    return settings.nvd_api_url or DEFAULT_SOURCES["nvd"].url


__all__ = [
    "DEFAULT_SOURCES",
    "MAX_NVD_PAGES",
    "MAX_NVD_WINDOW",
    "MAX_RESPONSE_BYTES",
    "REQUEST_TIMEOUT",
    "FeedFetchError",
    "FeedSource",
    "fetch_nvd",
    "fetch_simple",
]
