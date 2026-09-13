"""HTTP middleware: correlation ids, security headers, request logging, rate limiting."""

from __future__ import annotations

import time
import uuid
from collections import defaultdict, deque
from collections.abc import Awaitable, Callable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse, Response
from starlette.types import ASGIApp

from netsecops.core.config import Settings
from netsecops.core.logging import correlation_id, get_logger

log = get_logger(__name__)

CORRELATION_HEADER = "X-Correlation-ID"

RequestHandler = Callable[[Request], Awaitable[Response]]


class CorrelationIdMiddleware(BaseHTTPMiddleware):
    """Assign every request a correlation id and echo it back (NFR-LOG-01).

    The same id is carried into jobs and device sessions in later phases, so a finding
    can be traced back to the exact HTTP request that triggered its collection.
    """

    async def dispatch(self, request: Request, call_next: RequestHandler) -> Response:
        incoming = request.headers.get(CORRELATION_HEADER)
        # Only accept a well-formed inbound id; otherwise it is attacker-controlled
        # free text that ends up in every log line.
        cid = incoming if incoming and _is_safe_id(incoming) else uuid.uuid4().hex

        token = correlation_id.set(cid)
        request.state.correlation_id = cid
        try:
            response = await call_next(request)
        finally:
            correlation_id.reset(token)

        response.headers[CORRELATION_HEADER] = cid
        return response


def _is_safe_id(value: str) -> bool:
    return len(value) <= 64 and all(c.isalnum() or c in "-_" for c in value)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """SEC-02 — HSTS, CSP and framing/referrer policy on every response."""

    def __init__(self, app: ASGIApp, settings: Settings) -> None:
        super().__init__(app)
        self.settings = settings

    async def dispatch(self, request: Request, call_next: RequestHandler) -> Response:
        response = await call_next(request)
        headers = response.headers

        headers.setdefault("X-Content-Type-Options", "nosniff")
        headers.setdefault("X-Frame-Options", "DENY")
        headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        headers.setdefault(
            "Permissions-Policy", "geolocation=(), microphone=(), camera=(), payment=()"
        )
        headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
        headers.setdefault("Cross-Origin-Resource-Policy", "same-origin")

        if self.settings.cookie_secure:
            headers.setdefault(
                "Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload"
            )

        # The API serves JSON, not HTML, so it locks itself down completely. The SPA is
        # served by the reverse proxy, which applies its own (script-permitting) CSP.
        headers.setdefault(
            "Content-Security-Policy",
            "default-src 'none'; frame-ancestors 'none'; base-uri 'none'; form-action 'none'",
        )
        return response


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    """Structured access log. Query strings are dropped — they can carry secrets (C-2)."""

    async def dispatch(self, request: Request, call_next: RequestHandler) -> Response:
        started = time.perf_counter()
        try:
            response = await call_next(request)
        except Exception:
            log.exception(
                "http.request_failed",
                method=request.method,
                path=request.url.path,
                duration_ms=round((time.perf_counter() - started) * 1000, 2),
            )
            raise

        duration_ms = round((time.perf_counter() - started) * 1000, 2)
        principal = getattr(request.state, "principal", None)

        log.info(
            "http.request",
            method=request.method,
            path=request.url.path,
            status=response.status_code,
            duration_ms=duration_ms,
            actor=getattr(principal, "username", None),
        )
        response.headers["X-Response-Time-ms"] = str(duration_ms)
        return response


class RateLimitMiddleware(BaseHTTPMiddleware):
    """In-process sliding-window rate limiter for authentication endpoints (SEC-05).

    Deliberately per-process and in-memory: it blunts credential-stuffing against a
    single API replica without adding a Redis dependency that SRS §2.2 does not call
    for. Multi-replica deployments get their global limit at the reverse proxy, which
    ``deploy/caddy/Caddyfile`` documents.
    """

    def __init__(
        self,
        app: ASGIApp,
        *,
        paths: tuple[str, ...] = ("/api/v1/auth/login", "/api/v1/auth/mfa/verify"),
        max_requests: int = 10,
        window_seconds: int = 60,
    ) -> None:
        super().__init__(app)
        self.paths = paths
        self.max_requests = max_requests
        self.window_seconds = window_seconds
        self._hits: defaultdict[str, deque[float]] = defaultdict(deque)

    async def dispatch(self, request: Request, call_next: RequestHandler) -> Response:
        if not any(request.url.path.startswith(p) for p in self.paths):
            return await call_next(request)

        key = self._key(request)
        now = time.monotonic()
        window = self._hits[key]

        while window and now - window[0] > self.window_seconds:
            window.popleft()

        if len(window) >= self.max_requests:
            retry_after = int(self.window_seconds - (now - window[0])) + 1
            log.warning("http.rate_limited", path=request.url.path, key=key)
            return JSONResponse(
                status_code=429,
                media_type="application/problem+json",
                headers={"Retry-After": str(retry_after)},
                content={
                    "type": "https://netsecops.invalid/problems/rate-limited",
                    "title": "Too many requests",
                    "status": 429,
                    "detail": "Too many attempts. Please wait before trying again.",
                    "instance": request.url.path,
                },
            )

        window.append(now)
        self._prune(now)
        return await call_next(request)

    def _key(self, request: Request) -> str:
        if forwarded := request.headers.get("x-forwarded-for"):
            return forwarded.split(",")[0].strip()
        return request.client.host if request.client else "unknown"

    def _prune(self, now: float) -> None:
        """Drop fully-expired buckets so the dict cannot grow without bound."""
        if len(self._hits) < 1024:
            return
        for key in [k for k, w in self._hits.items() if not w or now - w[-1] > self.window_seconds]:
            del self._hits[key]
