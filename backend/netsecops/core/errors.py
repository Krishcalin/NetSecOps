"""RFC 7807 problem-details error model (SRS §4.2 conventions).

Every error the API emits is a ``application/problem+json`` document. Error messages are
deliberately coarse for auth failures so they cannot be used to enumerate users (SEC-05).
"""

from __future__ import annotations

from typing import Any

from fastapi import FastAPI, Request, status
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse
from starlette.exceptions import HTTPException as StarletteHTTPException

from netsecops.core.logging import correlation_id, get_logger

log = get_logger(__name__)

PROBLEM_CONTENT_TYPE = "application/problem+json"
PROBLEM_BASE_URI = "https://netsecops.invalid/problems"


class ProblemError(Exception):
    """Base class for errors that render as RFC 7807 problem details."""

    status_code: int = status.HTTP_500_INTERNAL_SERVER_ERROR
    title: str = "Internal Server Error"
    problem_type: str = "internal-error"

    def __init__(self, detail: str | None = None, **extra: Any) -> None:
        self.detail = detail or self.title
        self.extra = extra
        super().__init__(self.detail)

    def to_problem(self, instance: str) -> dict[str, Any]:
        problem: dict[str, Any] = {
            "type": f"{PROBLEM_BASE_URI}/{self.problem_type}",
            "title": self.title,
            "status": self.status_code,
            "detail": self.detail,
            "instance": instance,
        }
        if (cid := correlation_id.get()) is not None:
            problem["correlation_id"] = cid
        problem.update(self.extra)
        return problem


class AuthenticationError(ProblemError):
    status_code = status.HTTP_401_UNAUTHORIZED
    title = "Authentication failed"
    problem_type = "authentication-failed"


class MFARequiredError(ProblemError):
    """Credentials were valid but a second factor is still outstanding (FR-AUTH-03)."""

    status_code = status.HTTP_401_UNAUTHORIZED
    title = "MFA required"
    problem_type = "mfa-required"


class AccountLockedError(ProblemError):
    status_code = status.HTTP_423_LOCKED
    title = "Account locked"
    problem_type = "account-locked"


class PermissionDeniedError(ProblemError):
    status_code = status.HTTP_403_FORBIDDEN
    title = "Permission denied"
    problem_type = "permission-denied"


class NotFoundError(ProblemError):
    status_code = status.HTTP_404_NOT_FOUND
    title = "Resource not found"
    problem_type = "not-found"


class ConflictError(ProblemError):
    status_code = status.HTTP_409_CONFLICT
    title = "Conflict"
    problem_type = "conflict"


class ValidationProblem(ProblemError):
    # Literal 422 rather than the Starlette constant, whose name changed between
    # releases (UNPROCESSABLE_ENTITY → UNPROCESSABLE_CONTENT).
    status_code = 422
    title = "Validation failed"
    problem_type = "validation-failed"


class PasswordPolicyError(ValidationProblem):
    title = "Password does not meet policy"
    problem_type = "password-policy"


class RateLimitedError(ProblemError):
    status_code = status.HTTP_429_TOO_MANY_REQUESTS
    title = "Too many requests"
    problem_type = "rate-limited"


class ReadOnlyViolationError(ProblemError):
    """A command or API call outside the read-only allow-list was attempted (SRS §8.1).

    This is a critical internal fault, not a user error: it means an adapter tried to do
    something the platform guarantees it never does. Phase 1 wires this to an alert.
    """

    status_code = status.HTTP_500_INTERNAL_SERVER_ERROR
    title = "Read-only guarantee violated"
    problem_type = "readonly-violation"


def _problem_response(problem: dict[str, Any]) -> JSONResponse:
    return JSONResponse(
        status_code=int(problem["status"]),
        content=problem,
        media_type=PROBLEM_CONTENT_TYPE,
    )


def register_exception_handlers(app: FastAPI) -> None:
    @app.exception_handler(ProblemError)
    async def _problem_handler(request: Request, exc: ProblemError) -> JSONResponse:
        if exc.status_code >= 500:
            log.error("problem.server_error", problem_type=exc.problem_type, detail=exc.detail)
        else:
            log.info("problem.client_error", problem_type=exc.problem_type, detail=exc.detail)
        return _problem_response(exc.to_problem(request.url.path))

    @app.exception_handler(StarletteHTTPException)
    async def _http_handler(request: Request, exc: StarletteHTTPException) -> JSONResponse:
        problem = {
            "type": f"{PROBLEM_BASE_URI}/http-error",
            "title": str(exc.detail),
            "status": exc.status_code,
            "detail": str(exc.detail),
            "instance": request.url.path,
        }
        if (cid := correlation_id.get()) is not None:
            problem["correlation_id"] = cid
        return _problem_response(problem)

    @app.exception_handler(RequestValidationError)
    async def _validation_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
        problem = ValidationProblem(
            "One or more fields failed validation.",
            errors=[
                {"loc": list(e["loc"]), "msg": e["msg"], "type": e["type"]} for e in exc.errors()
            ],
        ).to_problem(request.url.path)
        return _problem_response(problem)

    @app.exception_handler(Exception)
    async def _unhandled_handler(request: Request, exc: Exception) -> JSONResponse:
        # Never leak internals to the client (C-2); the detail goes to the log only.
        log.exception("problem.unhandled", error=str(exc), path=request.url.path)
        return _problem_response(
            ProblemError("An unexpected error occurred.").to_problem(request.url.path)
        )
