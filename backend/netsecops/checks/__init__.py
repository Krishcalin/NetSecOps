"""The check engine and its shipped library (SRS §5, FR-CHK).

Importing this package registers the Python-implemented checks (FR-CHK-02), so the
registry is populated wherever the engine is used — the job runner, a unit test, or
the FR-CHK-06 dry run — without each caller having to remember an import.
"""

from netsecops.checks import python  # noqa: F401 - imported for its registrations
from netsecops.checks.engine import (
    CheckResult,
    DeviceContext,
    EvaluationContext,
    EvidenceLine,
    evaluate,
    evaluate_all,
    python_check,
)
from netsecops.checks.loader import CheckLoadError, CheckRegistry, get_registry, load_library
from netsecops.checks.schema import CheckDefinition, Outcome, Severity

__all__ = [
    "CheckDefinition",
    "CheckLoadError",
    "CheckRegistry",
    "CheckResult",
    "DeviceContext",
    "EvaluationContext",
    "EvidenceLine",
    "Outcome",
    "Severity",
    "evaluate",
    "evaluate_all",
    "get_registry",
    "load_library",
    "python_check",
]
