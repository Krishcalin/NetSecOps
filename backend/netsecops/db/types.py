"""Custom column types."""

from __future__ import annotations

from collections.abc import Callable
from typing import Any

from sqlalchemy import String
from sqlalchemy.engine.interfaces import Dialect
from sqlalchemy.types import TypeDecorator, TypeEngine, UserDefinedType


class Ltree(UserDefinedType[str]):
    """PostgreSQL ``ltree`` — a materialised path for hierarchical Device Groups.

    SRS §5.1 specifies ltree for ``device_groups``. The point is the ancestor operator:
    resolving "every device in this group's subtree" for FR-AUTH-05 scoping is a single
    indexed ``path <@ :ancestor`` rather than a recursive CTE per request.
    """

    cache_ok = True

    def get_col_spec(self, **kw: Any) -> str:
        return "LTREE"

    # ltree values are plain dotted strings on the wire, so neither direction needs
    # conversion; these exist only to satisfy the SQLAlchemy type contract.
    def bind_processor(self, dialect: Dialect) -> Callable[[str | None], str | None]:
        def process(value: str | None) -> str | None:
            return value

        return process

    def result_processor(
        self, dialect: Dialect, coltype: object
    ) -> Callable[[str | None], str | None]:
        def process(value: str | None) -> str | None:
            return value

        return process


class LtreePath(TypeDecorator[str]):
    """``Ltree`` with validation, so a malformed path cannot reach the database.

    ltree labels accept only ``[A-Za-z0-9_]``, separated by dots. Group *names* are
    free text; the path is built from sanitised ids, and this guard makes a mistake in
    that construction fail loudly rather than at query time.
    """

    impl = Ltree
    cache_ok = True

    def process_bind_param(self, value: str | None, dialect: Dialect) -> str | None:
        if value is None:
            return None
        for label in value.split("."):
            if not label or not all(c.isalnum() or c == "_" for c in label):
                raise ValueError(
                    f"Invalid ltree label {label!r} in path {value!r}: "
                    "labels must be non-empty and contain only letters, digits or underscores"
                )
        return value

    def load_dialect_impl(self, dialect: Dialect) -> TypeEngine[str]:
        if dialect.name == "postgresql":
            return dialect.type_descriptor(Ltree())
        # Only PostgreSQL is supported (SRS §2.2); this keeps introspection tools working.
        return dialect.type_descriptor(String(2048))
