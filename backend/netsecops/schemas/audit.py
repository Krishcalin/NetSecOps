"""Audit log response models (FR-AUD-01, FR-AUD-02)."""

from __future__ import annotations

import ipaddress
import uuid
from datetime import datetime
from typing import Any

from pydantic import BaseModel, ConfigDict, Field, field_validator


class AuditLogRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    ts: datetime
    actor_id: uuid.UUID | None
    actor_username: str | None
    token_id: uuid.UUID | None
    action: str
    outcome: str
    object_type: str | None
    object_id: str | None
    details: dict[str, Any] | None
    command_text: str | None
    device_id: uuid.UUID | None
    ip_address: str | None
    correlation_id: str | None
    #: Exposed so an auditor can verify the chain independently (FR-AUD-02).
    prev_hash: str
    hash: str

    @field_validator("ip_address", mode="before")
    @classmethod
    def _stringify_ip(cls, v: object) -> object:
        """asyncpg returns INET columns as ipaddress objects; the API contract is a string."""
        if isinstance(v, ipaddress.IPv4Address | ipaddress.IPv6Address):
            return str(v)
        return v


class PaginatedAuditLog(BaseModel):
    data: list[AuditLogRead]
    meta: dict[str, int]


class ChainVerificationResponse(BaseModel):
    total: int = Field(description="Records inspected")
    valid: bool
    first_invalid_id: int | None = None
    reason: str | None = None
