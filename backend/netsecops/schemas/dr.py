"""Disaster-recovery set payloads.

A read carries each member's hostname as well as its id, because an id names nothing to
somebody reading a console, and the whole point of a DR set is to be legible — "these
two are one device" is a claim a person has to be able to check at a glance.
"""

from __future__ import annotations

import uuid

from pydantic import BaseModel, Field

from netsecops.db.models.dr import DrRole


class DrMemberInput(BaseModel):
    device_id: uuid.UUID
    role: DrRole


class DrSetCreate(BaseModel):
    name: str = Field(min_length=1, max_length=150)
    description: str | None = Field(default=None, max_length=2000)
    #: At least two — a "set" of one is not a replica of anything — and one of them must
    #: be the primary, which the service checks because a schema cannot count roles.
    members: list[DrMemberInput] = Field(min_length=2, max_length=8)


class DrMemberRead(BaseModel):
    device_id: uuid.UUID
    hostname: str | None = None
    role: str


class DrSetRead(BaseModel):
    id: uuid.UUID
    name: str
    description: str | None = None
    members: list[DrMemberRead] = Field(default_factory=list)


class DrSuggestionMember(BaseModel):
    device_id: uuid.UUID
    hostname: str | None = None
    role: str


class DrSuggestionRead(BaseModel):
    """A DR set the estate's own HA facts imply, offered for a human to confirm.

    Never created automatically: ``ha.peer`` is a string a device reported about itself,
    matched to another device by name or address, and a wrong match would collapse two
    devices that are not a pair. The suggestion says what it matched on so the person
    approving it can see why.
    """

    members: list[DrSuggestionMember]
    reason: str
