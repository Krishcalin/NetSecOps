"""Manager child-enumeration response models (FR-INV-04, FR-DISC-06)."""

from __future__ import annotations

import uuid
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class ChildDeviceRead(BaseModel):
    hostname: str
    mgmt_ip: str | None = None
    vendor: str
    platform: str
    serial_number: str | None = None
    model: str | None = None
    os_version: str | None = None
    #: None where the manager does not report reachability on this call. Not False —
    #: claiming a gateway is unreachable because nothing said it was up would be a
    #: finding invented out of silence.
    reachable: bool | None = None
    #: Panorama device group, FortiManager ADOM, Check Point domain.
    group: str | None = None


class ChildProposalRead(BaseModel):
    """One child, and what importing it would do. `identity` is what the caller approves."""

    identity: str
    disposition: str = Field(description="new, known or unimportable")
    device_id: uuid.UUID | None = None
    reason: str | None = None
    child: ChildDeviceRead


class DisappearedDevice(BaseModel):
    """Previously imported from this manager, no longer reported by it.

    Never archived automatically. A manager that omits a device because of an API error,
    a permissions change or a domain filter looks identical to one that no longer manages
    it, and archiving on that basis would drop devices from assessment exactly when the
    manager is misbehaving.
    """

    device_id: uuid.UUID
    hostname: str | None = None
    mgmt_ip: str
    serial_number: str | None = None
    status: str


class EnumerationPreviewRead(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    manager_id: uuid.UUID
    manager_hostname: str | None = None
    platform: str | None = None
    counts: dict[str, int] = Field(default_factory=dict)
    proposals: list[ChildProposalRead] = Field(default_factory=list)
    disappeared: list[DisappearedDevice] = Field(default_factory=list)


#: A manager's device list is orders of magnitude smaller than a running configuration —
#: a few hundred entries, not a chassis dump — so it arrives in the request body rather
#: than as a file upload. This is still a generous bound for an estate of any size.
MAX_PAYLOAD_CHARS = 4 * 1024 * 1024


class EnumerationRequest(BaseModel):
    """The manager's own response to its device-list call.

    Supplied by the caller rather than fetched here: NetSecOps has an SSH transport and
    no HTTP one yet, so nothing in the product can currently execute the API calls the
    PAN-OS, FortiManager and Check Point profiles declare. Taking the response as input
    means enumeration works today, works for an air-gapped estate, and needs no change
    when the HTTP transport arrives — the same interpreter reads the same bytes.
    """

    payload: str = Field(
        max_length=MAX_PAYLOAD_CHARS,
        description=(
            "The manager's response body: Panorama's XML for "
            "`<show><devices><all/></devices></show>`, FortiManager's JSON-RPC result "
            "for `get /dvmdb/device`, or Check Point's `show-gateways-and-servers`."
        ),
    )


class ImportRequest(EnumerationRequest):
    """The approval. Only the identities named here are imported (FR-INV-04).

    Carries the payload again on purpose: the preview is re-derived and the identities
    are checked against it, so an import always acts on what the manager says *now*. A
    stored preview would let an approval be applied to a device list that has since
    changed.
    """

    identities: list[str] = Field(
        min_length=1,
        description=(
            "Identities from the preview to import. Serial number where the manager "
            "reports one, otherwise the management address."
        ),
    )
    criticality: str = Field(
        default="medium",
        description="Criticality applied to the imported devices; changeable afterwards.",
    )


class ImportResultRead(BaseModel):
    created: list[uuid.UUID] = Field(default_factory=list)
    updated: list[uuid.UUID] = Field(default_factory=list)
    skipped: list[str] = Field(default_factory=list)
    counts: dict[str, int] = Field(default_factory=dict)


class PendingDeviceRead(BaseModel):
    """A device awaiting approval — imported, attributed, and not yet assessed."""

    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    hostname: str | None = None
    mgmt_ip: Any
    vendor: str
    platform: str | None = None
    device_class: str
    serial_number: str | None = None
    model: str | None = None
    os_version: str | None = None
    parent_device_id: uuid.UUID | None = None
    facts: dict[str, Any] = Field(default_factory=dict)


__all__ = [
    "MAX_PAYLOAD_CHARS",
    "ChildDeviceRead",
    "ChildProposalRead",
    "DisappearedDevice",
    "EnumerationPreviewRead",
    "EnumerationRequest",
    "ImportRequest",
    "ImportResultRead",
    "PendingDeviceRead",
]
