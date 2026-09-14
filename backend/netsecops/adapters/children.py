"""Reading a manager's list of managed devices (FR-INV-04, FR-DISC-06).

Panorama, FortiManager and a Check Point management server each know about every
firewall they manage, including ones nobody put in a spreadsheet. Enumerating them is
the fastest route to an inventory that is actually complete — and completeness is what
decides whether a clean assessment means anything, because a device NetSecOps has never
heard of contributes nothing to the risk picture and is exactly where the problem is.

Everything here is a pure function over a response body. The transport belongs to the
adapters and the approval belongs to the service; keeping the vendor *shapes* separate
from both is what lets each manager's quirks be tested against a recorded response
without a network, and what keeps vendor knowledge inside this package (C-6).

**Three fields decide whether this is useful**, and each is fiddly per vendor:

*Identity.* A serial number is the only thing that survives a device being
re-addressed, so it is preferred over the management address for matching against
inventory. Panorama and FortiManager both give one; Check Point does not, and falls
back to its object UID, which is stable within that management server.

*Reachability.* A manager lists devices it cannot currently reach, and those are
frequently the interesting ones — a firewall that stopped checking in six months ago is
either decommissioned and still racked, or is live and unmanaged. The connection state
is carried through rather than being used to filter, because filtering would hide
exactly that case.

*What it actually is.* A Check Point management server lists *itself* and its log
servers alongside the gateways. Importing those as firewalls to assess would produce a
device that can never be collected from and a permanent collection failure.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from defusedxml.common import DefusedXmlException
from defusedxml.ElementTree import ParseError, fromstring

from netsecops.core.logging import get_logger

log = get_logger(__name__)


@dataclass(frozen=True, slots=True)
class ChildDevice:
    """One device a manager reports managing, in vendor-neutral form."""

    #: What NetSecOps will call it. Falls back to the serial where a manager has no name.
    hostname: str
    #: The address to collect from. None where the manager reports none — which happens,
    #: and means the device cannot be assessed until someone supplies one. Recorded as a
    #: proposal anyway, because a firewall the manager knows about and we cannot reach is
    #: a gap worth seeing rather than one worth dropping.
    mgmt_ip: str | None
    vendor: str
    platform: str
    #: Preferred for matching: it survives re-addressing, which is the event that would
    #: otherwise duplicate a device on the next enumeration.
    serial_number: str | None = None
    model: str | None = None
    os_version: str | None = None
    #: False where the manager says it has lost contact. Carried, never filtered on.
    reachable: bool | None = None
    #: The manager's own grouping — Panorama device group, FortiManager ADOM, Check Point
    #: domain. Kept so the import can mirror the operator's existing structure rather
    #: than flattening an estate they have already organised.
    group: str | None = None
    #: Anything vendor-specific worth keeping but not worth a column.
    facts: dict[str, Any] = field(default_factory=dict)

    @property
    def identity(self) -> str:
        """The key used to match this against inventory on a later enumeration."""
        return self.serial_number or self.mgmt_ip or self.hostname


class UnsupportedManagerError(LookupError):
    """No child enumeration is defined for a platform."""


def _text(element: Any, path: str) -> str | None:
    if element is None:
        return None
    found = element.find(path)
    if found is None or found.text is None:
        return None
    value = found.text.strip()
    return value or None


# ───────────────────────────── Panorama ─────────────────────────────────────


def _panorama(payload: str) -> list[ChildDevice]:
    """`<show><devices><all/></devices></show>`.

    Panorama reports every firewall added to it, connected or not, and the `connected`
    flag is the only thing that distinguishes a live device from one that was removed
    from the rack and never removed from Panorama.
    """
    try:
        root = fromstring(payload)
    except (ParseError, DefusedXmlException) as exc:
        # Both halves matter: `ParseError` for a truncated response, and defusedxml's own
        # exceptions for an entity bomb or an XXE payload. A manager's response is
        # attacker-influenced input like any other device output, and catching only the
        # first would let a hostile one crash the worker rather than be recorded as
        # unreadable.
        log.warning("children.panorama_unreadable", error=str(exc))
        return []

    children: list[ChildDevice] = []
    for entry in root.findall(".//devices/entry"):
        serial = _text(entry, "serial") or entry.get("name")
        hostname = _text(entry, "hostname") or serial
        if not hostname:
            continue

        connected = _text(entry, "connected")
        children.append(
            ChildDevice(
                hostname=hostname,
                mgmt_ip=_text(entry, "ip-address"),
                vendor="paloalto",
                platform="panos",
                serial_number=serial,
                model=_text(entry, "model"),
                os_version=_text(entry, "sw-version"),
                reachable=None if connected is None else connected.lower() == "yes",
                # Panorama nests the device group elsewhere in the response; where it is
                # present on the entry it is worth mirroring into inventory.
                group=_text(entry, "device-group") or _text(entry, "devicegroup"),
                facts={
                    "ha_state": _text(entry, "ha/state"),
                    "multi_vsys": _text(entry, "multi-vsys"),
                },
            )
        )
    return children


# ──────────────────────────── FortiManager ──────────────────────────────────


def _fortimanager(payload: str) -> list[ChildDevice]:
    """JSON-RPC `get /dvmdb/device`.

    FortiManager splits the firmware across three integers — `os_ver`, `mr` and `patch`
    — which have to be recombined into `7.2.5`. Passing `os_ver` through alone would
    give every FortiGate in the estate a version of "7", and the vulnerability matcher
    would then match every 7.x advisory against all of them.
    """
    try:
        body = json.loads(payload)
    except ValueError as exc:
        log.warning("children.fortimanager_unreadable", error=str(exc))
        return []

    records: list[dict[str, Any]] = []
    if isinstance(body, dict):
        for result in body.get("result") or []:
            data = result.get("data") if isinstance(result, dict) else None
            if isinstance(data, list):
                records.extend(item for item in data if isinstance(item, dict))
            elif isinstance(data, dict):
                records.append(data)
    elif isinstance(body, list):
        records = [item for item in body if isinstance(item, dict)]

    children: list[ChildDevice] = []
    for record in records:
        name = str(record.get("name") or "").strip()
        if not name:
            continue

        children.append(
            ChildDevice(
                hostname=name,
                mgmt_ip=str(record.get("ip") or "").strip() or None,
                vendor="fortinet",
                platform="fortios",
                serial_number=str(record.get("sn") or "").strip() or None,
                model=str(record.get("platform_str") or "").strip() or None,
                os_version=_fortios_version(record),
                # `conn_status` is 1 for up. Anything else — 0, or absent — is not
                # "down"; it is "not up", and only 1 is a positive statement.
                reachable=record.get("conn_status") == 1 if "conn_status" in record else None,
                group=str(record.get("adom") or "").strip() or None,
                facts={"ha_mode": record.get("ha_mode"), "vdom_count": record.get("vdom")},
            )
        )
    return children


def _fortios_version(record: dict[str, Any]) -> str | None:
    """`os_ver` 7, `mr` 2, `patch` 5 → `7.2.5`."""
    major = record.get("os_ver")
    if not isinstance(major, int):
        return None
    minor = record.get("mr") if isinstance(record.get("mr"), int) else 0
    patch = record.get("patch") if isinstance(record.get("patch"), int) else 0
    return f"{major}.{minor}.{patch}"


# ───────────────────────── Check Point management ───────────────────────────

#: Object types a management server returns that are *not* firewalls to assess. It lists
#: itself and its log servers alongside the gateways, and importing those would create a
#: device that can never be collected from and a collection failure that never resolves.
_CHECKPOINT_GATEWAY_TYPES = frozenset(
    {"simple-gateway", "simple-cluster", "cluster-member", "checkpoint-host"}
)
_CHECKPOINT_SKIP_TYPES = frozenset(
    {"management-server", "cpmi-host-ckp", "log-server", "primary-management", "domain"}
)


def _checkpoint(payload: str) -> list[ChildDevice]:
    """`show-gateways-and-servers`."""
    try:
        body = json.loads(payload)
    except ValueError as exc:
        log.warning("children.checkpoint_unreadable", error=str(exc))
        return []

    objects = body.get("objects") if isinstance(body, dict) else body
    if not isinstance(objects, list):
        return []

    children: list[ChildDevice] = []
    for obj in objects:
        if not isinstance(obj, dict):
            continue

        kind = str(obj.get("type") or "").strip().lower()
        if kind in _CHECKPOINT_SKIP_TYPES:
            continue
        # An unfamiliar type is *included* rather than skipped. A management server that
        # gains a new gateway type in a release should surface the device for a human to
        # look at, not silently omit it — the deny-list is the safe direction here,
        # because the cost of an extra proposal is a click and the cost of a missing one
        # is a firewall nobody assesses.
        if kind and kind not in _CHECKPOINT_GATEWAY_TYPES and "gateway" not in kind:
            if "cluster" not in kind and "host" not in kind:
                continue

        name = str(obj.get("name") or "").strip()
        if not name:
            continue

        policy = obj.get("policy")
        installed = None
        if isinstance(policy, dict):
            installed = policy.get("access-policy-installed")

        children.append(
            ChildDevice(
                hostname=name,
                mgmt_ip=str(obj.get("ipv4-address") or "").strip() or None,
                vendor="checkpoint",
                platform="checkpoint_gaia",
                # Check Point exposes no serial here; the object UID is stable within
                # this management server, which is the scope that matters for matching.
                serial_number=str(obj.get("uid") or "").strip() or None,
                model=str(obj.get("hardware") or "").strip() or None,
                os_version=str(obj.get("version") or "").strip() or None,
                # The API does not report reachability on this call. None, not True:
                # claiming every gateway is up because nothing said otherwise would be
                # the "absent is not false" mistake in a new place.
                reachable=None,
                group=str(obj.get("domain", {}).get("name") or "").strip() or None
                if isinstance(obj.get("domain"), dict)
                else None,
                facts={"type": kind, "policy_installed": installed},
            )
        )
    return children


#: Which interpreter reads which manager's response. A manager is a device whose
#: `device_class` is `manager`; the platform decides how to read what it returns.
INTERPRETERS: dict[str, Callable[[str], list[ChildDevice]]] = {
    # Panorama speaks the same XML API as the firewalls it manages, so it carries the
    # `panos` platform and is distinguished by its device class alone.
    "panos": _panorama,
    "panorama": _panorama,
    "fortimanager": _fortimanager,
    "checkpoint_mgmt": _checkpoint,
}

#: What each manager platform is asked for. Every entry is already on that platform's
#: allow-list in `policies.py`; `test_manager_enumeration.py` asserts that stays true,
#: because this is the one place the product reaches for a command outside a collection
#: profile (SRS §8.2).
ENUMERATION_REQUESTS: dict[str, tuple[str, str, dict[str, Any] | None]] = {
    "panos": (
        "GET",
        "/api/?type=op&cmd=<show><devices><all></all></devices></show>",
        None,
    ),
    "panorama": (
        "GET",
        "/api/?type=op&cmd=<show><devices><all></all></devices></show>",
        None,
    ),
    "fortimanager": (
        "POST",
        "/jsonrpc",
        {"method": "get", "params": [{"url": "/dvmdb/device"}]},
    ),
    "checkpoint_mgmt": (
        "POST",
        "/web_api/show-gateways-and-servers",
        {"command": "show-gateways-and-servers"},
    ),
}


def supports_enumeration(platform: str | None) -> bool:
    return platform in INTERPRETERS


def enumerate_children(platform: str, payload: str) -> list[ChildDevice]:
    """Read a manager's response into child device records.

    Never raises on bad input: a manager that returned something unreadable produces an
    empty list and a warning, and the caller reports "nothing enumerated" rather than
    failing the job. An exception here would lose whatever else the job was doing.
    """
    interpreter = INTERPRETERS.get(platform)
    if interpreter is None:
        raise UnsupportedManagerError(
            f"NetSecOps cannot enumerate managed devices from platform '{platform}'. "
            f"Supported managers: {', '.join(sorted(INTERPRETERS))}."
        )

    children = interpreter(payload)
    log.info("children.enumerated", platform=platform, count=len(children))
    return children


__all__ = [
    "ENUMERATION_REQUESTS",
    "INTERPRETERS",
    "ChildDevice",
    "UnsupportedManagerError",
    "enumerate_children",
    "supports_enumeration",
]
