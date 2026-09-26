"""The discovery SNMP probe: sysDescr and sysObjectID, and nothing else (FR-DISC-02).

sysObjectID is the strongest fingerprint signal there is — it names the exact hardware
model from a vendor-assigned tree, where an SSH banner says "Cisco" at best and a TLS
certificate usually says nothing. Without it more discovered hosts need a human.

**The encoding lives in :mod:`netsecops.snmp.codec`**, shared with the route walk that
collection performs against onboarded devices. One BER implementation, not two: a second
copy would drift, and the off-by-one in a length prefix presents as "this device does not
speak SNMP" rather than as a bug.

**What this module does not do is the point.** FR-DISC-02 permits two OIDs against a host
nobody has agreed to assess yet; everything else in the MIB is inventory, which is
collection's job and needs an onboarded device with approved credentials.

Collection once walked ``ipCidrRouteTable`` from here downstream. It no longer does, and
the walk has been removed rather than left dormant: the platforms it was built for answer
a route command over the session already open to them, and most of them do not implement
that MIB at all.

**v2c only, and v3 is refused rather than degraded.** SNMPv3's User Security Model needs
a username, an authentication protocol and key, and a privacy protocol and key —
per-device credentials that by definition nobody has for a host they have not yet
identified. A "v3 attempt" against an unknown host is therefore either a guess or a
failure, and guessing is what FR-DISC-02 rules out.

**No community is ever guessed.** `public` is a credential, and trying it is a credential
guess whatever its reputation. The probe runs only where an operator has supplied one,
which is why the scope carries a credential reference rather than a boolean.
"""

from __future__ import annotations

import asyncio
import secrets
import socket
from dataclasses import dataclass
from typing import Final

from netsecops.core.logging import get_logger
from netsecops.snmp.codec import (
    MAX_RESPONSE,
    SNMP_PORT,
    SnmpError,
    build_get,
    decode_oid,
    encode_oid,
    parse_response,
)

log = get_logger(__name__)

#: The only two OIDs this may request (FR-DISC-02), as dotted strings.
SYS_DESCR: Final[str] = "1.3.6.1.2.1.1.1.0"
SYS_OBJECT_ID: Final[str] = "1.3.6.1.2.1.1.2.0"


@dataclass(frozen=True, slots=True)
class SnmpFacts:
    """What one successful GET yielded."""

    sys_descr: str | None = None
    sys_object_id: str | None = None

    @property
    def empty(self) -> bool:
        return not (self.sys_descr or self.sys_object_id)


async def get_system_facts(
    address: str, community: str, *, timeout: float = 2.0, port: int = SNMP_PORT
) -> SnmpFacts:
    """GET sysDescr and sysObjectID from one host.

    One datagram, one reply, no retry. Discovery is paced and a retry would double the
    packet rate the limiter was configured for; a host that does not answer is recorded
    as not answering, which is the honest result for a single-shot probe.
    """
    request = build_get(community, (SYS_DESCR, SYS_OBJECT_ID), secrets.randbelow(0x7FFFFFFF))

    loop = asyncio.get_running_loop()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setblocking(False)
    try:
        await loop.sock_sendto(sock, request, (address, port))
        data = await asyncio.wait_for(loop.sock_recv(sock, MAX_RESPONSE), timeout=timeout)
    except (TimeoutError, OSError) as exc:
        raise SnmpError(f"No SNMP response from {address}: {exc}") from exc
    finally:
        sock.close()

    values = parse_response(data)
    descr = values.get(SYS_DESCR)
    obj = values.get(SYS_OBJECT_ID)
    return SnmpFacts(
        sys_descr=str(descr) if descr is not None else None,
        sys_object_id=str(obj) if obj is not None else None,
    )


__all__ = [
    "MAX_RESPONSE",
    "SNMP_PORT",
    "SYS_DESCR",
    "SYS_OBJECT_ID",
    "SnmpError",
    "SnmpFacts",
    "build_get",
    "decode_oid",
    "encode_oid",
    "get_system_facts",
    "parse_response",
]
