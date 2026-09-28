"""CDP and LLDP neighbour tables (FR-TOPO-01).

Shared by the IOS and NX-OS parsers, the way `route_tables.py` is: the output is the
protocol's, not the platform's, and two copies would drift the first time only one was
corrected.

**Why this exists at all.** `show cdp neighbors detail` and `show lldp neighbors detail`
have been approved in SRS §8.2 and on the `cisco_ios` and `cisco_nxos` allow-lists since
Phase 2, issued by no profile and parsed by nothing — found by
`test_unconsumed_capability.py`, which was written because that had happened nine times.
The consequence was specific: the topology graph is built by matching a route's next hop
to an interface, which *infers* a path. A neighbour entry is a device stating that a
cable goes somewhere. They are different kinds of claim and the product only had one.

Three things about the output decided the shape of the code below, all verified against
Cisco's published examples rather than remembered:

**The labels vary by platform and release.** CDP prints `Entry address(es):` on IOS and
`Interface address(es):` on some switches; the address beneath is `IP address:`,
`IPv4 address:` or `IPv4 Address:`. LLDP prints `Local Intf:` on IOS and
`Local Interface:` on IOS-XR. Every pattern here accepts the variants, because matching
one spelling means reporting no neighbours at all on the platforms that use another —
silently, since a device with CDP disabled reports none either.

**A field may be present and empty.** LLDP prints the literal string `not advertised`
where a device declined to send a value. Taken at face value it becomes a neighbour
*named* "not advertised", and an estate produces dozens of them — which a topology
builder would then merge into one node that every switch appears to be cabled to.

**CDP splits one record across lines in two different layouts.** `Interface:` and
`Port ID (outgoing port):` share a line on IOS and are separate lines on IOS-XR, so the
two are matched independently rather than as one pattern.
"""

from __future__ import annotations

import ipaddress
import re

from netsecops.ncm.models import Neighbour

#: What a device sends to mean "I am not telling you". Matched case-insensitively and
#: as the *whole* value: a system named "Not advertised by policy" is a real name.
_UNADVERTISED = re.compile(r"^(?:not advertised|none|n/?a|unknown)$", re.IGNORECASE)

#: A CDP record begins with a rule of dashes. Length varies by release, so this matches
#: a run rather than an exact width.
_CDP_RECORD = re.compile(r"^-{4,}\s*$")

_CDP_DEVICE = re.compile(r"^Device ID\s*:\s*(\S+)", re.IGNORECASE)
#: NX-OS prints the neighbour's plain hostname on its own line as well. Preferred over
#: `Device ID` where both are present — see `_hostname`.
_CDP_SYSNAME = re.compile(r"^System Name\s*:\s*(.+?)\s*$", re.IGNORECASE)
_CDP_LOCAL = re.compile(r"^Interface\s*:\s*([^,]+?)\s*(?:,|$)", re.IGNORECASE)
_CDP_REMOTE = re.compile(r"Port ID \(outgoing port\)\s*:\s*(.+?)\s*$", re.IGNORECASE)
_CDP_PLATFORM = re.compile(r"^Platform\s*:\s*(.+?)\s*(?:,\s*Capabilities\s*:\s*(.*))?$", re.I)

#: NX-OS appends the chassis serial to the device ID — `dist-sw02(FDO21120ABC)`. Kept,
#: the name matches no hostname in the inventory and the topology links nothing, while
#: the neighbour panel still shows a full list. Trailing only: a device genuinely named
#: `lab(test)-sw1` keeps its parentheses.
_CDP_ID_SERIAL = re.compile(r"\([A-Za-z0-9]+\)$")

#: `IP address:`, `IPv4 address:` and `IPv4 Address:` are all in Cisco's own CDP
#: examples — and LLDP prints a bare `IP:` beneath `Management Addresses:`, which is
#: why the word "address" is optional. Requiring it read no LLDP address at all.
_ADDRESS = re.compile(
    r"^IP(?:v4)?(?:\s+address)?\s*:\s*(\d{1,3}(?:\.\d{1,3}){3})\s*$", re.IGNORECASE
)

_LLDP_RECORD = re.compile(r"^-{4,}\s*$")
#: `Local Intf` on IOS, `Local Interface` on IOS-XR.
_LLDP_LOCAL = re.compile(r"^Local Int(?:f|erface)\s*:\s*(\S+)", re.IGNORECASE)
_LLDP_REMOTE = re.compile(r"^Port id\s*:\s*(.+?)\s*$", re.IGNORECASE)
_LLDP_NAME = re.compile(r"^System Name\s*:\s*(.+?)\s*$", re.IGNORECASE)
#: Both spellings. `System Capabilities` is what the far end can do and `Enabled
#: Capabilities` what it is doing; the second is the more useful and arrives second, so
#: last-one-wins picks it — but a platform that prints only the first still reports.
_LLDP_CAPS = re.compile(r"^(?:System |Enabled )?Capabilities\s*:\s*(.+?)\s*$", re.IGNORECASE)
#: `(.*)`, not `(.+?)`: IOS prints `System Description:` with the text on the FOLLOWING
#: line, so a pattern that needs a value on the same line matches nothing at all.
_LLDP_DESC = re.compile(r"^System Description\s*:\s*(.*?)\s*$", re.IGNORECASE)

#: Recognises `Label: value`, used only to decide whether the line after an empty
#: `System Description:` is its continuation or the next field. A description begins
#: with a vendor string — `Cisco IOS Software, …` — whose first punctuation is a comma,
#: so it does not match; `Time remaining: 97 seconds` does.
_LLDP_FIELD = re.compile(r"^[A-Za-z][A-Za-z0-9 /-]{0,30}\s*:\s")


def _value(raw: str | None) -> str | None:
    """A field's value, or None where the device declined to send one."""
    if raw is None:
        return None
    text = raw.strip()
    return None if not text or _UNADVERTISED.match(text) else text


def _address(raw: str) -> str | None:
    """A management address, or None where the four octets are not one.

    The regex accepts any dotted quad, which `999.999.999.999` is. Checked rather than
    trusted, for the reason the route parser checks a destination: a wrong address
    answers a topology lookup confidently, a missing one resolves to Unknown and asks a
    human. The second is the safe failure.
    """
    try:
        ipaddress.ip_address(raw)
    except ValueError:
        return None
    return raw


def _hostname(system_name: str | None, device_id: str | None) -> str | None:
    """The neighbour's name, preferring the one that can match an inventory hostname.

    NX-OS gives both: `System Name: dist-sw02` and `Device ID:dist-sw02(FDO21120ABC)`.
    IOS gives only the second, usually without a serial. Taking `Device ID` verbatim on
    NX-OS produced a name no device in the inventory has — the neighbour list looked
    complete and every topology edge derived from it was silently dropped.
    """
    if system_name:
        return system_name
    if device_id is None:
        return None
    return _CDP_ID_SERIAL.sub("", device_id).strip() or None


def _capabilities(raw: str | None) -> list[str]:
    value = _value(raw)
    if value is None:
        return []
    # CDP separates with spaces (`Switch IGMP`), LLDP with commas (`B,R`). Both, so one
    # function serves both protocols and a mixed estate reads the same either way.
    return [part for part in re.split(r"[,\s]+", value) if part]


def parse_cdp_detail(output: str) -> list[Neighbour]:
    """`show cdp neighbors detail`, on IOS, IOS-XE and NX-OS.

    Records are separated by a rule of dashes. A record with no local interface is
    dropped rather than kept with a placeholder: the local port is the one field that
    makes an entry useful — it is what "what is plugged into this port" is asked of —
    and an entry without it cannot be placed on a device.
    """
    found: list[Neighbour] = []

    for block in _split_records(output, _CDP_RECORD):
        device = platform = local = remote = address = system_name = None
        capabilities: list[str] = []

        for line in block:
            if match := _CDP_DEVICE.match(line):
                device = _value(match.group(1))
            elif match := _CDP_SYSNAME.match(line):
                system_name = _value(match.group(1))
            elif match := _CDP_PLATFORM.match(line):
                platform = _value(match.group(1))
                capabilities = _capabilities(match.group(2))
            # Not `elif`: on IOS both sit on one line, so the local interface and the
            # remote port must each get a look at it.
            if match := _CDP_LOCAL.match(line):
                local = _value(match.group(1))
            if match := _CDP_REMOTE.search(line):
                remote = _value(match.group(1))
            # Still `is None` after a rejected quad, so a later valid line is taken.
            if address is None and (match := _ADDRESS.search(line)):
                address = _address(match.group(1))

        if local is None:
            continue

        found.append(
            Neighbour(
                protocol="cdp",
                local_interface=local,
                remote_device=_hostname(system_name, device),
                remote_interface=remote,
                remote_address=address,
                platform=platform,
                capabilities=capabilities,
            )
        )

    return found


def parse_lldp_detail(output: str) -> list[Neighbour]:
    """`show lldp neighbors detail`.

    The system name is frequently `not advertised` — LLDP advertises what a device is
    configured to advertise, and a default-configured switch sends less than CDP does.
    Those entries are kept with `remote_device` unset rather than dropped: the local
    port and the remote port are still true, and "something is plugged in here and will
    not say what" is a more interesting fact than silence.
    """
    found: list[Neighbour] = []

    for block in _split_records(output, _LLDP_RECORD):
        local = remote = name = description = None
        address = None
        capabilities: list[str] = []

        for index, line in enumerate(block):
            if match := _LLDP_LOCAL.match(line):
                local = _value(match.group(1))
            elif match := _LLDP_REMOTE.match(line):
                remote = _value(match.group(1))
            elif match := _LLDP_NAME.match(line):
                name = _value(match.group(1))
            elif match := _LLDP_DESC.match(line):
                description = _value(match.group(1)) or _continuation(block, index)
            elif match := _LLDP_CAPS.match(line):
                # `Enabled Capabilities` follows `System Capabilities` and is the more
                # useful of the two — what the far end is actually doing, rather than
                # what it could. Last one wins, and that is the order they arrive in.
                capabilities = _capabilities(match.group(1))
            elif address is None and (match := _ADDRESS.search(line)):
                address = _address(match.group(1))

        if local is None:
            continue

        found.append(
            Neighbour(
                protocol="lldp",
                local_interface=local,
                remote_device=name,
                remote_interface=remote,
                remote_address=address,
                platform=description,
                capabilities=capabilities,
            )
        )

    return found


def _continuation(block: list[str], index: int) -> str | None:
    """The line after a label that carried no value, where that line is the value.

    IOS prints the system description under its label rather than beside it. The blank
    line between them is already gone — `_split_records` drops blanks — so the value is
    simply the next entry. It is taken only when it does not itself look like the next
    field, because a device that advertises no description prints the label followed by
    `Time remaining:`, and reading that as a description gives every such neighbour a
    platform of "Time remaining: 97 seconds".
    """
    following = block[index + 1] if index + 1 < len(block) else None
    if following is None or _LLDP_FIELD.match(following):
        return None
    return _value(following)


def _split_records(output: str, rule: re.Pattern[str]) -> list[list[str]]:
    """Group lines into records on the dashed rules between them.

    Leading preamble before the first rule is discarded, and a trailing record with no
    rule after it is kept — both are how a real capture ends.
    """
    records: list[list[str]] = []
    current: list[str] = []

    for raw in output.splitlines():
        line = raw.strip()
        if rule.match(line):
            if current:
                records.append(current)
            current = []
            continue
        if line:
            current.append(line)

    if current:
        records.append(current)
    return records


__all__ = ["parse_cdp_detail", "parse_lldp_detail"]
