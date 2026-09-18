"""ArcSight Common Event Format (FR-INT-02).

CEF is the lingua franca of SIEM ingestion and its escaping rules are the whole of the
difficulty. They are also asymmetric, which is what makes a hand-rolled formatter wrong
in a way that survives casual testing:

* In the **header**, a literal ``|`` must be written ``\\|`` and a literal ``\\`` must be
  written ``\\\\``. An unescaped pipe in a device hostname shifts every subsequent header
  field left by one, so the severity lands in the wrong slot and the SIEM reads a
  critical event as informational.
* In an **extension value**, ``=`` must be written ``\\=`` and ``\\`` as ``\\\\`` — but
  ``|`` needs no escaping at all. A formatter that applies the header rules to extensions
  produces values a strict parser rejects.
* A newline inside an extension value terminates the record for most collectors, so
  multi-line text has to be folded.

The severity slot takes 0–10, unrelated to syslog's 0–7 and inverted relative to it.
"""

from __future__ import annotations

from typing import Final

from netsecops.integrations.events import CEF_SEVERITY, Event

CEF_VERSION: Final[int] = 0
VENDOR: Final[str] = "NetSecOps"
PRODUCT: Final[str] = "NetSecOps"
PRODUCT_VERSION: Final[str] = "1.0"

#: Longest an extension value may be before it is cut.
#:
#: Collectors differ on the ceiling and several silently drop a record that exceeds it,
#: so a long finding description must be truncated here rather than discovered missing
#: at the SIEM. Truncation is marked, because a description that ends mid-sentence with
#: no sign of why reads as corruption.
MAX_VALUE = 1_000


def escape_header(value: str) -> str:
    """Escape a CEF header field: backslash first, then pipe."""
    # Backslash first. The other order double-escapes the backslash that escaping the
    # pipe just introduced, and the value arrives at the SIEM with a stray `\\`.
    return value.replace("\\", "\\\\").replace("|", "\\|")


def escape_value(value: str) -> str:
    """Escape a CEF extension value: backslash, equals, and fold newlines.

    Pipes are deliberately *not* escaped — they are legal in an extension value, and
    escaping them is a difference a strict parser notices.
    """
    folded = value.replace("\\", "\\\\").replace("=", "\\=")
    folded = folded.replace("\r\n", " ").replace("\n", " ").replace("\r", " ")
    if len(folded) > MAX_VALUE:
        folded = folded[: MAX_VALUE - 1] + "…"
    return folded


def format_event(event: Event) -> str:
    """Render one event as a CEF record.

    The signature id is the event kind, so a SIEM rule can key on a stable string rather
    than on the human-readable name, which is free to change.
    """
    clean = event.scrubbed()

    header = "|".join(
        [
            f"CEF:{CEF_VERSION}",
            escape_header(VENDOR),
            escape_header(PRODUCT),
            escape_header(PRODUCT_VERSION),
            escape_header(clean.signature_id),
            escape_header(clean.title),
            str(CEF_SEVERITY[clean.severity]),
        ]
    )

    extensions: dict[str, str] = {
        "rt": str(int(clean.occurred_at.timestamp() * 1000)),
        "cs1Label": "severity",
        "cs1": clean.severity.value,
    }
    if clean.device_hostname:
        extensions["dvchost"] = clean.device_hostname
    if clean.device_ip:
        extensions["dvc"] = clean.device_ip
    if clean.message:
        extensions["msg"] = clean.message
    if clean.object_type:
        extensions["cs2Label"] = "objectType"
        extensions["cs2"] = clean.object_type
    if clean.object_id:
        extensions["externalId"] = clean.object_id

    # Custom attributes last, and they may not overwrite a mapped field: a caller passing
    # `dvc` would otherwise silently replace the device address with something else.
    for key, value in clean.attributes.items():
        safe = "".join(ch for ch in key if ch.isalnum() or ch == "_")
        if safe and safe not in extensions:
            extensions[safe] = value

    body = " ".join(f"{k}={escape_value(v)}" for k, v in extensions.items())
    return f"{header}|{body}"


__all__ = [
    "CEF_VERSION",
    "MAX_VALUE",
    "PRODUCT",
    "PRODUCT_VERSION",
    "VENDOR",
    "escape_header",
    "escape_value",
    "format_event",
]
