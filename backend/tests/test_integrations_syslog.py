"""CEF formatting and RFC 5424 syslog forwarding (FR-INT-02).

Almost every failure mode here is silent at the sending end. A mis-escaped header shifts
every field after it, so the SIEM reads a *critical* event at whatever severity happened
to land in that slot; an inverted severity table sends critical events as `debug`, where
the first relay filtering on severity drops them; newline framing splits records the
collector then cannot parse. In all three the transport reports complete success.

So these assert the shape of the bytes, not that a function returned.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime

import pytest

from netsecops.integrations.cef import (
    MAX_VALUE,
    escape_header,
    escape_value,
    format_event,
)
from netsecops.integrations.events import (
    CEF_SEVERITY,
    SYSLOG_SEVERITY,
    Event,
    EventKind,
    EventSeverity,
    severity_of,
)
from netsecops.integrations.syslog import (
    MAX_MESSAGE_BYTES,
    SyslogFormat,
    format_message,
    frame,
    priority,
)

MOMENT = datetime(2026, 9, 18, 14, 30, 15, tzinfo=UTC)


def cef_fields(record: str) -> list[str]:
    """Split a CEF record the way a parser does: on *unescaped* pipes only.

    Splitting on every pipe is what a naive reader does, and it makes a correctly escaped
    record look broken — which is how the first version of these tests failed against
    working code.
    """
    fields: list[str] = []
    current: list[str] = []
    escaped = False

    for char in record:
        if escaped:
            current.append(char)
            escaped = False
        elif char == "\\":
            current.append(char)
            escaped = True
        elif char == "|":
            fields.append("".join(current))
            current = []
        else:
            current.append(char)

    fields.append("".join(current))
    return fields


def event(**overrides) -> Event:
    base = {
        "kind": EventKind.FINDING_OPENED,
        "severity": EventSeverity.CRITICAL,
        "title": "Telnet enabled",
        "message": "management.services.telnet.enabled is true",
        "occurred_at": MOMENT,
        "device_hostname": "core-sw-01",
        "device_ip": "10.10.10.2",
    }
    return Event(**{**base, **overrides})


# ════════════════════════════════ CEF escaping ═══════════════════════════════


class TestCefEscaping:
    def test_a_pipe_in_a_header_field_is_escaped(self) -> None:
        # The important one. An unescaped pipe shifts every later header field left, so
        # the severity slot receives the wrong value and the SIEM misreads urgency.
        record = format_event(event(title="Telnet | enabled"))
        header = cef_fields(record)

        assert header[5] == r"Telnet \| enabled"
        # The point of escaping: severity still lands in slot 6 rather than being pushed
        # along by the pipe inside the name.
        assert header[6] == str(CEF_SEVERITY[EventSeverity.CRITICAL])

    def test_backslash_is_escaped_before_pipe(self) -> None:
        # Order matters: escaping the pipe first, then the backslash, double-escapes the
        # backslash just introduced and the value arrives with a stray one.
        assert escape_header(r"a\b|c") == r"a\\b\|c"

    def test_an_equals_in_an_extension_value_is_escaped(self) -> None:
        assert escape_value("key=value") == r"key\=value"

    def test_a_pipe_in_an_extension_value_is_left_alone(self) -> None:
        # Legal there, and escaping it is a difference a strict parser notices.
        assert escape_value("a|b") == "a|b"

    def test_newlines_are_folded_out_of_values(self) -> None:
        # A newline inside an extension terminates the record for most collectors.
        assert "\n" not in escape_value("line one\nline two")
        assert "\r" not in escape_value("line one\r\nline two")

    def test_an_over_long_value_is_truncated_and_marked(self) -> None:
        rendered = escape_value("x" * (MAX_VALUE * 2))
        assert len(rendered) <= MAX_VALUE
        assert rendered.endswith("…")

    def test_the_signature_is_the_stable_event_kind(self) -> None:
        # A SIEM rule keys on this, so it must not be the human-readable name.
        assert cef_fields(format_event(event()))[4] == EventKind.FINDING_OPENED.value

    def test_an_attribute_cannot_overwrite_a_mapped_field(self) -> None:
        record = format_event(event(attributes={"dvc": "192.0.2.1", "ticket": "INC-9"}))
        assert "dvc=10.10.10.2" in record
        assert "ticket=INC-9" in record


# ═══════════════════════════ severity, both scales ═══════════════════════════


class TestSeverityMapping:
    def test_syslog_severity_is_inverted_relative_to_cef(self) -> None:
        """The trap this module exists to avoid.

        Syslog runs 0 (emergency) to 7 (debug) — lower is worse — while CEF runs 0 to 10
        with higher worse. A table written by analogy sends critical events as `debug`,
        the first relay filtering on severity drops them, and the integration looks
        healthy while the urgent events are the only ones nobody sees.
        """
        assert SYSLOG_SEVERITY[EventSeverity.CRITICAL] < SYSLOG_SEVERITY[EventSeverity.INFO]
        assert CEF_SEVERITY[EventSeverity.CRITICAL] > CEF_SEVERITY[EventSeverity.INFO]

    def test_every_severity_maps_on_both_scales(self) -> None:
        for level in EventSeverity:
            assert level in CEF_SEVERITY
            assert level in SYSLOG_SEVERITY

    def test_syslog_values_are_in_range(self) -> None:
        assert all(0 <= v <= 7 for v in SYSLOG_SEVERITY.values())

    def test_cef_values_are_in_range(self) -> None:
        assert all(0 <= v <= 10 for v in CEF_SEVERITY.values())

    @pytest.mark.parametrize(
        ("raw", "expected"),
        [
            ("critical", EventSeverity.CRITICAL),
            ("HIGH", EventSeverity.HIGH),
            ("informational", EventSeverity.INFO),
            (None, EventSeverity.MEDIUM),
            ("nonsense", EventSeverity.MEDIUM),
        ],
    )
    def test_finding_severities_map_or_default(self, raw, expected) -> None:
        # `severity` is free text in the database. An unrecognised value must land
        # somewhere visible rather than being dropped or silently called info.
        assert severity_of(raw) is expected

    def test_priority_combines_facility_and_severity(self) -> None:
        # local0 (16) × 8 + error (3).
        assert priority(3, 16) == 131


# ═══════════════════════════ RFC 5424 and framing ════════════════════════════


class TestSyslogMessage:
    def test_it_starts_with_a_priority_and_version(self) -> None:
        message = format_message(event(), fmt=SyslogFormat.CEF, hostname="netsecops-1")
        assert message.startswith(f"<{priority(SYSLOG_SEVERITY[EventSeverity.CRITICAL])}>1 ")

    def test_the_timestamp_is_rfc3339_zulu(self) -> None:
        message = format_message(event(), fmt=SyslogFormat.CEF, hostname="netsecops-1")
        assert "2026-09-18T14:30:15.000000Z" in message

    def test_an_absent_header_field_becomes_the_nilvalue(self) -> None:
        # An empty field is not legal, and a collector meeting one usually discards the
        # whole message rather than the field.
        #
        # Asserted by *position* — `<PRI>1 TIMESTAMP HOSTNAME APP PROCID MSGID SD` — and
        # not by searching for " - " anywhere, which the PROCID field supplies on every
        # message and which therefore passes whatever the hostname does.
        message = format_message(event(), fmt=SyslogFormat.CEF, hostname="")
        assert message.split(" ")[2] == "-"

    def test_a_present_hostname_occupies_that_field(self) -> None:
        message = format_message(event(), fmt=SyslogFormat.CEF, hostname="netsecops-1")
        assert message.split(" ")[2] == "netsecops-1"

    def test_spaces_are_stripped_from_header_fields(self) -> None:
        # A space in a header field ends it, shifting everything after it.
        message = format_message(event(), fmt=SyslogFormat.CEF, hostname="my host")
        assert "myhost" in message

    def test_json_format_carries_a_parseable_body(self) -> None:
        message = format_message(event(), fmt=SyslogFormat.JSON, hostname="netsecops-1")
        body = message.split("﻿", 1)[1]
        payload = json.loads(body)

        assert payload["event"] == EventKind.FINDING_OPENED.value
        assert payload["severity"] == "critical"
        assert payload["device"]["hostname"] == "core-sw-01"

    def test_the_utf8_bom_precedes_the_message(self) -> None:
        # RFC 5424 requires it for a UTF-8 MSG, and some collectors discard the payload
        # without it.
        message = format_message(event(), fmt=SyslogFormat.JSON, hostname="h")
        assert "﻿" in message

    def test_an_over_long_message_is_cut_on_a_character_boundary(self) -> None:
        # Cut mid-multibyte it becomes invalid UTF-8, which a strict collector drops
        # whole — losing the event rather than its tail.
        huge = format_message(
            event(message="é" * MAX_MESSAGE_BYTES),
            fmt=SyslogFormat.JSON,
            hostname="h",
        )
        huge.encode()  # raises if the cut left a broken sequence
        assert "truncated" in huge


class TestFraming:
    def test_it_is_octet_counted_not_newline_delimited(self) -> None:
        """A JSON body can legally contain a newline; framing on one splits records.

        The collector then sees fragments that parse as nothing, while the transport
        reports every byte delivered.
        """
        framed = frame("hello")
        assert framed == b"5 hello"

    def test_the_count_is_bytes_not_characters(self) -> None:
        # A multibyte character counted as one leaves the collector reading the next
        # record's first bytes as the tail of this one, desynchronising the stream from
        # that point on.
        framed = frame("é")
        assert framed == b"2 \xc3\xa9"


# ═════════════════════════════ secret scrubbing ══════════════════════════════


class TestNothingLeavesUnscrubbed:
    def test_a_secret_in_the_message_is_redacted(self) -> None:
        """Findings quote configuration, and configuration carries secrets.

        Without this a SIEM integration becomes the one place every community string in
        the estate is transmitted in clear — and it would look like it was working.
        """
        leaky = event(message="snmp-server community S3cretStr1ng RO")
        record = format_event(leaky)

        assert "S3cretStr1ng" not in record

    def test_a_secret_in_an_attribute_is_redacted(self) -> None:
        leaky = event(attributes={"line": "username admin password 0 Pa55w0rd!"})
        assert "Pa55w0rd!" not in format_event(leaky)

    def test_scrubbing_reaches_the_json_format_too(self) -> None:
        # Both formats share `Event.scrubbed()`. A channel that formatted the raw event
        # would be the one hole, so this asserts the second path independently.
        leaky = event(message="snmp-server community S3cretStr1ng RO")
        message = format_message(leaky, fmt=SyslogFormat.JSON, hostname="h")
        assert "S3cretStr1ng" not in message
