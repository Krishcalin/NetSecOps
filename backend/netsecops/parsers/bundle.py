"""Reading a collection artefact that is keyed by endpoint (FR-COL-08).

API-collected platforms do not produce one configuration file. They produce a bundle:
a mapping from the endpoint that was called to the response it returned. That shape is
what keeps a partial collection useful — if the policy endpoint returned 403 because the
service account lacks the role, the network devices still parsed, and only the policy
checks report Not Evaluated.

**Why this is a class and not a helper function.** Each parser must be able to say which
responses nothing read, because a response we collected and then ignored is a silent
gap: the data was there, the check that needed it reported Not Evaluated, and nothing
connected the two. Both API parsers previously answered that question from a hand-
maintained ``_KNOWN`` set listing the endpoints they believed they read — and both sets
had drifted, naming endpoints no rule in the parser touched. The set claimed coverage
the code did not have, which is worse than no claim at all, because it silenced the one
mechanism that would have reported the gap.

So the bundle records what was actually read, as it is read. ``unread()`` is then a fact
about the code rather than a statement about it, and the two cannot drift apart, because
there is no longer a second place to say it.
"""

from __future__ import annotations

from collections.abc import Callable, Iterator, Mapping
from typing import Any

#: Turns a bundle key into the form a parser asks for. ISE is keyed by a bare endpoint
#: name (``networkdevice``); FortiAuthenticator by a full path (``/api/v1/system/``).
Normaliser = Callable[[str], str]

#: Pulls the list of objects out of one response. Every vendor wraps them differently,
#: and ISE wraps them three different ways depending on which API answered.
Extractor = Callable[[Any], list[dict[str, Any]]]


def last_path_segment(key: str) -> str:
    """`/api/v1/radiusclients/` -> `radiusclients`."""
    return key.strip("/").split("/")[-1].lower()


def whole_key(key: str) -> str:
    """`policy/network-access/authentication` -> itself, lowercased."""
    return key.strip().lower()


class ResponseBundle:
    """A collection artefact, tracking which of its responses were read.

    ``get`` marks a response read even when the extractor finds no objects in it. That
    is deliberate: a rule looked at the response and concluded it was empty, which is a
    different outcome from nothing having looked, and only the second is a gap.
    """

    __slots__ = ("_extract", "_normalise", "_payload", "_read")

    def __init__(
        self,
        payload: Mapping[str, Any],
        *,
        normalise: Normaliser,
        extract: Extractor,
    ) -> None:
        self._payload = payload
        self._normalise = normalise
        self._extract = extract
        self._read: set[str] = set()

    def get(self, endpoint: str) -> list[dict[str, Any]]:
        """Every object in the response to ``endpoint``, or an empty list if absent."""
        for key, payload in self._payload.items():
            if self._normalise(key) == endpoint:
                self._read.add(key)
                return self._extract(payload)
        return []

    def first(self, endpoint: str) -> dict[str, Any] | None:
        """The single object an endpoint returns, for the ones that return settings
        rather than a collection."""
        records = self.get(endpoint)
        return records[0] if records else None

    def unread(self) -> list[str]:
        """Bundle keys no rule in the parser looked at.

        The honest form of "we collected this and did nothing with it". A parser that
        crashes inside a section also leaves that section's endpoints here, which is
        correct — the response was collected and its contents did not reach the NCM.
        """
        return sorted(key for key in self._payload if key not in self._read)

    def __contains__(self, endpoint: str) -> bool:
        return any(self._normalise(key) == endpoint for key in self._payload)

    def __iter__(self) -> Iterator[str]:
        return iter(self._payload)

    def __len__(self) -> int:
        return len(self._payload)


__all__ = ["Extractor", "Normaliser", "ResponseBundle", "last_path_segment", "whole_key"]
