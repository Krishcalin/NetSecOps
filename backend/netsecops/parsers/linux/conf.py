"""A reader for the brace-nested configuration format FreeRADIUS and tac_plus share.

Both write blocks as `name value { ... }` with `key = value` inside, nested arbitrarily
deep, with `#` comments and no indentation guarantees. The format is close enough that
one reader serves both, and different enough from every other parser here — which read
either indentation, XML or JSON — to be worth its own module.

Two behaviours matter more than the syntax:

**A truncated file keeps what arrived.** A `cat` that was cut short by a session drop
leaves blocks open. Discarding them would lose everything above the cut as well as
below it, and a partial FreeRADIUS client list is far more useful than none.

**Values keep their line numbers.** Every value a parser stores cites the line it came
from, which is what lets a finding show the operator their own configuration — and, for
these two platforms specifically, what lets the redacted excerpt be the thing displayed
rather than the raw file.
"""

from __future__ import annotations

import re
from collections.abc import Iterator
from dataclasses import dataclass, field

#: `name [arg [arg]] {`  — e.g. `client core-sw-01 {`, `tls-config tls-common {`.
_BLOCK_OPEN = re.compile(r"^(?P<words>[^#{}]+?)\s*\{\s*$")
#: `key = value`, with optional quotes. FreeRADIUS also permits `key := value`.
#:
#: The key may contain spaces: tac_plus writes `default service = permit`, which is the
#: single most important line in its whole configuration — it means every command not
#: explicitly denied is allowed. A key pattern of `[\w.\-]+` rejected it, so it landed in
#: `unparsed` and the finding was invisible.
_ASSIGNMENT = re.compile(r"^(?P<key>[\w.\-]+(?:\s+[\w.\-]+)*?)\s*:?=\s*(?P<value>.*?)\s*$")


@dataclass(slots=True)
class ConfBlock:
    """One `name { ... }` block, with its values and nested children."""

    #: The first word: `client`, `group`, `eap`, `user`.
    kind: str
    #: The remaining words before the brace: a client name, a group name, `tls-common`.
    args: list[str] = field(default_factory=list)
    values: dict[str, str] = field(default_factory=dict)
    #: Line number per value, so a finding can cite the operator's own file.
    value_lines: dict[str, int] = field(default_factory=dict)
    #: Lines that are directives rather than assignments — `permit .*` inside a
    #: `cmd = show { ... }` block. tac_plus's whole command-authorisation model is
    #: written this way, so treating them as unparsed would lose the thing the file
    #: exists to express.
    directives: list[str] = field(default_factory=list)
    children: list[ConfBlock] = field(default_factory=list)
    line: int = 0
    line_end: int = 0

    @property
    def name(self) -> str:
        """The block's identifier — its first argument, or its kind if it has none."""
        return self.args[0] if self.args else self.kind

    def get(self, key: str) -> str | None:
        return self.values.get(key)

    def flag(self, key: str) -> bool | None:
        """`yes`/`no`, `true`/`false`, `1`/`0`. Absent stays None, never False."""
        raw = self.values.get(key)
        if raw is None:
            return None
        token = raw.strip().strip('"').lower()
        if token in {"yes", "true", "1", "enabled", "on"}:
            return True
        if token in {"no", "false", "0", "disabled", "off"}:
            return False
        return None

    def child(self, kind: str) -> ConfBlock | None:
        return next((c for c in self.children if c.kind == kind), None)

    def children_of(self, kind: str) -> list[ConfBlock]:
        return [c for c in self.children if c.kind == kind]

    def walk(self) -> Iterator[ConfBlock]:
        """This block and every block beneath it, depth first."""
        yield self
        for child in self.children:
            yield from child.walk()


@dataclass(slots=True)
class ParsedConf:
    blocks: list[ConfBlock] = field(default_factory=list)
    #: Top-level `key = value` pairs, which tac_plus uses for its global shared key.
    values: dict[str, str] = field(default_factory=dict)
    value_lines: dict[str, int] = field(default_factory=dict)
    #: Lines nothing could be made of, with their numbers (FR-PARSE-03).
    unparsed: list[str] = field(default_factory=list)

    def walk(self) -> Iterator[ConfBlock]:
        for block in self.blocks:
            yield from block.walk()

    def of_kind(self, kind: str) -> list[ConfBlock]:
        return [block for block in self.walk() if block.kind == kind]


def read(text: str) -> ParsedConf:
    """Parse a FreeRADIUS or tac_plus configuration. Never raises."""
    config = ParsedConf()
    stack: list[ConfBlock] = []

    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue

        if line == "}":
            if stack:
                closed = stack.pop()
                closed.line_end = number
            else:
                # A stray closing brace. Recorded rather than ignored: it means the file
                # is not what we think it is, and that is worth seeing.
                config.unparsed.append(f"{number}: {raw.strip()}")
            continue

        # `something {` — a block opens. Handled before assignment, because
        # `tls-config tls-common {` would otherwise look like neither.
        if match := _BLOCK_OPEN.match(line):
            words = match.group("words").split()
            if not words:
                config.unparsed.append(f"{number}: {raw.strip()}")
                continue

            # `user = admin {` in tac_plus: the `=` is decoration, and the name is what
            # follows it. Dropping it here keeps the block's `name` usable.
            cleaned = [w for w in words if w != "="]
            block = ConfBlock(kind=cleaned[0], args=cleaned[1:], line=number, line_end=number)

            if stack:
                stack[-1].children.append(block)
            else:
                config.blocks.append(block)
            stack.append(block)
            continue

        if match := _ASSIGNMENT.match(line):
            key = match.group("key")
            value = match.group("value").strip().strip('"')
            target_values = stack[-1].values if stack else config.values
            target_lines = stack[-1].value_lines if stack else config.value_lines
            target_values[key] = value
            target_lines[key] = number
            continue

        if stack:
            # A bare directive inside a block. Kept rather than discarded: this is how
            # tac_plus writes every command-authorisation rule.
            stack[-1].directives.append(line)
            continue

        config.unparsed.append(f"{number}: {raw.strip()}")

    # Blocks left open by a truncated capture keep what they collected.
    for block in stack:
        block.line_end = block.line_end or len(text.splitlines())

    return config


__all__ = ["ConfBlock", "ParsedConf", "read"]
