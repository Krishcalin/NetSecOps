"""FortiOS configuration block reader (FR-PARSE-01, FR-PARSE-03).

`show full-configuration` is a nested, line-oriented format with exactly four verbs:

    config firewall policy          ← open a section
        edit 1                      ← open an entry within it
            set srcaddr "LAN" "DMZ" ← a value, possibly multi-valued
            config dstaddr          ← sections nest inside entries
                ...
            end
        next                        ← close the entry
    end                             ← close the section

That is regular enough to parse properly rather than with line regexes, and doing so
once here means the NCM mapping in `fortios.py` reads as a description of the
configuration rather than as string handling.

**It never raises.** An unbalanced `end`, a truncated capture, a `set` outside any entry
— all are recorded and skipped (FR-PARSE-03). A configuration that arrives half-written
because a session dropped must still yield everything above the cut.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

#: `set name "value one" "value two"` — values are quoted when they contain spaces and
#: bare when they do not, frequently in the same statement.
_VALUE = re.compile(r'"([^"]*)"|(\S+)')


@dataclass(slots=True)
class Block:
    """One `config` section or `edit` entry."""

    #: `firewall policy`, or the entry key such as `1` or `"Web access"`.
    name: str
    kind: str  # "config" or "edit"
    #: 1-based line where this block opened, for provenance (FR-PARSE-04).
    line: int
    line_end: int = 0
    values: dict[str, list[str]] = field(default_factory=dict)
    children: list[Block] = field(default_factory=list)
    #: Line number each `set` appeared on, so a finding can cite the exact statement
    #: rather than the whole stanza.
    value_lines: dict[str, int] = field(default_factory=dict)

    def get(self, key: str, default: str | None = None) -> str | None:
        values = self.values.get(key)
        return values[0] if values else default

    def get_all(self, key: str) -> list[str]:
        return list(self.values.get(key, ()))

    def flag(self, key: str, *, true_value: str = "enable") -> bool | None:
        """Tri-state read of a FortiOS toggle.

        Returns None when the key is absent, which the NCM needs kept distinct from
        False: `set utm-status disable` and never mentioning utm-status are different
        facts, and a check must be able to tell them apart.
        """
        value = self.get(key)
        if value is None:
            return None
        return value.lower() == true_value

    def child(self, name: str) -> Block | None:
        for block in self.children:
            if block.name == name:
                return block
        return None

    def entries(self) -> list[Block]:
        return [b for b in self.children if b.kind == "edit"]


@dataclass(slots=True)
class ParsedConfig:
    sections: list[Block] = field(default_factory=list)
    #: Lines the reader could not place. Surfaced, never dropped (FR-PARSE-03).
    unparsed: list[str] = field(default_factory=list)

    def section(self, path: str) -> Block | None:
        """Find a top-level section by its full name, e.g. `firewall policy`."""
        for block in self.sections:
            if block.name == path:
                return block
        return None

    def sections_matching(self, prefix: str) -> list[Block]:
        return [b for b in self.sections if b.name.startswith(prefix)]


def _values(text: str) -> list[str]:
    return [quoted if quoted else bare for quoted, bare in _VALUE.findall(text)]


def read(text: str) -> ParsedConfig:
    """Read a FortiOS configuration into nested blocks. Never raises."""
    config = ParsedConfig()
    stack: list[Block] = []

    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue

        if line.startswith("config "):
            block = Block(name=line[7:].strip().strip('"'), kind="config", line=number)
            if stack:
                stack[-1].children.append(block)
            else:
                config.sections.append(block)
            stack.append(block)

        elif line.startswith("edit "):
            if not stack:
                # An `edit` with no enclosing `config` cannot be placed. Recording it is
                # the honest alternative to inventing a parent for it.
                config.unparsed.append(f"{number}: {line}")
                continue
            block = Block(name=line[5:].strip().strip('"'), kind="edit", line=number)
            stack[-1].children.append(block)
            stack.append(block)

        elif line in {"next", "end"}:
            if not stack:
                config.unparsed.append(f"{number}: {line} with nothing open")
                continue
            closed = stack.pop()
            closed.line_end = number

        elif line.startswith(("set ", "unset ", "append ")):
            if not stack:
                config.unparsed.append(f"{number}: {line}")
                continue
            verb, _, rest = line.partition(" ")
            key, _, value_text = rest.partition(" ")
            block = stack[-1]

            if verb == "unset":
                # `unset` removes a value. Recording the key with an empty list keeps
                # "explicitly cleared" distinct from "never set", which a check may
                # legitimately care about.
                block.values[key] = []
            elif verb == "append":
                block.values.setdefault(key, []).extend(_values(value_text))
            else:
                block.values[key] = _values(value_text)
            block.value_lines[key] = number

        else:
            config.unparsed.append(f"{number}: {line}")

    # A truncated capture leaves blocks open. Close them at the last line rather than
    # discarding what they contain.
    last_line = len(text.splitlines())
    for block in stack:
        if not block.line_end:
            block.line_end = last_line

    return config


__all__ = ["Block", "ParsedConfig", "read"]
