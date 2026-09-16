"""Every third-party import is declared (C-5, and the container's ability to boot).

The Dockerfile installs the application with `pip install .` and nothing else, so
`pyproject.toml` is the complete list of what the image contains. A module imported by
`netsecops/` and missing from that list produces an image that cannot start â€” while
every test keeps passing, because the development venv has the package from somewhere
else and never consults pyproject.

That is not hypothetical. `ciscoconfparse2` was imported by the Cisco parsers from
Phase 2 and never declared, so every image built between Phase 2 and Phase 7 crashed on
import with `ModuleNotFoundError`. Nothing caught it: the unit tests, the integration
tests and the conformance tests all run against the venv, and the only thing that reads
pyproject is a `docker build` nobody ran in CI.

This test reads the import graph rather than the environment, so it fails on the commit
that adds the import rather than the deploy that discovers it.
"""

from __future__ import annotations

import ast
import pathlib
import re
import sys
import tomllib

BACKEND = pathlib.Path(__file__).resolve().parent.parent
PACKAGE = BACKEND / "netsecops"


def _normalise(name: str) -> str:
    """PEP 503 normalisation.

    `pydantic-settings` is imported as `pydantic_settings`, and comparing the two
    without this reports a declared dependency as missing â€” which would train whoever
    hits it to add an exemption and blunt the check.
    """
    return re.sub(r"[-_.]+", "-", name).lower()


#: Import name â†’ distribution name, where a package installs under a different name
#: from the one it is imported by.
DISTRIBUTION_NAMES = {
    "argon2": "argon2-cffi",
    "jwt": "pyjwt",
    "yaml": "pyyaml",
    "multipart": "python-multipart",
    "dateutil": "python-dateutil",
    "PIL": "pillow",
    # fpdf2 is the maintained fork; it still installs under the original `fpdf` name,
    # so the two differ and this test is the only thing that would have noticed.
    "fpdf": "fpdf2",
}

#: Imported directly but supplied by a declared dependency, with the reason.
#:
#: Each of these is a judgement that the transitive dependency is stable enough to rely
#: on. They are listed rather than silently skipped so the judgement is visible and can
#: be revisited â€” a FastAPI major version that swapped out Starlette would break the
#: middleware, and this is where somebody would look.
ACCEPTED_TRANSITIVE = {
    "starlette": "ships with fastapi; the ASGI types the middleware is built on",
}


def _declared() -> set[str]:
    data = tomllib.loads((BACKEND / "pyproject.toml").read_text(encoding="utf-8"))
    return {
        _normalise(entry.split(">=")[0].split("==")[0].split("[")[0].strip())
        for entry in data["project"]["dependencies"]
    }


def _imported() -> dict[str, list[str]]:
    """Top-level third-party modules imported anywhere under `netsecops/`."""
    found: dict[str, list[str]] = {}
    for path in PACKAGE.rglob("*.py"):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names = [alias.name.split(".")[0] for alias in node.names]
            elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                names = [node.module.split(".")[0]]
            else:
                continue
            for name in names:
                if name in sys.stdlib_module_names or name == "netsecops":
                    continue
                found.setdefault(name, []).append(str(path.relative_to(BACKEND)))
    return found


class TestTheImageCanImportTheApplication:
    def test_every_third_party_import_is_declared(self) -> None:
        """The check that would have caught ciscoconfparse2 five phases earlier."""
        declared = _declared()
        undeclared: dict[str, list[str]] = {}

        for name, users in _imported().items():
            if name in ACCEPTED_TRANSITIVE:
                continue
            distribution = _normalise(DISTRIBUTION_NAMES.get(name, name))
            if distribution not in declared:
                undeclared[name] = sorted(set(users))[:3]

        assert not undeclared, (
            "these modules are imported but not declared in pyproject.toml, so the "
            "container image will not start:\n"
            + "\n".join(
                f"  {name} â€” imported by {', '.join(paths)}" for name, paths in undeclared.items()
            )
        )

    def test_the_parsers_dependency_is_declared(self) -> None:
        """Named explicitly, because this is the one that actually broke.

        A general check can be weakened by adding an exemption; this one has to be
        deleted deliberately.
        """
        assert _normalise("ciscoconfparse2") in _declared()

    def test_accepted_transitive_imports_come_from_something_declared(self) -> None:
        """An exemption is only safe while its parent is still a dependency.

        `starlette` is exempt because FastAPI supplies it. If FastAPI were ever dropped
        the exemption would silently keep passing, so the link is asserted.
        """
        declared = _declared()
        assert _normalise("fastapi") in declared, (
            "starlette's exemption depends on fastapi being declared"
        )
