"""Locate the host hook files that ship inside the tripwire package.

The Claude Code PreToolUse hook is maintained at ``hooks/claude/tripwire-pretool.ps1``
in the source repository and is force-included into the wheel at
``tripwire/hooks/claude/tripwire-pretool.ps1`` (see ``pyproject.toml``). An installed
wheel therefore carries it next to this module; an editable or source checkout
falls back to the repository copy. ``tripwire hook path --host <host>`` prints the
resolved absolute path so an installer can copy and register it without knowing
the package layout.
"""

from __future__ import annotations

from pathlib import Path

#: Host name -> hook file name. The single source of the supported host set
#: (the CLI's ``--host`` choices are derived from it).
HOOK_FILES: dict[str, str] = {"claude": "tripwire-pretool.ps1"}


class HookNotFoundError(LookupError):
    """The packaged hook file for a host is missing from this install."""


def hook_candidates(host: str) -> list[Path]:
    """Return the locations searched for ``host``'s hook, in priority order.

    1. Inside the installed package (``<package>/hooks/<host>/<file>``).
    2. The source repository (``<repo>/hooks/<host>/<file>``), for editable and
       source-checkout runs where the package directory is ``src/tripwire``.
    """
    name = HOOK_FILES[host]
    package_dir = Path(__file__).resolve().parent
    packaged = package_dir / "hooks" / host / name
    source = package_dir.parent.parent / "hooks" / host / name
    return [packaged, source]


def hook_path(host: str) -> Path:
    """Return the absolute path of ``host``'s hook file.

    Raises ``KeyError`` for an unsupported host and :class:`HookNotFoundError`
    when no candidate location holds the file.
    """
    for candidate in hook_candidates(host):
        if candidate.is_file():
            return candidate
    raise HookNotFoundError(f"no {host} hook file found in this tripwire install")
