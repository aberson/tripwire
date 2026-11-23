"""Locate the host hook files that ship inside the tripwire package.

The PreToolUse hook is maintained at ``hooks/claude/tripwire-pretool.ps1`` in the
source repository and is force-included into the wheel at
``tripwire/hooks/claude/tripwire-pretool.ps1`` (see ``pyproject.toml``). An installed
wheel therefore carries it next to this module; an editable or source checkout
falls back to the repository copy. ``tripwire hook path --host <host>`` prints the
resolved absolute path so an installer can copy and register it without knowing
the package layout.

One script serves both hosts: Claude Code and the Codex CLI send the same
PreToolUse payload (``tool_name``, ``tool_input.command``, ``cwd``) and read the
same advisory output (``hookSpecificOutput.additionalContext``), so ``codex``
maps to the same file as ``claude`` -- one source, no copy to drift.
"""

from __future__ import annotations

from pathlib import Path, PurePosixPath

#: Host name -> hook file, relative to the ``hooks`` directory (POSIX separators).
#: The single source of the supported host set (the CLI's ``--host`` choices are
#: derived from it) and of each host's packaged location (``pyproject.toml``'s
#: force-include must ship every value; a test checks it).
HOOK_FILES: dict[str, str] = {
    "claude": "claude/tripwire-pretool.ps1",
    "codex": "claude/tripwire-pretool.ps1",
}


class HookNotFoundError(LookupError):
    """The packaged hook file for a host is missing from this install."""


def hook_candidates(host: str) -> list[Path]:
    """Return the locations searched for ``host``'s hook, in priority order.

    1. Inside the installed package (``<package>/hooks/<relative path>``).
    2. The source repository (``<repo>/hooks/<relative path>``), for editable and
       source-checkout runs where the package directory is ``src/tripwire``.
    """
    relative = PurePosixPath(HOOK_FILES[host])
    package_dir = Path(__file__).resolve().parent
    packaged = package_dir.joinpath("hooks", *relative.parts)
    source = package_dir.parent.parent.joinpath("hooks", *relative.parts)
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
