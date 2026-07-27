"""argparse entry point for tripwire.

Exposes two subcommands whose argument surface is final:

* ``tripwire check [--root <path>] [--json]`` -- workspace preflight
* ``tripwire command explain [--json] -- <command>`` -- command-text risk

``check`` is wired to the read-only workspace probes as of build step 2: it
resolves the target root per ``plans/plan.md`` section 6 (enclosing git root of
cwd, or ``--root``; no enclosing repository is invalid input -> exit 2), runs
the workspace probes for rules 1-6, and renders a text or ``--json`` report.
``command explain`` remains a deliberate stub emitting a well-formed empty
report; its classification logic lands in build step 3.
"""

from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Sequence

from tripwire.models import ExitCode, Report, exit_code_for
from tripwire.workspace import resolve_target, run_workspace_probes


def build_parser() -> argparse.ArgumentParser:
    """Construct the full argument parser (top-level + nested subcommands)."""
    parser = argparse.ArgumentParser(
        prog="tripwire",
        description=(
            "Local-first preflight checks that turn known workspace failure "
            "modes into evidence-bearing findings."
        ),
    )
    subcommands = parser.add_subparsers(dest="command", metavar="<command>", required=True)

    check_parser = subcommands.add_parser(
        "check",
        help="Read-only workspace/session preflight checks.",
        description=(
            "Probe the enclosing git root of the cwd (or --root) for known workspace failure modes."
        ),
    )
    check_parser.add_argument(
        "--root",
        metavar="<path>",
        default=None,
        help="Target root to probe (default: the enclosing git root of the cwd).",
    )
    check_parser.add_argument(
        "--json",
        action="store_true",
        help="Emit the report as JSON instead of text.",
    )
    check_parser.set_defaults(handler=_handle_check)

    command_parser = subcommands.add_parser(
        "command",
        help="Command-text risk explanation.",
        description="Classify proposed command text for known risky shapes.",
    )
    command_actions = command_parser.add_subparsers(
        dest="action", metavar="<action>", required=True
    )
    explain_parser = command_actions.add_parser(
        "explain",
        help="Explain the risk in proposed command text.",
        description=(
            "Classify the command text that follows '--'. Everything after the "
            "'--' separator is treated as the command to explain, not as "
            "tripwire options."
        ),
    )
    explain_parser.add_argument(
        "--json",
        action="store_true",
        help="Emit the report as JSON instead of text.",
    )
    explain_parser.add_argument(
        "command_text",
        nargs="*",
        metavar="-- <command>",
        help="The proposed command, given after a '--' separator.",
    )
    explain_parser.set_defaults(handler=_handle_command_explain)

    return parser


def _handle_check(args: argparse.Namespace) -> int:
    """``check`` handler: resolve the target root, run workspace probes, report.

    Target-root resolution follows ``plans/plan.md`` section 6: the enclosing
    git root of ``--root`` (or the cwd) is probed; no enclosing repository is
    invalid input and returns exit 2, never a heuristic fallback.
    """
    start = os.path.abspath(args.root) if args.root is not None else os.getcwd()
    target = resolve_target(start)
    if target is None:
        sys.stderr.write(
            f"tripwire: no enclosing git repository at {start!r} and no valid --root; "
            "nothing to check (invalid input, exit 2)\n"
        )
        return int(ExitCode.INVALID)
    report = Report(target=target, findings=run_workspace_probes(target))
    _emit(report, as_json=bool(args.json))
    return int(exit_code_for(report))


def _handle_command_explain(args: argparse.Namespace) -> int:
    """Stub ``command explain`` handler: echo the target, emit an empty report.

    Real tokenization and classification land in build step 3; here the target
    is the joined command text so the ``-- <command>`` surface is exercised.
    """
    command_text = " ".join(args.command_text)
    report = Report(target=command_text, findings=[])
    _emit(report, as_json=bool(args.json))
    return int(exit_code_for(report))


def _emit(report: Report, *, as_json: bool) -> None:
    """Render a report to stdout as JSON or human-readable text."""
    if as_json:
        print(report.to_json(indent=2))
    else:
        print(_render_text(report))


def _render_text(report: Report) -> str:
    """Render a report as a compact, deterministic text block."""
    lines = [f"target: {report.target}"]
    if not report.findings:
        lines.append("no findings")
        return "\n".join(lines)
    for finding in report.findings:
        lines.append(f"[{finding.severity}] {finding.rule_id}: {finding.message}")
        lines.append(f"    observed: {finding.observed}")
        lines.append(f"    provenance: {finding.provenance}")
    return "\n".join(lines)


def main(argv: Sequence[str] | None = None) -> int:
    """CLI entry point. Returns the process exit code (see plan section 6)."""
    parser = build_parser()
    args = parser.parse_args(argv)
    handler = args.handler
    return int(handler(args))


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
