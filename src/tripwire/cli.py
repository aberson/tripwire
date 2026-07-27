"""argparse entry point for tripwire.

Exposes two subcommands whose argument surface is final:

* ``tripwire check [--root <path>] [--json]`` -- workspace preflight
* ``tripwire command explain [--json] -- <command>`` -- command-text risk

For this build step the handlers are deliberate stubs: they resolve the
argument surface, emit a well-formed empty :class:`~tripwire.models.Report`,
and return the mapped exit code. The workspace/rule/command logic lands in
build steps 2-4 (see ``plans/plan.md`` section 7); the exit-code and JSON
shapes it will produce are already fixed by :mod:`tripwire.models`.
"""

from __future__ import annotations

import argparse
import os
import sys
from collections.abc import Sequence

from tripwire.models import Report, exit_code_for


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
    """Stub ``check`` handler: resolve the target root, emit an empty report.

    Real git-root resolution and read-only probes land in build step 2; here
    the target is simply the absolute ``--root`` (or cwd) so the argument
    surface and report shape are exercised end-to-end.
    """
    root = args.root if args.root is not None else os.getcwd()
    target = os.path.abspath(root)
    report = Report(target=target, findings=[])
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
