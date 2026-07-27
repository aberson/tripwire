"""argparse entry point for tripwire.

Exposes two subcommands whose argument surface is final:

* ``tripwire check [--root <path>] [--json]`` -- workspace preflight
* ``tripwire command explain [--json] -- <command>`` -- command-text risk

``check`` is wired to the read-only workspace probes as of build step 2: it
resolves the target root per ``plans/plan.md`` section 6 (enclosing git root of
cwd, or ``--root``; no enclosing repository is invalid input -> exit 2), runs
the workspace probes for rules 1-6, and renders a text or ``--json`` report.
``command explain`` is wired to the command classifier as of build step 3: it
joins the text after ``--``, classifies it against the command-evaluator rules
(2, 7, 8, 9, 10), and renders a text or ``--json`` report. Empty or unparseable
command text is invalid input (exit 2, at the CLI boundary); a parsed command
that matches no documented risky pattern is reported as "no known risky pattern"
and never as a safety endorsement (plan section 8, "False assurance").
"""

from __future__ import annotations

import argparse
import os
import sys
import unicodedata
from collections.abc import Sequence

from tripwire.command import classify
from tripwire.models import ExitCode, Report, exit_code_for
from tripwire.workspace import resolve_target, run_workspace_probes

#: Unicode general categories treated as unsafe to echo raw in the text report:
#: control (``Cc`` -- C0/DEL/C1) and format (``Cf`` -- zero-width / BiDi overrides,
#: the Trojan-source vector). Escaped to a visible ``\xNN`` so evidence is
#: preserved without being interpreted by the terminal.
_UNSAFE_CATEGORIES = frozenset({"Cc", "Cf"})


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
    """``command explain`` handler: classify the trailing command text, report.

    The text after ``--`` is joined and classified against the command-evaluator
    rules. Empty or unparseable input is invalid input (exit 2, at this boundary,
    mirroring ``check``); a parsed command with no risky match is rendered with a
    non-endorsing note so a no-finding result never reads as a safety guarantee
    (plan section 8).
    """
    command_text = " ".join(args.command_text)
    result = classify(command_text)
    if result.invalid_reason is not None:
        sys.stderr.write(f"tripwire: {result.invalid_reason} (invalid input, exit 2)\n")
        return int(ExitCode.INVALID)
    report = Report(target=command_text, findings=list(result.findings))
    _emit(
        report,
        as_json=bool(args.json),
        empty_note=(
            "no known risky pattern matched (tripwire flags only documented "
            "high-confidence patterns; this is not a safety guarantee)"
        ),
    )
    return int(exit_code_for(report))


def _emit(report: Report, *, as_json: bool, empty_note: str | None = None) -> None:
    """Render a report to stdout as JSON or human-readable text.

    ``empty_note`` overrides the text rendered for a zero-finding report (used by
    ``command explain`` so an empty result is not mistaken for an endorsement).
    """
    if as_json:
        print(report.to_json(indent=2))
    else:
        print(_render_text(report, empty_note=empty_note))


def _sanitize(text: str) -> str:
    """Escape control/non-printable characters in untrusted text for the text report.

    The classified command (``report.target``) and its ``observed`` evidence carry
    attacker-influenced tokens; a raw terminal escape or newline echoed into the
    report is a terminal-injection / log-spoofing vector. Control (``Cc``) and
    format (``Cf``) characters are rendered as visible ``\\xNN`` escapes so the
    evidence is preserved without being interpreted by the terminal. The JSON path
    serializes via ``json.dumps`` and is already safe, so it is left untouched.
    """
    return "".join(
        f"\\x{ord(ch):02x}" if unicodedata.category(ch) in _UNSAFE_CATEGORIES else ch for ch in text
    )


def _render_text(report: Report, *, empty_note: str | None = None) -> str:
    """Render a report as a compact, deterministic text block.

    Untrusted fields (the classified ``target`` and each finding's ``observed``
    evidence) are passed through :func:`_sanitize`; registry-owned message and
    provenance text is trusted and rendered as-is.
    """
    lines = [f"target: {_sanitize(report.target)}"]
    if not report.findings:
        lines.append(empty_note if empty_note is not None else "no findings")
        return "\n".join(lines)
    for finding in report.findings:
        lines.append(f"[{finding.severity}] {finding.rule_id}: {finding.message}")
        lines.append(f"    observed: {_sanitize(finding.observed)}")
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
