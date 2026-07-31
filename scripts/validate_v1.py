"""Step 5 validation harness for the tripwire v1 CLI (read-only).

Drives the PRODUCTION CLI (``python -m tripwire.cli`` -- the exact ``main()`` the
``tripwire`` console script maps to) as a subprocess against:

* six disposable fixture repos that each seed one workspace rule's bad state,
  reusing the ``tests/fixtures/repos.py`` builders,
* the frozen risky/safe command corpora from ``tests/fixtures/commands.py``, and
* the live dev workspace (``--dev-root``; defaults to the ``TRIPWIRE_DEV_ROOT``
  env var if set, else the current working directory).

It builds every fixture in a throwaway temp dir, never writes to the dev
workspace, and changes no production behaviour. Output is a structured text
report plus a JSON dump of the live-workspace findings, both consumed by
``docs/findings/v1-validation.md``.

Run: ``uv run python scripts/validate_v1.py [--dev-root <path>] [--json-out <path>]``
"""

from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import tempfile
import time
from collections.abc import Callable, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

# The in-repo pytest fixtures live under a namespace-package ``tests`` dir; put
# the repo root on the path so this standalone script can reuse the builders.
_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from tests.fixtures import commands, repos  # noqa: E402  (path bootstrap above)

#: The production entry point, invoked exactly as the ``tripwire`` console script
#: would (``tripwire.cli:main``), using the current interpreter's environment.
_CLI: tuple[str, ...] = (sys.executable, "-m", "tripwire.cli")

# Neutral default: the ``TRIPWIRE_DEV_ROOT`` env var if set, else the current
# working directory. Never a hard-coded personal path.
_DEFAULT_DEV_ROOT = os.environ.get("TRIPWIRE_DEV_ROOT", os.getcwd())


@dataclass(frozen=True)
class CliResult:
    """One production-CLI invocation: exit code, parsed JSON report, raw streams."""

    exit_code: int
    report: dict[str, Any]
    stdout: str
    stderr: str

    def rule_ids(self) -> list[str]:
        """Rule ids of every finding in the JSON report (empty if none/invalid)."""
        findings = self.report.get("findings", [])
        return [str(item["rule_id"]) for item in findings]

    def findings(self) -> list[dict[str, Any]]:
        """The report's findings list (empty for invalid-input / no-JSON runs)."""
        return list(self.report.get("findings", []))


def run_cli(args: Sequence[str]) -> CliResult:
    """Invoke ``tripwire <args> --json`` as a subprocess and parse the report."""
    proc = subprocess.run(
        [*_CLI, *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
    )
    report: dict[str, Any] = {}
    stripped = proc.stdout.strip()
    if stripped:
        try:
            parsed = json.loads(stripped)
        except json.JSONDecodeError:
            parsed = None
        if isinstance(parsed, dict):
            report = parsed
    return CliResult(proc.returncode, report, proc.stdout, proc.stderr)


def check(target: str) -> CliResult:
    """Run ``tripwire check --root <target> --json``."""
    return run_cli(["check", "--root", target, "--json"])


def explain(command: str) -> CliResult:
    """Run ``tripwire command explain --json -- <command>`` (command as one arg)."""
    return run_cli(["command", "explain", "--json", "--", command])


# --- Seeded workspace fixtures: (label, builder, expected primary rule id) ----

_WorkspaceBuilder = Callable[[Path], Path]

_SEEDED_WORKSPACE: tuple[tuple[str, _WorkspaceBuilder, str], ...] = (
    ("wrong-repo-layer", repos.build_nested_repo_layer, "TW-GIT-002@v1"),
    ("broad-staging", repos.build_staged_coding_root, "TW-GIT-001@v1"),
    ("wrong-worktree / detached-HEAD", repos.build_detached_worktree, "TW-WTR-001@v1"),
    ("stale-worktree", repos.build_stale_worktree, "TW-WTR-002@v1"),
    ("concurrent .plan-expedite-state.*", repos.build_concurrent_state_files, "TW-SES-001@v1"),
    (
        "active worktrees / other-branch commits",
        repos.build_active_parallel_sessions,
        "TW-SES-002@v1",
    ),
)


@dataclass
class Summary:
    """Accumulated counts + narrative rows for the final report."""

    seeded_ws_total: int = 0
    seeded_ws_found: int = 0
    seeded_ws_max_runtime: float = 0.0
    seeded_cmd_total: int = 0
    seeded_cmd_found: int = 0
    clean_trials: int = 0
    clean_fp: int = 0
    misses: list[str] = field(default_factory=list)
    rows: list[str] = field(default_factory=list)

    def line(self, text: str) -> None:
        self.rows.append(text)
        print(text)


def _seeded_workspace(summary: Summary) -> None:
    summary.line("== SEEDED WORKSPACE FIXTURES (rules 1-6) ==")
    for label, builder, expected in _SEEDED_WORKSPACE:
        with tempfile.TemporaryDirectory(prefix="tw-val-") as tmp:
            target = builder(Path(tmp))
            start = time.perf_counter()
            result = check(str(target))
            elapsed = time.perf_counter() - start
            summary.seeded_ws_max_runtime = max(summary.seeded_ws_max_runtime, elapsed)
            ids = result.rule_ids()
            hit = expected in ids
            summary.seeded_ws_total += 1
            summary.seeded_ws_found += int(hit)
            verdict = "FOUND" if hit else "MISS"
            summary.line(
                f"  [{verdict}] {label:<42} expect {expected} "
                f"exit={result.exit_code} runtime={elapsed:.3f}s"
            )
            summary.line(f"           got: {ids or 'none'}")
            if not hit:
                summary.misses.append(f"workspace/{label}: expected {expected}, got {ids}")


def _seeded_commands(summary: Summary) -> None:
    summary.line("== SEEDED COMMAND CORPUS (rules 2,7,8,9,10 risky forms) ==")
    per_rule: dict[str, list[bool]] = {}
    for command, expected_id, expected_sev in commands.RISKY:
        result = explain(command)
        matches = [
            f
            for f in result.findings()
            if f["rule_id"] == expected_id and f["severity"] == expected_sev
        ]
        hit = bool(matches)
        summary.seeded_cmd_total += 1
        summary.seeded_cmd_found += int(hit)
        per_rule.setdefault(expected_id, []).append(hit)
        if not hit:
            got = [(f["rule_id"], f["severity"]) for f in result.findings()]
            summary.line(f"  [MISS] {command!r} expect {expected_id}/{expected_sev} got {got}")
            summary.misses.append(
                f"command/{command!r}: expected {expected_id}/{expected_sev}, got {got}"
            )
    for rule_id in sorted(per_rule):
        hits = per_rule[rule_id]
        summary.line(f"  {rule_id}: {sum(hits)}/{len(hits)} risky forms detected")


def _clean_workspace(summary: Summary) -> float:
    summary.line("== CLEAN WORKSPACE FIXTURE (nuisance) ==")
    with tempfile.TemporaryDirectory(prefix="tw-val-clean-") as tmp:
        target = repos.build_clean_coding_root(Path(tmp))
        start = time.perf_counter()
        result = check(str(target))
        elapsed = time.perf_counter() - start
        ids = result.rule_ids()
        summary.clean_trials += 1
        fp = len(ids)
        summary.clean_fp += fp
        summary.line(
            f"  clean coding-root: {fp} finding(s) exit={result.exit_code} "
            f"runtime={elapsed:.3f}s -> {ids or 'clean'}"
        )
    return elapsed


def _clean_commands(summary: Summary) -> None:
    summary.line("== SAFE COMMAND CORPUS (nuisance) ==")
    raw: list[str] = [cmd for cmd, _ in commands.SCOPED] + [cmd for cmd, _ in commands.SAFER_FORMS]
    # Several SAFER_FORMS re-list SCOPED entries verbatim; a duplicate re-check of
    # an identical string adds no independent evidence, so count each unique safe
    # command once (an honest nuisance-rate denominator).
    seen: set[str] = set()
    safe: list[str] = []
    for command in raw:
        if command not in seen:
            seen.add(command)
            safe.append(command)
    dupes = len(raw) - len(safe)
    for command in safe:
        result = explain(command)
        found = result.findings()
        summary.clean_trials += 1
        if found:
            summary.clean_fp += 1
            got = [(f["rule_id"], f["severity"]) for f in found]
            summary.line(f"  [FP] {command!r} -> {got}")
    summary.line(
        f"  {len(safe)} unique safe commands evaluated "
        f"({len(raw)} raw, {dupes} SAFER_FORMS entries duplicate SCOPED verbatim)"
    )


def _markerless_note(summary: Summary) -> None:
    summary.line("== DESIGN-BEHAVIOUR PROBE: markerless standalone repo ==")
    with tempfile.TemporaryDirectory(prefix="tw-val-marker-") as tmp:
        target = repos.build_markerless_repo(Path(tmp))
        result = check(str(target))
        summary.line(
            f"  markerless repo -> exit={result.exit_code} ids={result.rule_ids()} "
            "(TW-SES-001 unknown is by-design incomplete-eval, not a clean pass)"
        )


def _real_workspace(summary: Summary, dev_root: str, json_out: Path | None) -> None:
    summary.line("== LIVE DEV WORKSPACE ==")
    # Best-of-three: the check is read-only, so findings are identical across runs;
    # report the minimum wall-clock (warm-cache steady state). Running it three
    # times here is what makes the reported figure reproducible from this harness.
    timings: list[float] = []
    start = time.perf_counter()
    result = check(dev_root)
    timings.append(time.perf_counter() - start)
    for _ in range(2):
        start = time.perf_counter()
        result = check(dev_root)
        timings.append(time.perf_counter() - start)
    best = min(timings)
    runs = " / ".join(f"{t:.3f}" for t in timings)
    summary.line(
        f"  root={dev_root} exit={result.exit_code} runtime(best-of-3)={best:.3f}s runs=[{runs}]s"
    )
    for finding in result.findings():
        summary.line(f"  [{finding['severity']}] {finding['rule_id']}")
        summary.line(f"      observed:   {finding['observed']}")
        summary.line(f"      provenance: {finding['provenance']}")
    if json_out is not None and result.report:
        json_out.write_text(
            json.dumps(result.report, indent=2, ensure_ascii=False), encoding="utf-8"
        )
        summary.line(f"  (JSON evidence written to {json_out})")


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="tripwire v1 validation harness (read-only).")
    parser.add_argument(
        "--dev-root", default=_DEFAULT_DEV_ROOT, help="Live workspace root to probe."
    )
    parser.add_argument("--json-out", default=None, help="Write live-workspace JSON evidence here.")
    args = parser.parse_args(argv)

    summary = Summary()
    _seeded_workspace(summary)
    _seeded_commands(summary)
    clean_ws_runtime = _clean_workspace(summary)
    _clean_commands(summary)
    _markerless_note(summary)
    json_out = Path(args.json_out) if args.json_out else None
    _real_workspace(summary, args.dev_root, json_out)

    seeded_total = summary.seeded_ws_total + summary.seeded_cmd_total
    seeded_found = summary.seeded_ws_found + summary.seeded_cmd_found
    nuisance = (summary.clean_fp / summary.clean_trials * 100.0) if summary.clean_trials else 0.0
    summary.line("== TOTALS ==")
    summary.line(
        f"  seeded coverage: {seeded_found}/{seeded_total} "
        f"(workspace {summary.seeded_ws_found}/{summary.seeded_ws_total}, "
        f"command {summary.seeded_cmd_found}/{summary.seeded_cmd_total})"
    )
    summary.line(
        f"  clean-case nuisance: {summary.clean_fp}/{summary.clean_trials} "
        f"= {nuisance:.1f}% (clean-workspace check runtime {clean_ws_runtime:.3f}s)"
    )
    summary.line(
        f"  seeded-workspace fixture runtime: {summary.seeded_ws_max_runtime:.3f}s max "
        f"(over {summary.seeded_ws_total} fixtures)"
    )
    if summary.misses:
        summary.line("  MISSES:")
        for miss in summary.misses:
            summary.line(f"    - {miss}")
    return 0 if seeded_found == seeded_total else 1


if __name__ == "__main__":
    raise SystemExit(main())
