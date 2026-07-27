"""Table-driven tests for the workspace probes (plan step 2 done-when).

Asserts every frozen bad fixture emits its expected stable rule id, clean
fixtures produce zero findings, the markerless case reports ``unknown`` (never a
clean pass), and a full run completes well under the 10-second budget.
"""

from __future__ import annotations

import time
from collections.abc import Callable
from pathlib import Path

import pytest

from fixtures.repos import (
    build_active_parallel_sessions,
    build_clean_coding_root,
    build_concurrent_state_files,
    build_detached_worktree,
    build_markerless_repo,
    build_nested_repo_layer,
    build_staged_coding_root,
    build_stale_worktree,
)
from tripwire.models import Finding, Report, exit_code_for
from tripwire.rules import RULES_BY_ID
from tripwire.workspace import resolve_target, run_workspace_probes

Builder = Callable[[Path], Path]

# (builder, expected stable rule id) -- one row per workspace rule 1-6.
BAD_CASES: list[tuple[Builder, str]] = [
    (build_nested_repo_layer, "TW-GIT-002@v1"),
    (build_staged_coding_root, "TW-GIT-001@v1"),
    (build_detached_worktree, "TW-WTR-001@v1"),
    (build_stale_worktree, "TW-WTR-002@v1"),
    (build_concurrent_state_files, "TW-SES-001@v1"),
    (build_active_parallel_sessions, "TW-SES-002@v1"),
]


@pytest.mark.parametrize(
    "builder,expected_id",
    BAD_CASES,
    ids=[expected_id for _, expected_id in BAD_CASES],
)
def test_bad_fixture_emits_expected_rule_id(
    tmp_path: Path, builder: Builder, expected_id: str
) -> None:
    target = resolve_target(str(builder(tmp_path)))
    assert target is not None
    findings = run_workspace_probes(target)
    ids = {finding.rule_id for finding in findings}
    assert expected_id in ids, f"expected {expected_id}, got {sorted(ids)}"


@pytest.mark.parametrize(
    "builder,expected_id",
    BAD_CASES,
    ids=[expected_id for _, expected_id in BAD_CASES],
)
def test_bad_fixture_findings_carry_evidence_and_known_provenance(
    tmp_path: Path, builder: Builder, expected_id: str
) -> None:
    target = resolve_target(str(builder(tmp_path)))
    assert target is not None
    matching = [f for f in run_workspace_probes(target) if f.rule_id == expected_id]
    assert matching, f"no finding for {expected_id}"
    for finding in matching:
        assert finding.evaluator == "workspace"
        assert finding.observed.strip(), "finding must carry observed evidence"
        # Provenance is owned by the registry -- probes never re-invent it.
        assert finding.provenance == RULES_BY_ID[expected_id].provenance


def _exit_code(findings: list[Finding]) -> int:
    return int(exit_code_for(Report(target="/t", findings=findings)))


def test_clean_coding_root_has_no_findings(tmp_path: Path) -> None:
    target = resolve_target(str(build_clean_coding_root(tmp_path)))
    assert target is not None
    findings = run_workspace_probes(target)
    assert findings == [], [f.rule_id for f in findings]
    assert _exit_code(findings) == 0


def test_markerless_repo_reports_unknown_not_clean(tmp_path: Path) -> None:
    """No coding-root marker -> session probe is incomplete (unknown), never clean."""
    target = resolve_target(str(build_markerless_repo(tmp_path)))
    assert target is not None
    findings = run_workspace_probes(target)
    unknowns = {(f.rule_id, f.severity) for f in findings if f.severity == "unknown"}
    assert ("TW-SES-001@v1", "unknown") in unknowns
    # Incomplete evaluation must not read as success (exit 2 per the model).
    assert _exit_code(findings) == 2


def test_detached_worktree_is_blocking(tmp_path: Path) -> None:
    target = resolve_target(str(build_detached_worktree(tmp_path)))
    assert target is not None
    findings = run_workspace_probes(target)
    assert any(f.rule_id == "TW-WTR-001@v1" and f.severity == "fail" for f in findings)
    assert _exit_code(findings) == 1


def test_full_run_completes_well_under_10_seconds(tmp_path: Path) -> None:
    target = resolve_target(str(build_stale_worktree(tmp_path)))
    assert target is not None
    start = time.perf_counter()
    run_workspace_probes(target)
    assert time.perf_counter() - start < 5.0
