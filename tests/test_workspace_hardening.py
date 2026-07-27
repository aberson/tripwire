"""Step 4 workspace hardening + Step 2/3 deep-review carry-forward tests.

Covers the report-behavior and false-assurance fixes folded into Step 4:

* git subprocess TIMEOUT degrades a probe to ``unknown`` (never a silent clean
  pass) -- both through ``run_workspace_probes`` and the CLI ``check`` boundary.
* the rule-6 (TW-SES-002) clock-skew guard on the "<1h recent commit" heuristic.
* additive edge-case coverage: rule-4 (TW-WTR-002) age *and* commits-behind
  branches; rule-1 submodule-gitlink-without-marker suppression; rule-3 mid-rebase
  suppression; and the ``discover_coding_root`` ancestor walk.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import time
from pathlib import Path

import pytest

from fixtures.repos import (
    build_active_parallel_sessions,
    build_clean_coding_root,
    build_detached_worktree,
    build_detached_worktree_mid_rebase,
    build_markerless_repo,
    build_nested_repo_layer,
    build_stale_worktree,
    build_submodule_gitlink_no_marker,
)
from tripwire import workspace
from tripwire.cli import main
from tripwire.models import Report, exit_code_for
from tripwire.workspace import (
    discover_coding_root,
    find_nested_repos,
    probe_active_parallel_sessions,
    probe_stale_worktree,
    probe_worktree_branch_mismatch,
    probe_wrong_repo_layer,
    resolve_target,
    run_workspace_probes,
)


def _raise_timeout(*args: object, **kwargs: object) -> object:
    """Stand-in for ``subprocess.run`` that always times out."""
    raise subprocess.TimeoutExpired("git", 1.0)


# --- git subprocess timeout -> unknown, never a silent clean pass ----------


def test_git_timeout_reports_unknown_never_clean_pass(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    target = resolve_target(str(build_clean_coding_root(tmp_path)))  # built before patch
    assert target is not None
    monkeypatch.setattr("tripwire.workspace.subprocess.run", _raise_timeout)
    findings = run_workspace_probes(target)
    # A hung git must surface as an incomplete evaluation, not an empty all-clear.
    assert any(f.severity == "unknown" for f in findings), findings
    assert int(exit_code_for(Report(target=target, findings=findings))) == 2


def test_cli_check_git_timeout_exits_2_with_message(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    repo = build_clean_coding_root(tmp_path)  # built before patch
    monkeypatch.setattr("tripwire.workspace.subprocess.run", _raise_timeout)
    code = main(["check", "--root", str(repo)])
    err = capsys.readouterr().err
    assert code == 2
    assert "did not respond" in err


# --- rule 6 (TW-SES-002) clock-skew guard ----------------------------------


def test_rule6_future_dated_commit_is_not_counted_recent(tmp_path: Path) -> None:
    """A commit dated in the future beyond tolerance (clock skew) is not 'recent'."""
    target = resolve_target(str(build_active_parallel_sessions(tmp_path)))
    assert target is not None
    rc, out = workspace._git(target, "log", "-1", "--format=%ct", "other-session")
    assert rc == 0 and out.isdigit()
    commit_ts = int(out)
    # `now` far BEFORE the commit -> the commit looks future-dated -> suppressed.
    skewed = probe_active_parallel_sessions(target, now=commit_ts - 100_000)
    assert all(f.rule_id != "TW-SES-002@v1" for f in skewed), skewed
    # Control: `now` == commit time -> genuinely recent -> flagged.
    current = probe_active_parallel_sessions(target, now=commit_ts)
    assert any(f.rule_id == "TW-SES-002@v1" for f in current)


# --- rule 4 (TW-WTR-002) age AND commits-behind branches -------------------


def test_rule4_commits_behind_and_age_branches_both_fire(tmp_path: Path) -> None:
    target = resolve_target(str(build_stale_worktree(tmp_path)))
    assert target is not None
    # Default clock: the >3-commits-behind branch fires (tip is fresh).
    behind = probe_stale_worktree(target)
    assert any("commits behind" in f.observed for f in behind), behind
    assert all("days old" not in f.observed for f in behind)
    # Far-future clock: the >1-day age branch also fires.
    aged = probe_stale_worktree(target, now=time.time() + 3 * 86400)
    assert any("days old" in f.observed for f in aged), aged


# --- rule 1 submodule-gitlink-without-marker suppression -------------------


def test_rule1_submodule_gitlink_without_marker_is_suppressed(tmp_path: Path) -> None:
    target = resolve_target(str(build_submodule_gitlink_no_marker(tmp_path)))
    assert target is not None
    # Suppression is via the marker gate, not by failing to see the nested repo:
    assert find_nested_repos(target), "fixture must actually contain a nested gitlink"
    assert probe_wrong_repo_layer(target) == []
    # Positive control: the same nested structure WITH the marker fires rule 1.
    marked = resolve_target(str(build_nested_repo_layer(tmp_path)))
    assert marked is not None
    assert any(f.rule_id == "TW-GIT-002@v1" for f in probe_wrong_repo_layer(marked))


# --- rule 3 mid-rebase suppression -----------------------------------------


def test_rule3_mid_rebase_is_suppressed(tmp_path: Path) -> None:
    target = resolve_target(str(build_detached_worktree_mid_rebase(tmp_path)))
    assert target is not None
    # Detached HEAD is expected mid-rebase -> suppressed.
    assert probe_worktree_branch_mismatch(target) == []
    # Toggle the sentinel off: the same detached worktree now fires rule 3.
    git_dir = workspace._git_dir_abs(target)
    assert git_dir is not None
    shutil.rmtree(os.path.join(git_dir, "rebase-merge"))
    findings = probe_worktree_branch_mismatch(target)
    assert any(f.rule_id == "TW-WTR-001@v1" for f in findings), findings


def test_plain_detached_worktree_still_fires_rule3(tmp_path: Path) -> None:
    target = resolve_target(str(build_detached_worktree(tmp_path)))
    assert target is not None
    assert any(f.rule_id == "TW-WTR-001@v1" for f in probe_worktree_branch_mismatch(target))


# --- discover_coding_root ancestor walk ------------------------------------


def test_discover_coding_root_walks_up_to_marker_ancestor(tmp_path: Path) -> None:
    coding = build_nested_repo_layer(tmp_path)  # marker at root, nested repo has none
    nested = coding / "proj"
    found = discover_coding_root(str(nested))
    assert found is not None
    # Walked up from the markerless nested repo to the marker-bearing ancestor.
    assert os.path.samefile(found, str(coding))


def test_discover_coding_root_returns_none_without_any_marker(tmp_path: Path) -> None:
    plain = build_markerless_repo(tmp_path)
    assert discover_coding_root(str(plain)) is None
