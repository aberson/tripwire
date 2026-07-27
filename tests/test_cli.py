"""Tests for the tripwire CLI argument surface and the wired ``check`` handler.

``check`` is wired to the real workspace probes as of build step 2, so these
tests drive it through fixtures (via ``--root``) rather than the Step-1 stub's
always-empty report. ``command explain`` remains a Step-1 stub (its logic lands
in build step 3), so its tests still assert an empty report.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from fixtures.repos import (
    build_clean_coding_root,
    build_detached_worktree,
    build_markerless_repo,
    build_non_repo_dir,
    build_staged_coding_root,
)
from tripwire.cli import main


def test_check_clean_coding_root_exits_ok(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    repo = build_clean_coding_root(tmp_path)
    code = main(["check", "--root", str(repo)])
    out = capsys.readouterr().out
    assert code == 0
    assert "target:" in out
    assert "no findings" in out


def test_check_default_root_uses_cwd(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    repo = build_clean_coding_root(tmp_path)
    monkeypatch.chdir(repo)
    code = main(["check"])
    out = capsys.readouterr().out
    assert code == 0
    assert "no findings" in out


def test_check_json_clean_report_shape(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    repo = build_clean_coding_root(tmp_path)
    code = main(["check", "--root", str(repo), "--json"])
    payload = json.loads(capsys.readouterr().out)
    assert code == 0
    assert list(payload.keys()) == ["schema_version", "target", "findings"]
    assert payload["schema_version"] == 1
    assert payload["findings"] == []


def test_check_bad_fixture_emits_expected_finding_json(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    repo = build_staged_coding_root(tmp_path)
    code = main(["check", "--root", str(repo), "--json"])
    payload = json.loads(capsys.readouterr().out)
    ids = [finding["rule_id"] for finding in payload["findings"]]
    assert "TW-GIT-001@v1" in ids
    assert code == 0  # warn-only findings do not block


def test_check_detached_worktree_blocks_with_exit_1(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    worktree = build_detached_worktree(tmp_path)
    code = main(["check", "--root", str(worktree)])
    out = capsys.readouterr().out
    assert "TW-WTR-001@v1" in out
    assert code == 1


def test_check_markerless_repo_is_incomplete_exit_2(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    repo = build_markerless_repo(tmp_path)
    code = main(["check", "--root", str(repo), "--json"])
    payload = json.loads(capsys.readouterr().out)
    severities = {finding["severity"] for finding in payload["findings"]}
    assert "unknown" in severities
    assert code == 2


def test_check_invalid_root_exits_2_with_error(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    not_a_repo = build_non_repo_dir(tmp_path)
    code = main(["check", "--root", str(not_a_repo)])
    err = capsys.readouterr().err
    assert code == 2
    assert "no enclosing git repository" in err


def test_command_explain_accepts_trailing_command(
    capsys: pytest.CaptureFixture[str],
) -> None:
    code = main(["command", "explain", "--", "git", "reset", "--hard"])
    out = capsys.readouterr().out
    assert code == 0
    assert "git reset --hard" in out
    assert "no findings" in out


def test_command_explain_json_emits_command_as_target(
    capsys: pytest.CaptureFixture[str],
) -> None:
    code = main(["command", "explain", "--json", "--", "git", "push", "--force"])
    payload = json.loads(capsys.readouterr().out)
    assert code == 0
    assert payload["target"] == "git push --force"
    assert payload["findings"] == []


def test_missing_subcommand_errors_with_exit_2() -> None:
    with pytest.raises(SystemExit) as excinfo:
        main([])
    assert excinfo.value.code == 2


def test_command_without_action_errors_with_exit_2() -> None:
    with pytest.raises(SystemExit) as excinfo:
        main(["command"])
    assert excinfo.value.code == 2


def test_unknown_subcommand_errors_with_exit_2() -> None:
    with pytest.raises(SystemExit) as excinfo:
        main(["bogus"])
    assert excinfo.value.code == 2
