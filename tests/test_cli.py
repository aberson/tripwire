"""Tests for the tripwire CLI argument surface and the wired handlers.

``check`` is wired to the real workspace probes as of build step 2, so these
tests drive it through fixtures (via ``--root``). ``command explain`` is wired to
the command classifier as of build step 3: risky command text now produces
findings + the mapped exit code, empty/unparseable text is invalid input
(exit 2), and a benign parsed command is reported without an endorsement. The two
former Step-1 stub tests (which asserted an always-empty report for real risky
commands) are replaced by the risky-path tests below.
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


def test_command_explain_flags_destructive_git_with_exit_1(
    capsys: pytest.CaptureFixture[str],
) -> None:
    code = main(["command", "explain", "--", "git", "reset", "--hard"])
    out = capsys.readouterr().out
    assert code == 1  # fail-severity finding blocks
    assert "git reset --hard" in out
    assert "TW-GIT-003@v1" in out


def test_command_explain_json_flags_force_push(
    capsys: pytest.CaptureFixture[str],
) -> None:
    code = main(["command", "explain", "--json", "--", "git", "push", "--force"])
    payload = json.loads(capsys.readouterr().out)
    assert code == 1
    assert payload["target"] == "git push --force"
    ids = [finding["rule_id"] for finding in payload["findings"]]
    assert "TW-GIT-003@v1" in ids


def test_command_explain_benign_command_is_not_endorsed(
    capsys: pytest.CaptureFixture[str],
) -> None:
    code = main(["command", "explain", "--", "ls", "-la"])
    out = capsys.readouterr().out
    assert code == 0
    assert "not a safety guarantee" in out


def test_command_explain_empty_is_invalid_input_exit_2(
    capsys: pytest.CaptureFixture[str],
) -> None:
    code = main(["command", "explain", "--"])
    err = capsys.readouterr().err
    assert code == 2
    assert "no command text" in err


def test_text_report_escapes_control_characters_in_untrusted_text(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """A terminal escape smuggled into a command token must not reach the terminal raw.

    The text renderer sanitizes the untrusted ``target`` and ``observed`` fields;
    a raw ESC is rendered as a visible ``\\x1b`` escape instead (log-spoofing /
    terminal-injection defense). The JSON path is already safe and is not changed.
    """
    code = main(["command", "explain", "--", "cat", "secrets\x1b[31m.env"])
    out = capsys.readouterr().out
    assert code == 1  # secrets-bearing dump -> fail
    assert "\x1b" not in out  # raw escape neutralized
    assert "\\x1b" in out  # rendered as a visible escape instead


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
