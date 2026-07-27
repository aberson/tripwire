"""Baseline tests for the tripwire CLI argument surface (plan sections 6 and 10)."""

from __future__ import annotations

import json

import pytest

from tripwire.cli import main


def test_check_default_root_exits_ok(capsys: pytest.CaptureFixture[str]) -> None:
    code = main(["check"])
    out = capsys.readouterr().out
    assert code == 0
    assert "target:" in out
    assert "no findings" in out


def test_check_accepts_root_option(tmp_path: object, capsys: pytest.CaptureFixture[str]) -> None:
    code = main(["check", "--root", str(tmp_path)])
    out = capsys.readouterr().out
    assert code == 0
    assert str(tmp_path) in out


def test_check_json_emits_valid_report(
    tmp_path: object, capsys: pytest.CaptureFixture[str]
) -> None:
    code = main(["check", "--root", str(tmp_path), "--json"])
    payload = json.loads(capsys.readouterr().out)
    assert code == 0
    assert list(payload.keys()) == ["schema_version", "target", "findings"]
    assert payload["schema_version"] == 1
    assert payload["findings"] == []


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
