"""PowerShell ``-Command`` wrapper unwrapping (the Codex CLI's shell-call shape).

The Codex CLI on Windows runs every shell call as
``"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" -Command "<cmd>"``
and gives hooks that whole line as ``tool_input.command``. tripwire must judge
the INNER command, as PowerShell, and report that it did so; any shape it cannot
read unambiguously falls back to classifying the text as given (fail open).
"""

from __future__ import annotations

import json

import pytest

from tripwire.cli import main
from tripwire.command import (
    SHELL_POWERSHELL,
    SHELL_UNSPECIFIED,
    classify,
    unwrap_powershell,
)
from tripwire.models import Report

PS = r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe"


def _codex(inner: str) -> str:
    """The Codex wrapper line, inner text already quoted for the Windows command line."""
    return f'"{PS}" -Command {inner}'


def _ids(command: str) -> list[tuple[str, str]]:
    return [(f.rule_id, f.severity) for f in classify(command).findings]


# --- accepted shapes ---------------------------------------------------------------


@pytest.mark.parametrize(
    ("command", "inner"),
    [
        (_codex('"git status && git diff"'), "git status && git diff"),
        (f'{PS} -Command "git status && git diff"', "git status && git diff"),
        ('powershell.exe -Command "git status && git diff"', "git status && git diff"),
        ('pwsh.exe -c "git status && git diff"', "git status && git diff"),
        ('pwsh -c "git status && git diff"', "git status && git diff"),
        ("C:/Program Files/PowerShell/7/pwsh.exe -c x", None),  # unquoted path with a blank
        ('"C:\\Program Files\\PowerShell\\7\\pwsh.exe" -c "a && b"', "a && b"),
        (
            f'"{PS}" -NoProfile -NonInteractive -Command "git status && git diff"',
            "git status && git diff",
        ),
        (
            f'"{PS}" -NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -Command "a && b"',
            "a && b",
        ),
        (f'"{PS}" -nop -noni -ep Bypass -COMMAND "a && b"', "a && b"),
        # A one-token inner command needs no quotes on the command line.
        (_codex("git-status"), "git-status"),
    ],
)
def test_unwrap_accepted_shapes(command: str, inner: str | None) -> None:
    assert unwrap_powershell(command) == inner


def test_codex_wrapper_judges_inner_command_as_powershell() -> None:
    result = classify(_codex('"git status && git diff"'))
    assert result.unwrapped is True
    assert result.shell == SHELL_POWERSHELL
    assert result.inner_command == "git status && git diff"
    assert [(f.rule_id, f.severity) for f in result.findings] == [("TW-SHL-001@v1", "warn")]


@pytest.mark.parametrize(
    ("inner", "expected"),
    [
        ('"git push --force origin main"', ("TW-GIT-003@v1", "fail")),
        ('"git reset --hard HEAD~1"', ("TW-GIT-003@v1", "fail")),
        ('"git add -A"', ("TW-GIT-001@v1", "warn")),
        ('"Get-Content C:\\proj\\.env"', ("TW-SEC-001@v1", "fail")),
        ('"Stop-Process -Name node"', ("TW-CMD-001@v1", "fail")),
    ],
)
def test_codex_wrapper_inner_rules_fire(inner: str, expected: tuple[str, str]) -> None:
    assert expected in _ids(_codex(inner))


# --- the quoting of the inner argument ----------------------------------------------


def test_escaped_quotes_inside_inner_are_unescaped() -> None:
    # Codex (Rust std on Windows) writes an inner double quote as \" -- the inner
    # command is git commit -m "a && b", whose && is QUOTED: no shell mismatch.
    command = _codex('"git commit -m \\"a && b\\""')
    assert unwrap_powershell(command) == 'git commit -m "a && b"'
    assert _ids(command) == []


def test_escaped_quote_red_anchor() -> None:
    # The same && outside the inner quotes IS a shell mismatch: the unescaping is
    # what decides, not a blanket silence.
    command = _codex('"git commit -m \\"a\\" && git push"')
    assert unwrap_powershell(command) == 'git commit -m "a" && git push'
    assert ("TW-SHL-001@v1", "warn") in _ids(command)


@pytest.mark.parametrize(
    ("raw", "inner"),
    [
        # backslashes not before a quote are literal
        ('"Get-Content C:\\x\\y.txt"', "Get-Content C:\\x\\y.txt"),
        # 2n backslashes before a quote -> n backslashes, quote toggles
        ('"echo C:\\dir\\\\"', "echo C:\\dir\\"),
        # 2n+1 backslashes before a quote -> n backslashes + a literal quote
        ('"echo \\\\\\"x\\\\\\" y"', 'echo \\"x\\" y'),
        # single quotes and $ are ordinary characters on the Windows command line
        ("\"Write-Output '$env:X'\"", "Write-Output '$env:X'"),
        # a multi-line inner command keeps its line breaks
        ('"git status\r\ngit diff"', "git status\r\ngit diff"),
    ],
)
def test_inner_argument_quoting_rules(raw: str, inner: str) -> None:
    assert unwrap_powershell(_codex(raw)) == inner


# --- fallbacks: today's behaviour, never a crash ------------------------------------


@pytest.mark.parametrize(
    "command",
    [
        _codex("git status"),  # several args after -Command: PowerShell re-joins them
        f'"{PS}" -File script.ps1',
        f'"{PS}" -EncodedCommand ZQBjAGgAbwA=',
        f'"{PS}" -NoProfile',  # no -Command at all
        f'"{PS}" -Unknown -Command "a && b"',
        f'"{PS}" -ExecutionPolicy',  # value missing
        _codex('"unterminated'),
        _codex('"a""b"'),  # "" inside quotes: C-runtime-version dependent
        _codex('""'),  # empty inner
        _codex('"   "'),
        _codex("-"),  # read the command from stdin
        f'"{PS}"x -Command "a"',  # quoted program glued to text
        f'"{PS} -Command "a"',  # program quote never closes cleanly
        'cmd.exe /c "a && b"',
        'bash -c "a && b"',
        "git status && git diff",
        f'"{PS}" -Command "a"\r\n -Command "b"',  # line break outside quotes
        "",
        "   ",
    ],
)
def test_unwrap_refuses_ambiguous_shapes(command: str) -> None:
    assert unwrap_powershell(command) is None
    result = classify(command)
    assert result.unwrapped is False
    assert result.shell == SHELL_UNSPECIFIED
    assert result.inner_command is None


def test_fallback_matches_pre_unwrap_classification() -> None:
    # Several args after -Command: classified exactly as the plain text, as before.
    command = f'"{PS}" -Command git push --force'
    assert unwrap_powershell(command) is None
    assert ("TW-GIT-003@v1", "fail") in _ids(command)


def test_inner_the_tokenizer_cannot_parse_falls_back_to_the_wrapper() -> None:
    # The inner text has an unbalanced quote for tripwire's tokenizer; the wrapper
    # line itself parses, so the wrapper is classified as given (fail open).
    command = _codex('"echo \'x"')
    assert unwrap_powershell(command) == "echo 'x"
    result = classify(command)
    assert result.invalid_reason is None
    assert result.unwrapped is False


def test_unwrap_never_raises_on_odd_input() -> None:
    for text in ['"', '""', '"\\', "\\", '" "', "powershell -c", '"x" -c \\"', "\x00\x1c"]:
        unwrap_powershell(text)
        classify(text)


# --- the --json report -----------------------------------------------------------


def test_json_reports_shell_and_unwrapped(capsys: pytest.CaptureFixture[str]) -> None:
    command = _codex('"git status && git diff"')
    code = main(["command", "explain", "--json", "--", command])
    payload = json.loads(capsys.readouterr().out)
    assert code == 0
    assert payload["schema_version"] == 1
    assert payload["target"] == command
    assert list(payload)[:3] == ["schema_version", "target", "findings"]
    assert payload["shell"] == "powershell"
    assert payload["unwrapped"] is True
    assert payload["inner_command"] == "git status && git diff"
    assert [f["rule_id"] for f in payload["findings"]] == ["TW-SHL-001@v1"]


def test_json_plain_command_reports_unspecified(capsys: pytest.CaptureFixture[str]) -> None:
    code = main(["command", "explain", "--json", "--", "git", "status"])
    payload = json.loads(capsys.readouterr().out)
    assert code == 0
    assert list(payload) == ["schema_version", "target", "findings", "shell", "unwrapped"]
    assert payload["shell"] == "unspecified"
    assert payload["unwrapped"] is False


def test_report_round_trips_the_additive_fields() -> None:
    report = Report(
        target="t", findings=[], shell="powershell", unwrapped=True, inner_command="git status"
    )
    again = Report.from_json(report.to_json())
    assert again.shell == "powershell"
    assert again.unwrapped is True
    assert again.inner_command == "git status"
    # A schema_version 1 document without the fields still reads (older producers).
    old = Report.from_json('{"schema_version": 1, "target": "t", "findings": []}')
    assert (old.shell, old.unwrapped, old.inner_command) == (None, None, None)
    assert list(old.to_dict()) == ["schema_version", "target", "findings"]


def test_text_report_names_the_unwrapped_inner_command(capsys: pytest.CaptureFixture[str]) -> None:
    main(["command", "explain", "--", _codex('"git status && git diff"')])
    out = capsys.readouterr().out
    assert "classified as powershell (unwrapped from a PowerShell -Command wrapper)" in out
    assert "git status && git diff" in out
