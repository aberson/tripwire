"""Step 4 command-parsing hardening + Step 3 deep-review carry-forward tests.

Covers the conservative Windows/PowerShell hardening added in Step 4:

* quoting -- adjacent / mixed-style quoted+bare spans concatenate into one token,
  and an unbalanced quote is invalid input (exit 2) through the CLI.
* executable normalization -- ``.exe`` / path-qualified / case-insensitive program
  names and the ``spps`` Stop-Process alias resolve to the same rule.
* path casing / separators -- Windows-style secret paths still trip rule 10.
* suggested safer forms parse in the supported PS 5.1 subset and do not re-trip.
* additive classifier-branch coverage (generic stash, cleared PID+subst kill,
  ambiguous checkout) and the unknown/unbalanced -> exit 2 paths asserted through
  the production CLI caller, not only ``classify()``.
"""

from __future__ import annotations

import pytest

from fixtures.commands import MIXED_QUOTING_SECRET, RISKY, SAFER_FORMS
from tripwire.cli import main
from tripwire.command import classify, tokenize

# --- quoting: adjacency / mixed styles / unbalanced ------------------------


def test_tokenizer_concatenates_adjacent_quoted_and_bare_spans() -> None:
    assert tokenize('cat "foo"bar') == ["cat", "foobar"]
    assert tokenize("cat foo'bar'baz") == ["cat", "foobarbaz"]
    assert tokenize('cat "id_""rsa"') == ["cat", "id_rsa"]


def test_tokenizer_honours_mixed_quote_styles() -> None:
    # An inner opposite-style quote is a literal character, not a delimiter.
    assert tokenize("echo 'a\"b'") == ["echo", 'a"b']
    assert tokenize('echo "a\'b"') == ["echo", "a'b"]


def test_tokenizer_still_splits_operators_adjacent_to_words() -> None:
    assert tokenize("a&&b") == ["a", "&&", "b"]
    assert tokenize("a;b|c") == ["a", ";", "b", "|", "c"]


def test_tokenizer_unbalanced_quote_is_unparseable() -> None:
    assert tokenize('cat "x') is None
    assert tokenize("cat 'x\"y") is None


@pytest.mark.parametrize(
    "command,expected_id", MIXED_QUOTING_SECRET, ids=[c for c, _ in MIXED_QUOTING_SECRET]
)
def test_mixed_quoting_secret_still_trips_rule10(command: str, expected_id: str) -> None:
    """A split-across-quotes secret path must not evade rule 10 (concatenation)."""
    findings = classify(command).findings
    assert any(f.rule_id == expected_id for f in findings), (
        command,
        [f.rule_id for f in findings],
    )


# --- executable normalization: .exe / path / casing / alias ----------------


def test_exe_and_path_qualified_and_cased_tools_normalize() -> None:
    # `.exe` suffix on git.
    assert any(f.rule_id == "TW-GIT-003@v1" for f in classify("git.exe reset --hard").findings)
    # Full Windows path + `.exe` on taskkill.
    cmd = r"C:\Windows\System32\taskkill.exe /IM node.exe"
    assert any(f.rule_id == "TW-CMD-001@v1" for f in classify(cmd).findings)
    # POSIX path to grep dumping a secret.
    assert any(f.rule_id == "TW-SEC-001@v1" for f in classify("/usr/bin/grep AKIA id_rsa").findings)
    # `spps` alias of Stop-Process, name-based.
    assert any(f.rule_id == "TW-CMD-001@v1" for f in classify("spps -Name node").findings)


def test_windows_cased_secret_path_trips_rule10() -> None:
    findings = classify(r"type C:\Users\Me\.SSH\ID_RSA").findings
    assert any(f.rule_id == "TW-SEC-001@v1" and f.severity == "fail" for f in findings), findings


# --- suggested safer forms parse in the supported subset -------------------


@pytest.mark.parametrize("safer,avoided", SAFER_FORMS, ids=[c for c, _ in SAFER_FORMS])
def test_safer_form_parses_and_does_not_retrip(safer: str, avoided: str) -> None:
    result = classify(safer)
    assert result.invalid_reason is None, safer  # parses in the supported subset
    ids = {f.rule_id for f in result.findings}
    assert avoided not in ids, (safer, sorted(ids))
    assert all(f.severity != "unknown" for f in result.findings), safer
    assert "&&" not in safer and "||" not in safer  # no bash-only operator


def test_every_emitted_suggestion_is_ps51_clean() -> None:
    """No safer-form suggestion may itself contain a PS 5.1 parse error (`&&`/`||`)."""
    for command, _rule_id, _severity in RISKY:
        for finding in classify(command).findings:
            if "Suggested:" in finding.message:
                suggestion = finding.message.split("Suggested:", 1)[1]
                assert "&&" not in suggestion and "||" not in suggestion, (
                    command,
                    finding.message,
                )


# --- additive classifier-branch coverage -----------------------------------


def test_generic_stash_subcommand_warns() -> None:
    findings = classify("git stash frobnicate").findings
    assert any(f.rule_id == "TW-GIT-001@v1" and f.severity == "warn" for f in findings), findings


@pytest.mark.parametrize(
    "command", ["taskkill /PID $PID /F", "Stop-Process -Id $PID", "spps -Id $PID"]
)
def test_kill_with_pid_selector_and_subst_is_cleared_not_unknown(command: str) -> None:
    """An explicit PID/Id selector clears the kill even with a variable value."""
    findings = classify(command).findings
    assert all(f.rule_id != "TW-CMD-001@v1" for f in findings), (
        command,
        [(f.rule_id, f.severity) for f in findings],
    )


def test_ambiguous_checkout_target_is_unknown_not_pass() -> None:
    findings = classify("git checkout $TARGET").findings
    unknowns = [f for f in findings if f.rule_id == "TW-GIT-003@v1" and f.severity == "unknown"]
    assert unknowns, [(f.rule_id, f.severity) for f in findings]


# --- unknown / unbalanced -> exit 2 through the production CLI caller -------


def test_cli_unknown_severity_finding_exits_2(capsys: pytest.CaptureFixture[str]) -> None:
    code = main(["command", "explain", "--", "git", "reset", "$MODE", "HEAD~1"])
    capsys.readouterr()
    assert code == 2  # unknown -> incomplete evaluation -> exit 2, never a pass


def test_cli_unbalanced_quote_exits_2(capsys: pytest.CaptureFixture[str]) -> None:
    code = main(["command", "explain", "--", "cat", '"secrets.env'])
    err = capsys.readouterr().err
    assert code == 2
    assert "unbalanced quote" in err


# --- quoted control operators are literal arguments, not separators ---------


def test_quoted_operator_tokenizes_as_a_single_literal_token() -> None:
    """A quoted ``"&&"`` / ``";"`` concatenates into one content token, not a separator."""
    assert tokenize('git reset "&&" --hard') == ["git", "reset", "&&", "--hard"]
    assert tokenize('cat ";" secrets.env') == ["cat", ";", "secrets.env"]
    assert tokenize('git commit -m "&&"') == ["git", "commit", "-m", "&&"]


def test_quoted_operator_does_not_split_segment_bypassing_rule7() -> None:
    """A quoted ``"&&"`` must not split ``--hard`` into its own segment (rule 7 fails)."""
    findings = classify('git reset "&&" --hard').findings
    assert any(f.rule_id == "TW-GIT-003@v1" and f.severity == "fail" for f in findings), [
        (f.rule_id, f.severity) for f in findings
    ]


def test_quoted_operator_does_not_split_segment_bypassing_rule10() -> None:
    """A quoted ``";"`` must not split off the secret argument (rule 10 fails)."""
    findings = classify('cat ";" secrets.env').findings
    assert any(f.rule_id == "TW-SEC-001@v1" and f.severity == "fail" for f in findings), [
        (f.rule_id, f.severity) for f in findings
    ]


def test_quoted_operator_is_not_a_shell_mismatch_false_positive() -> None:
    """A quoted ``"&&"`` is a commit-message argument, not a bash-ism -> rule 9 must NOT fire."""
    findings = classify('git commit -m "&&"').findings
    assert all(f.rule_id != "TW-SHL-001@v1" for f in findings), [
        (f.rule_id, f.severity) for f in findings
    ]


def test_cli_quoted_operator_bypass_is_caught_end_to_end(
    capsys: pytest.CaptureFixture[str],
) -> None:
    """Through the production CLI: a quoted-operator destructive git still exits 1."""
    code = main(["command", "explain", "--", "git", "reset", '"&&"', "--hard"])
    out = capsys.readouterr().out
    assert code == 1
    assert "TW-GIT-003@v1" in out


# --- rule 10 substitution -> unknown (parity with rules 2/7/8) --------------


@pytest.mark.parametrize("command", ["cat $VAR", "type %SECRET%", "grep AKIA $FILE"])
def test_secret_dump_target_substitution_is_unknown_not_pass(command: str) -> None:
    """A dumped filename that is a shell substitution cannot be ruled a non-secret -> unknown."""
    findings = classify(command).findings
    unknowns = [f for f in findings if f.rule_id == "TW-SEC-001@v1" and f.severity == "unknown"]
    assert unknowns, [(f.rule_id, f.severity) for f in findings]


def test_secret_dump_plain_nonsecret_target_still_clears() -> None:
    """The substitution branch must not over-fire: a plain non-secret filename stays clean."""
    findings = classify("cat README.md").findings
    assert all(f.rule_id != "TW-SEC-001@v1" for f in findings), [
        (f.rule_id, f.severity) for f in findings
    ]
