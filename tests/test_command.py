"""Table-driven tests for the command classifier (plan step 3 done-when).

Asserts every risky fixture trips its expected stable rule id, every scoped
equivalent avoids the paired high-risk id, and every ambiguous case returns
unknown/invalid rather than a pass-shaped success. A CLI pass drives the same
risky fixtures through the production ``command explain`` entry point so the
classifier is exercised end-to-end (``code-quality.md``: a new component wired
through its production caller).
"""

from __future__ import annotations

import json

import pytest

from fixtures.commands import (
    AMBIGUOUS_INVALID,
    AMBIGUOUS_UNKNOWN,
    RISKY,
    SCOPED,
)
from tripwire.cli import main
from tripwire.command import classify, tokenize
from tripwire.models import Report, exit_code_for


@pytest.mark.parametrize(
    "command,expected_id,expected_severity", RISKY, ids=[c for c, _, _ in RISKY]
)
def test_risky_command_trips_expected_rule(
    command: str, expected_id: str, expected_severity: str
) -> None:
    result = classify(command)
    assert result.invalid_reason is None
    matching = [f for f in result.findings if f.rule_id == expected_id]
    assert matching, (
        f"{command!r}: expected {expected_id}, got {[f.rule_id for f in result.findings]}"
    )
    for finding in matching:
        assert finding.severity == expected_severity
        assert finding.evaluator == "command"
        assert finding.observed.strip(), "finding must carry observed evidence"
        # Provenance/message are owned by the registry, never re-invented here.
        assert finding.provenance.strip()


@pytest.mark.parametrize("command,avoided_id", SCOPED, ids=[c for c, _ in SCOPED])
def test_scoped_equivalent_avoids_high_risk_finding(command: str, avoided_id: str) -> None:
    result = classify(command)
    ids = {f.rule_id for f in result.findings}
    assert avoided_id not in ids, f"{command!r} should not trip {avoided_id}: got {sorted(ids)}"


@pytest.mark.parametrize("command", AMBIGUOUS_INVALID, ids=[repr(c) for c in AMBIGUOUS_INVALID])
def test_ambiguous_invalid_input_is_not_a_pass(command: str) -> None:
    result = classify(command)
    assert result.invalid_reason is not None
    assert result.findings == ()


@pytest.mark.parametrize(
    "command,expected_id", AMBIGUOUS_UNKNOWN, ids=[c for c, _ in AMBIGUOUS_UNKNOWN]
)
def test_ambiguous_variable_flag_is_unknown_not_pass(command: str, expected_id: str) -> None:
    result = classify(command)
    assert result.invalid_reason is None
    unknowns = [f for f in result.findings if f.severity == "unknown"]
    assert any(f.rule_id == expected_id for f in unknowns), [
        (f.rule_id, f.severity) for f in result.findings
    ]
    # unknown -> incomplete evaluation -> exit 2, never a pass (exit 0).
    code = int(exit_code_for(Report(target=command, findings=list(result.findings))))
    assert code == 2


def test_safer_form_suggestion_lives_in_message_not_observed() -> None:
    """Section 5 field contract: ``observed`` holds evidence, the prescription goes to ``message``.

    The deterministic safer-form suggestion is folded into ``message`` (via the
    per-finding message override), never into the ``observed`` evidence field.
    """
    reset = next(f for f in classify("git reset --hard").findings if f.rule_id == "TW-GIT-003@v1")
    assert reset.observed == "git reset --hard"  # pure evidence, no prescription
    assert "suggested" not in reset.observed.lower()
    assert "Suggested:" in reset.message  # safer form folded into the message
    # A warn-severity suggestion-bearing finding follows the same contract.
    stash = next(f for f in classify("git stash").findings if f.rule_id == "TW-GIT-001@v1")
    assert "suggested" not in stash.observed.lower()
    assert "Suggested:" in stash.message


def test_tokenizer_isolates_operators_and_detects_unbalanced_quotes() -> None:
    assert tokenize("git add -A") == ["git", "add", "-A"]
    assert tokenize("git add -A && git commit") == ["git", "add", "-A", "&&", "git", "commit"]
    assert tokenize('cat "secrets.env') is None  # unbalanced quote
    assert tokenize("echo 'unterminated") is None


def test_classification_is_deterministic_and_multi_finding() -> None:
    command = "git add -A && git reset --hard"
    first = [f.rule_id for f in classify(command).findings]
    second = [f.rule_id for f in classify(command).findings]
    assert first == second
    assert {"TW-GIT-001@v1", "TW-GIT-003@v1", "TW-SHL-001@v1"} <= set(first)
    # A fail present anywhere makes the whole command blocking.
    findings = classify(command).findings
    assert int(exit_code_for(Report(target=command, findings=list(findings)))) == 1


@pytest.mark.parametrize(
    "command,expected_id,expected_severity", RISKY, ids=[c for c, _, _ in RISKY]
)
def test_cli_command_explain_reaches_classifier(
    command: str,
    expected_id: str,
    expected_severity: str,
    capsys: pytest.CaptureFixture[str],
) -> None:
    code = main(["command", "explain", "--json", "--", *command.split()])
    payload = json.loads(capsys.readouterr().out)
    ids = [finding["rule_id"] for finding in payload["findings"]]
    assert expected_id in ids, f"{command!r}: {ids}"
    assert payload["target"] == command
    assert code == (1 if expected_severity == "fail" else 0)
