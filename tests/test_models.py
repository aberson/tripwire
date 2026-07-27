"""Baseline tests for the tripwire report contract (plan sections 5 and 6)."""

from __future__ import annotations

import pytest

from tripwire.models import (
    SCHEMA_VERSION,
    ExitCode,
    Finding,
    Report,
    exit_code_for,
)


def _finding(severity: str = "warn", evaluator: str = "workspace") -> Finding:
    return Finding(
        rule_id="TW-GIT-001@v1",
        severity=severity,  # type: ignore[arg-type]
        message="broad staging at the coding-root",
        observed="git add -A",
        provenance=".claude/rules/working-directory.md",
        evaluator=evaluator,  # type: ignore[arg-type]
    )


def test_finding_construction_sets_all_fields() -> None:
    finding = _finding()
    assert finding.rule_id == "TW-GIT-001@v1"
    assert finding.severity == "warn"
    assert finding.message == "broad staging at the coding-root"
    assert finding.observed == "git add -A"
    assert finding.provenance == ".claude/rules/working-directory.md"
    assert finding.evaluator == "workspace"


def test_finding_rejects_invalid_severity() -> None:
    with pytest.raises(ValueError, match="invalid severity"):
        _finding(severity="critical")


def test_finding_rejects_invalid_evaluator() -> None:
    with pytest.raises(ValueError, match="invalid evaluator"):
        _finding(evaluator="shell")


def test_finding_is_frozen() -> None:
    finding = _finding()
    with pytest.raises(Exception):  # noqa: B017 - dataclasses raises FrozenInstanceError
        finding.severity = "fail"  # type: ignore[misc]


def test_report_defaults() -> None:
    report = Report(target="/repo")
    assert report.schema_version == SCHEMA_VERSION == 1
    assert report.findings == []


def test_report_to_dict_key_order_is_deterministic() -> None:
    report = Report(target="/repo", findings=[_finding()])
    assert list(report.to_dict().keys()) == ["schema_version", "target", "findings"]


def test_finding_to_dict_key_order_matches_plan_section_5() -> None:
    keys = list(_finding().to_dict().keys())
    assert keys == ["rule_id", "severity", "message", "observed", "provenance", "evaluator"]


def test_exit_code_empty_report_is_ok() -> None:
    assert exit_code_for(Report(target="/repo")) is ExitCode.OK
    assert int(ExitCode.OK) == 0


def test_exit_code_warn_only_is_ok() -> None:
    report = Report(target="/repo", findings=[_finding(severity="warn")])
    assert exit_code_for(report) is ExitCode.OK


def test_exit_code_fail_is_blocking() -> None:
    report = Report(target="/repo", findings=[_finding(severity="fail")])
    assert exit_code_for(report) is ExitCode.BLOCKING
    assert int(ExitCode.BLOCKING) == 1


def test_exit_code_unknown_is_invalid() -> None:
    report = Report(target="/repo", findings=[_finding(severity="unknown")])
    assert exit_code_for(report) is ExitCode.INVALID
    assert int(ExitCode.INVALID) == 2


def test_exit_code_fail_takes_precedence_over_unknown() -> None:
    report = Report(
        target="/repo",
        findings=[_finding(severity="unknown"), _finding(severity="fail")],
    )
    assert exit_code_for(report) is ExitCode.BLOCKING


def test_json_round_trip_is_lossless() -> None:
    report = Report(
        target="/repo",
        findings=[_finding(severity="fail"), _finding(severity="unknown")],
    )
    restored = Report.from_json(report.to_json())
    assert restored == report


def test_json_serialization_is_deterministic() -> None:
    report = Report(target="/repo", findings=[_finding()])
    first = report.to_json()
    second = report.to_json()
    assert first == second
    # Re-serializing after a round trip is byte-identical too.
    assert Report.from_json(first).to_json() == first


def test_from_dict_tolerates_current_schema_version() -> None:
    report = Report.from_dict({"schema_version": 1, "target": "/repo", "findings": []})
    assert report.schema_version == 1


def test_from_dict_refuses_newer_schema_version() -> None:
    with pytest.raises(ValueError, match="unsupported schema_version"):
        Report.from_dict({"schema_version": 2, "target": "/repo", "findings": []})
