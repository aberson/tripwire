"""Determinism regression tests (plan Step 4: lock byte-identical report output).

Proves that identical input yields byte-identical JSON, that key ordering is the
fixed section-5 insertion order (NOT alphabetized -- so it cannot silently become
sort-dependent), and that finding ordering is stable across repeated runs for
both the command and workspace evaluators.
"""

from __future__ import annotations

import json
from pathlib import Path

from fixtures.repos import build_nested_repo_layer
from tripwire.command import classify
from tripwire.models import Finding, Report
from tripwire.workspace import resolve_target, run_workspace_probes

_MULTI = "git add -A && git reset --hard"


def _finding() -> Finding:
    return Finding(
        rule_id="TW-GIT-001@v1",
        severity="warn",
        message="broad staging at the coding-root",
        observed="git add -A",
        provenance=".claude/rules/working-directory.md",
        evaluator="workspace",
    )


def test_command_report_json_is_byte_identical_across_runs() -> None:
    first = Report(target=_MULTI, findings=list(classify(_MULTI).findings)).to_json(indent=2)
    second = Report(target=_MULTI, findings=list(classify(_MULTI).findings)).to_json(indent=2)
    assert first == second


def test_workspace_report_json_is_byte_identical_across_runs(tmp_path: Path) -> None:
    target = resolve_target(str(build_nested_repo_layer(tmp_path)))
    assert target is not None
    first = Report(target=target, findings=run_workspace_probes(target)).to_json(indent=2)
    second = Report(target=target, findings=run_workspace_probes(target)).to_json(indent=2)
    assert first == second


def test_report_key_order_is_insertion_not_sorted() -> None:
    keys = list(Report(target="/x", findings=[_finding()]).to_dict().keys())
    assert keys == ["schema_version", "target", "findings"]
    # Alphabetical would be [findings, schema_version, target]; proving keys are
    # not sorted guards against a future switch to sort_keys-based ordering.
    assert keys != sorted(keys)


def test_finding_key_order_is_insertion_not_sorted() -> None:
    keys = list(_finding().to_dict().keys())
    assert keys == ["rule_id", "severity", "message", "observed", "provenance", "evaluator"]
    assert keys != sorted(keys)


def test_to_json_does_not_sort_keys() -> None:
    report = Report(target="/x", findings=[_finding()])
    sorted_form = json.dumps(report.to_dict(), sort_keys=True, ensure_ascii=False)
    # The real serializer preserves insertion order, so it must differ from the
    # sort_keys=True rendering (which reorders both report and finding keys).
    assert report.to_json() != sorted_form


def test_command_finding_order_is_stable_across_repeated_runs() -> None:
    orders = [[f.rule_id for f in classify(_MULTI).findings] for _ in range(25)]
    assert all(order == orders[0] for order in orders)
    assert orders[0] == ["TW-GIT-001@v1", "TW-GIT-003@v1", "TW-SHL-001@v1"]
