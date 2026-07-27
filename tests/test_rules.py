"""Tests for the canonical rule registry (plan section 6, "One rule owner")."""

from __future__ import annotations

import re

import pytest

from tripwire.models import SEVERITIES
from tripwire.rules import (
    RULE_BROAD_STAGING,
    RULES,
    RULES_BY_ID,
    Rule,
    rules_for,
)

_ID_RE = re.compile(r"^TW-(GIT|WTR|SES|CMD|SHL|SEC)-\d{3}@v\d+$")

# The full v1 inventory (plan section 6): ten rules, six with a workspace surface.
_EXPECTED_IDS = {
    "TW-GIT-001@v1",
    "TW-GIT-002@v1",
    "TW-WTR-001@v1",
    "TW-WTR-002@v1",
    "TW-SES-001@v1",
    "TW-SES-002@v1",
    "TW-GIT-003@v1",
    "TW-CMD-001@v1",
    "TW-SHL-001@v1",
    "TW-SEC-001@v1",
}


def test_registry_covers_full_v1_inventory() -> None:
    assert {rule.id for rule in RULES} == _EXPECTED_IDS
    assert len(RULES) == len(RULES_BY_ID) == 10


def test_every_id_matches_the_versioned_format() -> None:
    for rule in RULES:
        assert _ID_RE.match(rule.id), rule.id


def test_severities_are_in_vocabulary() -> None:
    for rule in RULES:
        assert rule.severity in SEVERITIES


def test_broad_staging_is_the_pinned_git_001() -> None:
    # Pinned by plan section 6's worked example and the Step-1 model tests.
    assert RULE_BROAD_STAGING.id == "TW-GIT-001@v1"
    assert "command" in RULE_BROAD_STAGING.evaluators
    assert "workspace" in RULE_BROAD_STAGING.evaluators


def test_rules_for_workspace_returns_exactly_rules_1_to_6() -> None:
    assert {rule.id for rule in rules_for("workspace")} == {
        "TW-GIT-001@v1",
        "TW-GIT-002@v1",
        "TW-WTR-001@v1",
        "TW-WTR-002@v1",
        "TW-SES-001@v1",
        "TW-SES-002@v1",
    }


def test_rules_for_command_includes_shared_and_command_only() -> None:
    command_ids = {rule.id for rule in rules_for("command")}
    # Rule 2 is shared; 7-10 are command-only.
    assert command_ids == {
        "TW-GIT-001@v1",
        "TW-GIT-003@v1",
        "TW-CMD-001@v1",
        "TW-SHL-001@v1",
        "TW-SEC-001@v1",
    }


def test_finding_refuses_unexposed_evaluator() -> None:
    with pytest.raises(ValueError, match="does not expose evaluator"):
        # Rule 1 exposes only 'workspace'.
        RULES_BY_ID["TW-GIT-002@v1"].finding("x", evaluator="command")


def test_finding_carries_registry_message_and_provenance() -> None:
    rule = RULES_BY_ID["TW-GIT-001@v1"]
    finding = rule.finding("git add -A", evaluator="workspace")
    assert finding.rule_id == rule.id
    assert finding.message == rule.message
    assert finding.provenance == rule.provenance
    assert finding.severity == rule.severity


def test_finding_allows_severity_and_message_override() -> None:
    rule = RULES_BY_ID["TW-SES-001@v1"]
    finding = rule.finding("walked /x", evaluator="workspace", severity="unknown", message="m")
    assert finding.severity == "unknown"
    assert finding.message == "m"


def test_rule_is_frozen() -> None:
    rule: Rule = RULES[0]
    with pytest.raises(Exception):  # noqa: B017 - dataclass raises FrozenInstanceError
        rule.id = "x"  # type: ignore[misc]
