"""Canonical typed report contract for tripwire.

Field shapes are pinned by ``plans/plan.md`` section 5 (New Components); the
severity/evaluator vocabularies, the rule-id format, and the exit-code contract
are pinned by section 6 (Design Decisions). Everything here is stdlib-only so
the runtime package carries no third-party dependency.

Pinned invariants (do not drift without a plan change):

* ``Finding``: ``rule_id``, ``severity``, ``message``, ``observed``,
  ``provenance``, ``evaluator`` -- section 5 finding table.
* ``Report``: ``schema_version`` (int, ``1``), ``target`` (str),
  ``findings`` (list of Finding) -- section 5 report table.
* Exit contract (section 6): ``0`` no blocking findings, ``1`` blocking
  findings, ``2`` invalid input or incomplete evaluation. JSON mirrors it.
* Readers tolerate older ``schema_version`` and refuse newer with an explicit
  error (section 5 report table note).
"""

from __future__ import annotations

import json
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, Literal, get_args

Severity = Literal["warn", "fail", "unknown"]
Evaluator = Literal["workspace", "command"]

#: Allowed severity strings, derived from the ``Severity`` alias so the runtime
#: validation and the static type can never drift apart.
SEVERITIES: tuple[Severity, ...] = get_args(Severity)

#: Allowed evaluator strings, derived from the ``Evaluator`` alias.
EVALUATORS: tuple[Evaluator, ...] = get_args(Evaluator)

#: The only report schema version emitted or fully trusted by this build.
SCHEMA_VERSION = 1


class ExitCode(IntEnum):
    """Process exit codes, pinned by ``plans/plan.md`` section 6.

    A single value covers exit ``2`` because the plan assigns it two related
    meanings: invalid input (handled at the CLI boundary) and incomplete
    evaluation (an ``unknown`` finding that must never read as success).
    """

    OK = 0
    BLOCKING = 1
    INVALID = 2


@dataclass(frozen=True)
class Finding:
    """A single evidence-bearing verdict from one evaluator.

    Frozen: a finding is an immutable record. ``severity`` and ``evaluator``
    are validated at construction so an out-of-vocabulary value fails loudly
    rather than silently serializing into a report.
    """

    rule_id: str
    severity: Severity
    message: str
    observed: str
    provenance: str
    evaluator: Evaluator

    def __post_init__(self) -> None:
        if self.severity not in SEVERITIES:
            raise ValueError(f"invalid severity {self.severity!r}; expected one of {SEVERITIES}")
        if self.evaluator not in EVALUATORS:
            raise ValueError(f"invalid evaluator {self.evaluator!r}; expected one of {EVALUATORS}")

    def to_dict(self) -> dict[str, str]:
        """Serialize to a dict with the section-5 field order, deterministically."""
        return {
            "rule_id": self.rule_id,
            "severity": self.severity,
            "message": self.message,
            "observed": self.observed,
            "provenance": self.provenance,
            "evaluator": self.evaluator,
        }

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> Finding:
        """Rebuild a ``Finding`` from a parsed JSON object (validated in ``__post_init__``)."""
        return cls(
            rule_id=str(data["rule_id"]),
            severity=data["severity"],
            message=str(data["message"]),
            observed=str(data["observed"]),
            provenance=str(data["provenance"]),
            evaluator=data["evaluator"],
        )


@dataclass
class Report:
    """A run's target plus the ordered list of findings it produced.

    Field order in :meth:`to_dict` follows the section-5 report table
    (``schema_version``, ``target``, ``findings``) so JSON key ordering is
    deterministic regardless of construction order.
    """

    target: str
    findings: list[Finding] = field(default_factory=list)
    schema_version: int = SCHEMA_VERSION

    def to_dict(self) -> dict[str, Any]:
        """Serialize to a dict with a deterministic, section-5 key order."""
        return {
            "schema_version": self.schema_version,
            "target": self.target,
            "findings": [finding.to_dict() for finding in self.findings],
        }

    def to_json(self, *, indent: int | None = None) -> str:
        """Serialize to a JSON string with deterministic key ordering.

        Keys are emitted in the fixed section-5 order (not alphabetized), so
        ``report.to_json()`` is byte-stable across runs and platforms.
        """
        return json.dumps(self.to_dict(), indent=indent, ensure_ascii=False)

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> Report:
        """Rebuild a ``Report`` from a parsed JSON object.

        Older ``schema_version`` values are tolerated; a newer version than
        this build understands is refused with an explicit error (section 5).
        """
        version = int(data.get("schema_version", SCHEMA_VERSION))
        if version > SCHEMA_VERSION:
            raise ValueError(
                f"unsupported schema_version {version}; this reader supports up to {SCHEMA_VERSION}"
            )
        findings = [Finding.from_dict(item) for item in data.get("findings", [])]
        return cls(target=str(data["target"]), findings=findings, schema_version=version)

    @classmethod
    def from_json(cls, text: str) -> Report:
        """Parse a JSON string into a ``Report`` (see :meth:`from_dict`)."""
        return cls.from_dict(json.loads(text))


def exit_code_for(report: Report) -> ExitCode:
    """Map a report's findings to the process exit code, per plan section 6.

    Precedence (most-actionable signal wins):

    * any ``fail`` finding  -> :attr:`ExitCode.BLOCKING` (1)
    * else any ``unknown``  -> :attr:`ExitCode.INVALID` (2), an incomplete
      evaluation that section 6 forbids from reading as success
    * else (``warn``-only or no findings) -> :attr:`ExitCode.OK` (0)

    Invalid *input* (e.g. no enclosing repo and no ``--root``) also maps to
    ``2`` but is handled at the CLI boundary, not from findings.
    """
    severities = {finding.severity for finding in report.findings}
    if "fail" in severities:
        return ExitCode.BLOCKING
    if "unknown" in severities:
        return ExitCode.INVALID
    return ExitCode.OK
