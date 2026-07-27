"""tripwire -- local-first preflight checks for known workspace failure modes.

Public surface is the report contract in :mod:`tripwire.models` plus the CLI
entry point in :mod:`tripwire.cli`. Rule/workspace/command logic lands in later
build steps (see ``plans/plan.md`` section 7).
"""

from __future__ import annotations

from tripwire.models import (
    EVALUATORS,
    SCHEMA_VERSION,
    SEVERITIES,
    Evaluator,
    ExitCode,
    Finding,
    Report,
    Severity,
    exit_code_for,
)

__version__ = "0.1.0"

__all__ = [
    "EVALUATORS",
    "SCHEMA_VERSION",
    "SEVERITIES",
    "Evaluator",
    "ExitCode",
    "Finding",
    "Report",
    "Severity",
    "__version__",
    "exit_code_for",
]
