"""Canonical rule registry -- the single source of truth for tripwire rules.

Per ``plans/plan.md`` section 6 ("One rule owner"), every workspace check and
command explanation shares one registry entry that owns the rule's stable id,
severity, human message, provenance, and which evaluator surfaces it. A rule may
expose one or both evaluators without duplicating policy text.

Rule identifiers use the versioned categorical format ``TW-<AREA>-<NNN>@v<M>``
(section 6, "Rule identifiers"); ``AREA`` is one of {GIT, WTR, SES, CMD, SHL,
SEC} and ``NNN`` is scoped per area. IDs are defined once here and consumed by
``workspace.py``, ``command.py``, fixtures, and JSON reports. A semantic change
bumps ``@v<M>``; an id is never reused or re-meant.

Both evaluator surfaces are now wired: ``workspace.py`` implements the
workspace-evaluator rules 1-6 (build step 2) and ``command.py`` implements the
command-evaluator rules -- rule 2's command side plus 7-10 (build step 3). Each
consumer imports the ``Rule`` objects below and calls :meth:`Rule.finding` with
its evaluator; this registry stays the single owner of every rule's id,
severity, message and provenance.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from tripwire.models import Evaluator, Finding, Severity

#: Stable rule-id grammar from ``plans/plan.md`` section 6. Validated at import
#: so a malformed or off-enum id fails loudly rather than shipping in a report.
_RULE_ID_RE = re.compile(r"^TW-(?:GIT|WTR|SES|CMD|SHL|SEC)-\d{3}@v\d+$")


@dataclass(frozen=True)
class Rule:
    """One registry entry: the owner of a rule's id, policy text, and surfaces.

    ``severity`` is the rule's *default* verdict weight; a probe may override it
    for a specific observation (for example, emitting ``unknown`` when an
    evaluation is incomplete). ``evaluators`` lists every surface that may raise
    the rule; :meth:`finding` refuses an evaluator the rule does not expose.
    """

    id: str
    title: str
    message: str
    severity: Severity
    provenance: str
    evaluators: tuple[Evaluator, ...]

    def finding(
        self,
        observed: str,
        *,
        evaluator: Evaluator | None = None,
        severity: Severity | None = None,
        message: str | None = None,
    ) -> Finding:
        """Build a :class:`~tripwire.models.Finding` from this rule + evidence.

        The rule owns ``rule_id``, ``message``, ``provenance`` and the default
        ``severity``; the caller supplies the ``observed`` evidence and, where
        the observation warrants it, a ``severity``/``message`` override (used
        for the ``unknown`` incomplete-evaluation case in section 6).
        """
        surface: Evaluator = evaluator if evaluator is not None else self.evaluators[0]
        if surface not in self.evaluators:
            raise ValueError(f"rule {self.id} does not expose evaluator {surface!r}")
        return Finding(
            rule_id=self.id,
            severity=severity if severity is not None else self.severity,
            message=message if message is not None else self.message,
            observed=observed,
            provenance=self.provenance,
            evaluator=surface,
        )


# --- V1 rule inventory (plans/plan.md section 6) ----------------------------
#
# Rows 1-6 expose the workspace evaluator (build step 2, workspace.py). Row 2
# also exposes the command evaluator; rows 7-10 are command-only. The command
# surfaces are implemented in build step 3 (command.py).

# Row 1 -- workspace.
RULE_WRONG_REPO_LAYER = Rule(
    id="TW-GIT-002@v1",
    title="Wrong-repo-layer commit target",
    message=(
        "Target root is a coding-root layer that contains nested project repositories; git/gh run "
        "here resolve to the coding-root, so a commit or broad stage can land against the wrong "
        "repo layer. Anchor git operations to the specific nested project's own repo."
    ),
    severity="warn",
    provenance=".claude/rules/working-directory.md",
    evaluators=("workspace",),
)

# Row 2 -- workspace and command (command side wired in build step 3).
RULE_BROAD_STAGING = Rule(
    id="TW-GIT-001@v1",
    title="Broad staging / bare git stash at the coding-root",
    message=(
        "Changes are staged at a coding-root, where a broad `git add -A` or a bare `git stash` "
        "sweeps nested project repos. Prefer path-scoped `git add <paths>` / `git stash push -- "
        "<paths>` and verify the staged set before committing."
    ),
    severity="warn",
    provenance=".claude/rules/working-directory.md",
    evaluators=("workspace", "command"),
)

# Row 3 -- workspace.
RULE_WORKTREE_BRANCH_MISMATCH = Rule(
    id="TW-WTR-001@v1",
    title="Wrong-worktree branch mismatch",
    message=(
        "This linked worktree has a detached HEAD (it is on no branch), so a commit here advances "
        "no branch and is easily lost -- the classic cwd-drift symptom. Verify `git -C <worktree> "
        "branch --show-current` returns the intended branch before committing."
    ),
    severity="fail",
    provenance="CLAUDE.md (Session wrap & commit discipline)",
    evaluators=("workspace",),
)

# Row 4 -- workspace.
RULE_STALE_WORKTREE = Rule(
    id="TW-WTR-002@v1",
    title="Stale worktree (>1 day or >3 commits behind)",
    message=(
        "This worktree's branch is stale (more than 3 commits behind its base branch, or its tip "
        "commit is over a day old). Run `git merge <base>` before any test gate so results reflect "
        "current base."
    ),
    severity="warn",
    provenance=".claude/rules/worktree-hygiene.md",
    evaluators=("workspace",),
)

# Row 5 -- workspace (session/state-file probe; coding-root discovered by marker).
RULE_CONCURRENT_STATE_FILES = Rule(
    id="TW-SES-001@v1",
    title="Concurrent .plan-expedite-state.* state files",
    message=(
        "`.plan-expedite-state.*` files are present at the coding-root, which usually means "
        "another plan-expedite/build session is mid-flight; starting another risks a state-file "
        "collision. Surface and confirm no concurrent session before proceeding."
    ),
    severity="warn",
    provenance="CLAUDE.md (Parallel session safety)",
    evaluators=("workspace",),
)

# Row 6 -- workspace.
RULE_ACTIVE_PARALLEL_SESSIONS = Rule(
    id="TW-SES-002@v1",
    title="Active worktrees / recent other-branch commits",
    message=(
        "Additional linked worktrees or recent (<1h) commits on other branches suggest a "
        "concurrent session; a parallel /build-phase or /repo-sync can race. Check `git worktree "
        "list` and recent branch activity before starting one."
    ),
    severity="warn",
    provenance="CLAUDE.md (Parallel session safety)",
    evaluators=("workspace",),
)

# Rows 7-10 -- command-only. Implemented by command.py (build step 3); no
# workspace probe raises these.
RULE_DESTRUCTIVE_GIT = Rule(
    id="TW-GIT-003@v1",
    title="Destructive git (reset --hard, push --force, checkout --)",
    message=(
        "Command performs a destructive git operation (`reset --hard`, `push --force`, "
        "`checkout -- <path>`) that discards work irrecoverably. Run a merge-base/ancestor check "
        "first and prefer a non-destructive alternative."
    ),
    severity="fail",
    provenance=".claude/rules/worktree-hygiene.md; docs/friction-catalog.md",
    evaluators=("command",),
)

RULE_NAME_BASED_KILL = Rule(
    id="TW-CMD-001@v1",
    title="Name-based process kill",
    message=(
        "Command kills processes by name (`taskkill /IM`, `Stop-Process -Name`), which can "
        "terminate unrelated processes. Kill by PID with a tree kill (`taskkill /T /F /PID <pid>`)."
    ),
    severity="fail",
    provenance="docs/lessons-learned.md (Subprocess tree-kill on Windows)",
    evaluators=("command",),
)

RULE_SHELL_MISMATCH = Rule(
    id="TW-SHL-001@v1",
    title="Shell mismatch (bash-ism handed to PowerShell 5.1)",
    message=(
        "Command uses bash syntax (for example `&&`) that is a parser error in PowerShell 5.1. "
        "Split into separate statements or use `; if ($?) { ... }` for conditional chaining."
    ),
    severity="warn",
    provenance=".claude/rules/windows-shell.md",
    evaluators=("command",),
)

RULE_SECRET_FILE_DUMP = Rule(
    id="TW-SEC-001@v1",
    title="Secret-file dump via cat/type/grep",
    message=(
        "Command prints the contents of a secrets-bearing file (`cat`/`type`/`grep`). Use "
        "metadata-only checks (`stat`, `wc -c`) or effect-based verification instead of dumping "
        "secret contents."
    ),
    severity="fail",
    provenance=".claude/rules/security.md (Never dump secret file contents)",
    evaluators=("command",),
)


#: Every registered rule, in inventory order (rows 1-10). Single source of truth.
RULES: tuple[Rule, ...] = (
    RULE_BROAD_STAGING,
    RULE_WRONG_REPO_LAYER,
    RULE_WORKTREE_BRANCH_MISMATCH,
    RULE_STALE_WORKTREE,
    RULE_CONCURRENT_STATE_FILES,
    RULE_ACTIVE_PARALLEL_SESSIONS,
    RULE_DESTRUCTIVE_GIT,
    RULE_NAME_BASED_KILL,
    RULE_SHELL_MISMATCH,
    RULE_SECRET_FILE_DUMP,
)


def _validate_registry(rules: tuple[Rule, ...]) -> dict[str, Rule]:
    """Index the registry by id, refusing malformed ids or duplicates at import."""
    by_id: dict[str, Rule] = {}
    for rule in rules:
        if not _RULE_ID_RE.match(rule.id):
            raise ValueError(f"rule id {rule.id!r} does not match TW-<AREA>-<NNN>@v<M>")
        if not rule.evaluators:
            raise ValueError(f"rule {rule.id} exposes no evaluator")
        if rule.id in by_id:
            raise ValueError(f"duplicate rule id {rule.id!r}")
        by_id[rule.id] = rule
    return by_id


#: Registry indexed by stable id; consumed by fixtures and report readers.
RULES_BY_ID: dict[str, Rule] = _validate_registry(RULES)


def rules_for(evaluator: Evaluator) -> tuple[Rule, ...]:
    """Return every rule that exposes ``evaluator`` (inventory order preserved)."""
    return tuple(rule for rule in RULES if evaluator in rule.evaluators)
