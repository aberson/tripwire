"""Read-only git / worktree / session probes for workspace rules 1-6.

Every probe here is strictly read-only: it inspects the target with git *read*
subcommands (``rev-parse``, ``branch``, ``rev-list``, ``log``, ``worktree
list``, ``diff --cached``, ``for-each-ref``, ``symbolic-ref``) and filesystem
reads only. Nothing mutates the target repository or working tree.

Target-root resolution and the coding-root marker walk follow ``plans/plan.md``
section 6:

* The default target is the enclosing git root of the cwd; ``--root`` overrides
  the starting point. No enclosing repository is invalid input (the CLI maps it
  to exit 2), never a heuristic fallback -- see :func:`resolve_target`.
* Session/state-file probes never assume the dev layout. They discover the
  coding-root by walking up to the outermost git root carrying the marker file
  ``.claude/observatory/registry.toml`` (a path convention only). If no marker
  is found, the probe reports severity ``unknown`` with the walked path as
  evidence -- never a clean pass. See :func:`discover_coding_root` and
  :func:`probe_concurrent_state_files`.

The message/provenance/default-severity of each finding is owned by the
``rules.py`` registry; probes supply only the observed evidence.
"""

from __future__ import annotations

import glob
import os
import subprocess
import time
from collections.abc import Callable

from tripwire import rules
from tripwire.models import Finding
from tripwire.rules import Rule

#: Marker file that identifies a coding-root (path convention; section 6).
_MARKER_RELPATH = os.path.join(".claude", "observatory", "registry.toml")

#: Directories the nested-repo scan never descends into (dependency/cache trees
#: that legitimately vendor their own repos and would only add false positives).
_SCAN_EXCLUDES = frozenset(
    {
        ".git",
        ".venv",
        "venv",
        "node_modules",
        "__pycache__",
        ".mypy_cache",
        ".pytest_cache",
        ".ruff_cache",
        ".tox",
        "site-packages",
        "dist",
        "build",
        ".idea",
        ".vs",
        ".vscode",
    }
)

#: Per-call git timeout (seconds). Probes stay well under the 10s budget even if
#: an individual git invocation stalls.
_GIT_TIMEOUT = 8.0

#: A recent commit / fresh state file is "concurrent" if newer than this (1h).
_RECENT_SECONDS = 3600

#: Clock-skew tolerance (seconds) for the rule-6 "recent commit" heuristic. A
#: commit whose timestamp is in the *future* by more than this is a clock-skew
#: artifact, not a genuine just-now commit, and is not counted as a concurrent
#: signal -- otherwise a repo with a future-dated commit (skewed authoring clock)
#: would false-positive as an active parallel session. Minor skew within the
#: tolerance is still treated as recent.
_CLOCK_SKEW_TOLERANCE = 300

#: Staleness thresholds (worktree-hygiene.md: >1 day OR >3 commits behind).
_STALE_COMMITS_BEHIND = 3
_STALE_AGE_SECONDS = 86400

#: Message on the ``unknown`` finding a probe emits when a git subprocess exceeds
#: the per-call timeout: the check is incomplete and must never read as a pass.
_GIT_TIMEOUT_MESSAGE = (
    "A git subprocess exceeded the per-call timeout, so this check could not "
    "complete. This is reported as unknown (incomplete evaluation), never a clean "
    "pass -- a hung or slow git must not degrade to a false all-clear."
)


class GitTimeout(Exception):
    """Raised by :func:`_git` when a git subprocess exceeds the per-call timeout.

    Distinguished from an ordinary non-zero return so a stalled git degrades a
    probe to a section-8 ``unknown`` finding rather than a silent clean pass.
    The message carries the git argument vector that timed out.
    """


def _git(target: str, *args: str) -> tuple[int, str]:
    """Run one read-only ``git -C <target> <args>``; return (returncode, stdout).

    A missing git binary or any non-timeout failure is reported as a non-zero
    return code so probes degrade to "no finding" rather than crashing a check.
    A *timeout* is different: it raises :class:`GitTimeout` so the caller can
    surface an ``unknown`` (incomplete evaluation) finding instead of silently
    reading a hung git as a clean pass (plan section 8, "False assurance").
    """
    try:
        proc = subprocess.run(
            ["git", "-C", target, *args],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=_GIT_TIMEOUT,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:  # must precede SubprocessError below
        raise GitTimeout(f"git {' '.join(args)}") from exc
    except (OSError, subprocess.SubprocessError):
        return (127, "")
    return (proc.returncode, proc.stdout.strip())


def resolve_target(start: str) -> str | None:
    """Resolve the enclosing git root of ``start``, or ``None`` if there is none.

    ``None`` is the section-6 "no enclosing repository" case; the CLI maps it to
    invalid input (exit 2). A non-``None`` result is an absolute git top-level
    path suitable for the read-only probes.
    """
    rc, out = _git(start, "rev-parse", "--show-toplevel")
    if rc != 0 or not out:
        return None
    return os.path.abspath(out)


def _has_marker(path: str) -> bool:
    """True if ``path`` carries the coding-root marker file."""
    return os.path.isfile(os.path.join(path, _MARKER_RELPATH))


def discover_coding_root(target: str) -> str | None:
    """Walk up from ``target`` to the outermost git root carrying the marker.

    Returns the highest ancestor git root (including ``target`` itself) that
    carries ``.claude/observatory/registry.toml``, or ``None`` if no ancestor
    git root carries it. Section 6: session/state-file probes use this and, on
    ``None``, must report ``unknown`` -- never a clean pass.
    """
    outermost: str | None = None
    path = os.path.abspath(target)
    while True:
        rc, top = _git(path, "rev-parse", "--show-toplevel")
        if rc != 0 or not top:
            break
        top_abs = os.path.abspath(top)
        if _has_marker(top_abs):
            outermost = top_abs
        parent = os.path.dirname(top_abs)
        if parent == top_abs:
            break
        path = parent
    return outermost


def _git_dir_abs(target: str) -> str | None:
    """Absolute path to ``target``'s git directory, or ``None`` if not a repo."""
    rc, out = _git(target, "rev-parse", "--git-dir")
    if rc != 0 or not out:
        return None
    return os.path.abspath(os.path.join(target, out))


def _is_linked_worktree(target: str) -> bool:
    """True if ``target`` is a linked worktree (its git dir differs from common)."""
    rc1, git_dir = _git(target, "rev-parse", "--git-dir")
    rc2, common_dir = _git(target, "rev-parse", "--git-common-dir")
    if rc1 != 0 or rc2 != 0 or not git_dir or not common_dir:
        return False
    git_dir_abs = os.path.normcase(os.path.abspath(os.path.join(target, git_dir)))
    common_abs = os.path.normcase(os.path.abspath(os.path.join(target, common_dir)))
    return git_dir_abs != common_abs


def _current_branch(target: str) -> str | None:
    """Current branch short name, or ``None`` when HEAD is detached."""
    rc, out = _git(target, "symbolic-ref", "--quiet", "--short", "HEAD")
    if rc != 0 or not out:
        return None
    return out


def _mid_git_operation(target: str) -> bool:
    """True during a bisect/rebase/merge/cherry-pick (detached HEAD is expected)."""
    git_dir = _git_dir_abs(target)
    if git_dir is None:
        return False
    sentinels = ("BISECT_LOG", "rebase-merge", "rebase-apply", "MERGE_HEAD", "CHERRY_PICK_HEAD")
    return any(os.path.exists(os.path.join(git_dir, name)) for name in sentinels)


def find_nested_repos(target: str, max_depth: int = 3) -> list[str]:
    """Return relative paths of nested git repos under ``target`` (bounded scan).

    A nested repo is any directory below ``target`` that carries its own ``.git``
    (directory or gitlink file). ``target``'s own repo is skipped, dependency and
    cache trees are pruned, and the walk stops descending once it enters a nested
    repo, so the result lists each nested repo root once.
    """
    target_abs = os.path.abspath(target)
    found: list[str] = []
    for root, dirs, files in os.walk(target_abs):
        rel = os.path.relpath(root, target_abs)
        is_target = rel == os.curdir
        if not is_target and (".git" in dirs or ".git" in files):
            found.append(rel.replace(os.sep, "/"))
            dirs[:] = []
            continue
        dirs[:] = [d for d in dirs if d not in _SCAN_EXCLUDES]
        depth = 0 if is_target else rel.count(os.sep) + 1
        if depth >= max_depth:
            dirs[:] = []
    return sorted(found)


def _sample(items: list[str], limit: int = 5) -> str:
    """Render a bounded, deterministic sample of ``items`` for the evidence line."""
    shown = ", ".join(items[:limit])
    extra = len(items) - limit
    return shown if extra <= 0 else f"{shown} (+{extra} more)"


def probe_wrong_repo_layer(target: str) -> list[Finding]:
    """Rule 1: target root is a coding-root *layer* containing nested project repos.

    Gated on the coding-root marker (like the rule-2 workspace side): the
    "wrong repo layer" hazard is specifically that git/gh at the marker-bearing
    coding-root resolve to that layer rather than a nested project's own repo.
    A markerless repo that merely contains a nested ``.git`` -- for example a git
    submodule's gitlink, or a vendored checkout -- is an ordinary repository, not
    a coding-root, so it is not flagged here (false-positive suppression). The
    marker convention is the same path-only signal used everywhere in section 6.
    """
    if not _has_marker(target):
        return []
    nested = find_nested_repos(target)
    if not nested:
        return []
    observed = f"nested git repositories under target: {_sample(nested)}"
    return [rules.RULE_WRONG_REPO_LAYER.finding(observed, evaluator="workspace")]


def probe_broad_staging(target: str) -> list[Finding]:
    """Rule 2 (workspace side): staged changes at a coding-root risk a broad sweep.

    Only fires when the target root itself carries the coding-root marker -- that
    is exactly the layer where a broad `git add -A` / bare `git stash` sweeps
    nested repos. Staging inside a nested project repo is normal and is ignored.
    """
    if not _has_marker(target):
        return []
    rc, out = _git(target, "diff", "--cached", "--name-only")
    if rc != 0:
        return []
    staged = [line for line in out.splitlines() if line.strip()]
    if not staged:
        return []
    observed = f"{len(staged)} staged path(s) at coding-root: {_sample(staged)}"
    return [rules.RULE_BROAD_STAGING.finding(observed, evaluator="workspace")]


def probe_worktree_branch_mismatch(target: str) -> list[Finding]:
    """Rule 3: a linked worktree on a detached HEAD (commit here advances no branch).

    We flag only the unambiguous, high-confidence sub-case (a linked worktree
    whose HEAD is detached and that is not mid bisect/rebase/merge). The general
    "is this the *intended* branch?" question needs operator knowledge the probe
    cannot observe read-only, so it is deliberately out of scope here.
    """
    if not _is_linked_worktree(target):
        return []
    if _mid_git_operation(target):
        return []
    if _current_branch(target) is not None:
        return []
    _, head = _git(target, "rev-parse", "--short", "HEAD")
    observed = f"detached HEAD at {head or '?'} in linked worktree {target}"
    return [rules.RULE_WORKTREE_BRANCH_MISMATCH.finding(observed, evaluator="workspace")]


def _base_branch(target: str, current: str | None) -> str | None:
    """Pick the repo's base branch (main/master) that isn't the current branch."""
    for candidate in ("main", "master"):
        if candidate == current:
            continue
        rc, _ = _git(target, "rev-parse", "--verify", "--quiet", f"refs/heads/{candidate}")
        if rc == 0:
            return candidate
    return None


def probe_stale_worktree(target: str, now: float | None = None) -> list[Finding]:
    """Rule 4: a linked worktree >3 commits behind its base or >1 day untouched."""
    if not _is_linked_worktree(target):
        return []
    moment = time.time() if now is None else now
    reasons: list[str] = []

    current = _current_branch(target)
    base = _base_branch(target, current)
    if base is not None:
        rc, out = _git(target, "rev-list", "--count", f"HEAD..{base}")
        if rc == 0 and out.isdigit():
            behind = int(out)
            if behind > _STALE_COMMITS_BEHIND:
                reasons.append(f"{behind} commits behind {base}")

    rc, out = _git(target, "log", "-1", "--format=%ct")
    if rc == 0 and out.isdigit():
        age = moment - int(out)
        if age > _STALE_AGE_SECONDS:
            reasons.append(f"tip commit is {age / 86400:.1f} days old")

    if not reasons:
        return []
    observed = f"{'; '.join(reasons)} (worktree {target})"
    return [rules.RULE_STALE_WORKTREE.finding(observed, evaluator="workspace")]


def probe_concurrent_state_files(target: str) -> list[Finding]:
    """Rule 5: `.plan-expedite-state.*` files at the coding-root (session/state probe).

    Section 6: discover the coding-root by marker walk; if none is found this
    evaluation is incomplete and must report ``unknown`` with the walked path --
    never a clean pass.
    """
    coding_root = discover_coding_root(target)
    if coding_root is None:
        observed = (
            "no coding-root marker (.claude/observatory/registry.toml) found walking up from "
            f"{os.path.abspath(target)}"
        )
        message = (
            "Coding-root marker not found, so the concurrent-state-file check is incomplete for "
            "this target. This is reported as unknown (incomplete evaluation), never a clean pass."
        )
        return [
            rules.RULE_CONCURRENT_STATE_FILES.finding(
                observed, evaluator="workspace", severity="unknown", message=message
            )
        ]
    matches = sorted(glob.glob(os.path.join(coding_root, ".plan-expedite-state.*")))
    if not matches:
        return []
    names = [os.path.basename(path) for path in matches]
    observed = f"{len(names)} state file(s) at coding-root {coding_root}: {_sample(names)}"
    return [rules.RULE_CONCURRENT_STATE_FILES.finding(observed, evaluator="workspace")]


def probe_active_parallel_sessions(target: str, now: float | None = None) -> list[Finding]:
    """Rule 6: additional worktrees or recent (<1h) commits on other branches.

    Both signals are repo-local (they need no coding-root marker), so this probe
    inspects the target repo directly and always completes -- it never reports
    ``unknown``.
    """
    moment = time.time() if now is None else now
    signals: list[str] = []

    rc, out = _git(target, "worktree", "list", "--porcelain")
    if rc == 0:
        count = sum(1 for line in out.splitlines() if line.startswith("worktree "))
        if count > 1:
            signals.append(f"{count} linked worktrees active")

    current = _current_branch(target)
    rc, out = _git(
        target, "for-each-ref", "--format=%(committerdate:unix) %(refname:short)", "refs/heads"
    )
    if rc == 0:
        recent: list[str] = []
        for line in out.splitlines():
            parts = line.split(" ", 1)
            if len(parts) != 2 or not parts[0].isdigit():
                continue
            timestamp, name = int(parts[0]), parts[1]
            if current is not None and name == current:
                continue
            delta = moment - timestamp
            # Clock-skew guard: a commit dated in the future beyond the tolerance
            # is a skewed-clock artifact, not a genuine just-now commit, so it is
            # not counted as a concurrent signal. Minor skew (within tolerance)
            # and any commit in the last hour still count.
            if -_CLOCK_SKEW_TOLERANCE <= delta < _RECENT_SECONDS:
                recent.append(name)
        if recent:
            signals.append(f"recent (<1h) commits on other branch(es): {', '.join(sorted(recent))}")

    if not signals:
        return []
    return [rules.RULE_ACTIVE_PARALLEL_SESSIONS.finding("; ".join(signals), evaluator="workspace")]


#: Workspace probes paired with the rule each raises, in inventory (rule-number)
#: order, for deterministic output. The pairing lets :func:`run_workspace_probes`
#: attribute a git-timeout ``unknown`` finding to the rule whose probe stalled.
#: (The ``now``-taking probes are callable with a single ``target`` argument.)
_WORKSPACE_PROBES: tuple[tuple[Rule, Callable[[str], list[Finding]]], ...] = (
    (rules.RULE_WRONG_REPO_LAYER, probe_wrong_repo_layer),
    (rules.RULE_BROAD_STAGING, probe_broad_staging),
    (rules.RULE_WORKTREE_BRANCH_MISMATCH, probe_worktree_branch_mismatch),
    (rules.RULE_STALE_WORKTREE, probe_stale_worktree),
    (rules.RULE_CONCURRENT_STATE_FILES, probe_concurrent_state_files),
    (rules.RULE_ACTIVE_PARALLEL_SESSIONS, probe_active_parallel_sessions),
)


def run_workspace_probes(target: str) -> list[Finding]:
    """Run every workspace probe against ``target`` and concatenate the findings.

    Findings are returned in inventory (rule-number) order so text and JSON
    reports are deterministic regardless of which probes fire. If a probe's git
    subprocess exceeds the per-call timeout (:class:`GitTimeout`), that probe
    contributes an ``unknown`` finding for its rule instead of silently dropping
    out -- a hung git is an incomplete evaluation, never a clean pass (section 8).
    """
    findings: list[Finding] = []
    for rule, probe in _WORKSPACE_PROBES:
        try:
            findings.extend(probe(target))
        except GitTimeout as exc:
            observed = (
                f"git subprocess exceeded the {_GIT_TIMEOUT:g}s per-call timeout while "
                f"evaluating this rule ({exc}); evaluation incomplete"
            )
            findings.append(
                rule.finding(
                    observed,
                    evaluator="workspace",
                    severity="unknown",
                    message=_GIT_TIMEOUT_MESSAGE,
                )
            )
    return findings
