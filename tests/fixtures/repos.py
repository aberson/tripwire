"""Builders for synthetic git-repo fixtures (bad + clean workspace states).

Each ``build_*`` function takes a pytest ``tmp_path`` (a :class:`pathlib.Path`)
and returns the path a test should point ``tripwire check --root`` at. Repos are
built with real ``git`` so probes observe genuine state; git identity and a
deterministic default branch (``main``) are pinned per-invocation so the
fixtures are hermetic and reproducible.

Bad fixtures are engineered to trip a single primary rule; two (detached and
stale worktrees) unavoidably also trip rule 6 (any linked worktree is, by
definition, an active worktree), so workspace tests assert the *expected* id is
present rather than that it is the only finding.
"""

from __future__ import annotations

import subprocess
from pathlib import Path

#: Deterministic git config applied to every invocation (identity, no signing,
#: ``main`` as the default branch so branch names are stable across platforms).
_GIT_CONF = [
    "-c",
    "user.name=Tripwire Test",
    "-c",
    "user.email=test@example.invalid",
    "-c",
    "commit.gpgsign=false",
    "-c",
    "init.defaultBranch=main",
]


def _git(cwd: Path, *args: str) -> str:
    """Run a git command in ``cwd`` (checked); return stripped stdout."""
    result = subprocess.run(
        ["git", *_GIT_CONF, *args],
        cwd=str(cwd),
        check=True,
        capture_output=True,
        text=True,
        encoding="utf-8",
    )
    return result.stdout.strip()


def _init(path: Path) -> Path:
    path.mkdir(parents=True, exist_ok=True)
    _git(path, "init")
    return path


def _write(repo: Path, rel: str, content: str = "x\n") -> Path:
    target = repo / rel
    target.parent.mkdir(parents=True, exist_ok=True)
    target.write_text(content, encoding="utf-8")
    return target


def _commit(repo: Path, rel: str, content: str = "x\n", message: str = "commit") -> None:
    _write(repo, rel, content)
    _git(repo, "add", rel)
    _git(repo, "commit", "-m", message)


def _add_coding_root_marker(repo: Path) -> None:
    """Commit the ``.claude/observatory/registry.toml`` coding-root marker."""
    _write(repo, ".claude/observatory/registry.toml", "# coding-root marker\n")
    _git(repo, "add", ".claude/observatory/registry.toml")
    _git(repo, "commit", "-m", "add coding-root marker")


# --- Clean (negative) fixtures ---------------------------------------------


def build_clean_coding_root(tmp_path: Path) -> Path:
    """A coding-root with the marker committed, on ``main``, otherwise pristine.

    One worktree, one branch, no nested repos, no staged changes, no state
    files. Every workspace probe should stay silent -> zero findings.
    """
    repo = _init(tmp_path / "coding_root")
    _add_coding_root_marker(repo)
    return repo


# --- Bad (positive) fixtures -----------------------------------------------


def build_nested_repo_layer(tmp_path: Path) -> Path:
    """Rule 1 (TW-GIT-002): coding-root containing a nested project repo."""
    repo = build_clean_coding_root(tmp_path)
    nested = _init(repo / "proj")
    _commit(nested, "file.txt", "nested\n", "nested initial")
    return repo


def build_staged_coding_root(tmp_path: Path) -> Path:
    """Rule 2 (TW-GIT-001): staged (uncommitted) changes at a coding-root."""
    repo = build_clean_coding_root(tmp_path)
    _write(repo, "newfile.txt", "staged content\n")
    _git(repo, "add", "newfile.txt")  # staged but not committed
    return repo


def build_detached_worktree(tmp_path: Path) -> Path:
    """Rule 3 (TW-WTR-001): a linked worktree checked out on a detached HEAD."""
    main = build_clean_coding_root(tmp_path)
    head = _git(main, "rev-parse", "HEAD")
    worktree = tmp_path / "wt_detached"
    _git(main, "worktree", "add", "--detach", str(worktree), head)
    return worktree


def build_stale_worktree(tmp_path: Path) -> Path:
    """Rule 4 (TW-WTR-002): a linked worktree >3 commits behind its base branch."""
    main = build_clean_coding_root(tmp_path)
    _git(main, "branch", "feature")
    worktree = tmp_path / "wt_feature"
    _git(main, "worktree", "add", str(worktree), "feature")
    for i in range(4):
        _commit(main, f"advance_{i}.txt", f"{i}\n", f"main advance {i}")
    return worktree


def build_concurrent_state_files(tmp_path: Path) -> Path:
    """Rule 5 (TW-SES-001): `.plan-expedite-state.*` present at the coding-root."""
    repo = build_clean_coding_root(tmp_path)
    _write(repo, ".plan-expedite-state.session-abc123", "{}\n")
    return repo


def build_active_parallel_sessions(tmp_path: Path) -> Path:
    """Rule 6 (TW-SES-002): a recent commit on a branch other than the current."""
    repo = build_clean_coding_root(tmp_path)
    _git(repo, "checkout", "-b", "other-session")
    _commit(repo, "other.txt", "concurrent\n", "other-session work")
    _git(repo, "checkout", "main")
    return repo


# --- Incomplete-evaluation / invalid-input fixtures ------------------------


def build_markerless_repo(tmp_path: Path) -> Path:
    """A plain git repo with no coding-root marker (rule 5 -> unknown, not clean)."""
    repo = _init(tmp_path / "plain")
    _commit(repo, "file.txt", "x\n", "initial")
    return repo


def build_non_repo_dir(tmp_path: Path) -> Path:
    """A directory that is not a git repository (CLI invalid input -> exit 2)."""
    path = tmp_path / "not_a_repo"
    path.mkdir()
    return path
