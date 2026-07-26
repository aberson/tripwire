# tripwire

A local-first preflight utility that turns known workspace failure modes into fast,
evidence-bearing checks. Wrong working directories, wrong worktrees, broad staging, unsafe
process termination, and shell mismatches have recurred despite written guidance; tripwire
operationalizes a small, high-confidence subset of those rules as one-shot checks.

Two entry points:

- `tripwire check` — read-only repository/session-state probes for the current (or `--root`) tree.
- `tripwire command explain -- <command>` — classifies proposed command text for known risky shapes.

## Stack

| Tool | Why |
|---|---|
| Python 3.12+ | Implementation language |
| uv | Environment + dependency management |
| argparse | CLI (no third-party CLI dependency) |
| pytest | Table-driven fixture tests |
| Ruff | Lint + format |
| mypy (strict) | Static typing |

## Prerequisites

- Python 3.12+
- [uv](https://docs.astral.sh/uv/)

## Setup

```bash
uv sync --extra dev
uv run pytest -q          # tests
uv run ruff check .       # lint
uv run mypy --strict src  # types
```

## Usage

```bash
# Check the enclosing git root of the cwd (or an explicit --root)
uv run tripwire check
uv run tripwire check --root <path>

# Explain proposed command text
uv run tripwire command explain -- <command>
```

Exit codes: `0` no blocking findings, `1` blocking findings, `2` invalid input or incomplete
evaluation. JSON output carries the same distinction.

## Design decisions

- **One rule owner.** Workspace checks and command explanations share IDs, severity, rationale,
  and provenance in a single registry (`rules.py`); a rule may expose one or both evaluators.
- **Evidence before verdict.** Every `warn`/`fail` carries the observed value and its source rule.
  Unknown or unparsed input is explicit — it never becomes a success-shaped result.
- **Strict admission bar.** v1 contains only rules backed by a written workspace policy or a
  recorded incident plus a stable fixture pair.
- **Rule identifiers.** Versioned categorical IDs `TW-<AREA>-<NNN>@v<M>` (e.g. `TW-GIT-001@v1`),
  defined once in `rules.py`; a semantic change bumps `@v<M>` (bump = supersede).

## Project structure

```
src/tripwire/
  models.py      finding / evidence / severity / report shapes
  rules.py       canonical rule registry with provenance
  workspace.py   read-only git / worktree / session probes
  command.py     conservative command tokenizer + classifier
  cli.py         check + command explain entry points
tests/fixtures/  frozen good / bad / ambiguous cases
```

See [plans/plan.md](plans/plan.md) for the full build plan and the v1 rule inventory.

## Scope

**In:** read-only workspace probes, command-text classification, versioned rule IDs, text + JSON
reports, Windows path normalization. **Out:** command execution, shell interception, automatic
fixes, remote policy, and any assurance that an unflagged command is safe.
