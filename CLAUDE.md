# tripwire — project instructions

Local-first preflight utility: turns known workspace failure modes into fast, evidence-bearing
checks. `tripwire check` probes repository/session state; `tripwire command explain -- <cmd>`
classifies proposed command text. One-shot, read-only, no daemon/server. Authoritative shapes and
the v1 rule inventory live in [`plans/plan.md`](plans/plan.md) (§5, §6, §10).

## Stack

- Python 3.12+ (managed by uv); stdlib-only runtime (no third-party runtime deps).
- argparse CLI (no third-party CLI dependency).
- pytest / ruff / mypy (strict) — `dev` optional-dependency group only.

## Commands

Shell: PowerShell (primary) on Windows; commands are shell-agnostic via uv.

- `uv sync --extra dev` — create env + install dev tools
- `uv run pytest -q` — tests
- `uv run ruff check .` — lint
- `uv run ruff format --check .` — format check (never run write-mode across the repo)
- `uv run mypy --strict src` — types
- `uv run tripwire check [--root <path>] [--json]` — workspace preflight
- `uv run tripwire command explain [--json] -- <command>` — command-text risk explanation
- `powershell -ExecutionPolicy Bypass -File docs/tour/open-tour.ps1` — open the guided tour page

## Layout

- `src/tripwire/__init__.py` — public exports
- `src/tripwire/models.py` — `Finding` / `Report` shapes, `ExitCode`, `exit_code_for` (Step 1)
- `src/tripwire/cli.py` — argparse: `check` workspace probes + `command explain` classification
- `src/tripwire/rules.py` — canonical rule registry with provenance (Step 2)
- `src/tripwire/workspace.py` — read-only git / worktree / session probes (Step 2)
- `src/tripwire/command.py` — conservative command tokenizer + classifier (Step 3)
- `tests/` — baseline model + CLI-surface tests
- `tests/fixtures/` — frozen good / bad / ambiguous cases (Steps 2-4)

## Contract (authoritative shapes in plans/plan.md §5, §6)

- Rule IDs: `TW-<AREA>-<NNN>@v<M>`, AREA in {GIT, WTR, SES, CMD, SHL, SEC}; defined once in `rules.py`.
- Severity: `warn` | `fail` | `unknown` (tripwire-local vocabulary, deliberate per-tool choice).
- Exit codes: `0` no blocking findings, `1` blocking findings, `2` invalid input / incomplete
  evaluation. `exit_code_for()` maps: any `fail` -> 1; else any `unknown` -> 2; else 0. Invalid
  *input* (no enclosing repo and no `--root`) also exits 2, handled at the CLI boundary.
- Report JSON: deterministic key order (`schema_version`, `target`, `findings`); readers tolerate
  older `schema_version`, refuse newer with an explicit error.

## Status

Steps 1-5 are marked DONE in [`plans/plan.md`](plans/plan.md) §7. The CLI runs workspace
probes and command classification; historical v1 validation is recorded in
[`docs/findings/v1-validation.md`](docs/findings/v1-validation.md).

## Gotchas

- CLI handlers in `cli.py` run the production evaluators. A `check` exit 0 means no blocking
  findings, not absence of advisory findings; retain explicit `unknown`/incomplete results.
- Everything beyond the pinned §5 finding/report fields is builder-decided; do not add fields to the
  pinned shapes without a plan change.
