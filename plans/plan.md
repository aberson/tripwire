# Seed Plan: tripwire

<!-- decisions-applied: 2026-07-26 per dev/docs/plan-reviews/2026-07-25-utility/DECISIONS.md -->

## 1. What This Is

Proposal: `../../docs/utility-project-proposal.html`

Tripwire is a local-first utility project that turns known workspace failure modes into fast,
evidence-bearing preflight checks. It provides `tripwire check` for repository/session state and
`tripwire command explain -- <command>` for proposed command text. It exists because wrong working
directories, wrong worktrees, broad staging, unsafe process termination, and shell mismatches have
recurred despite written guidance.

## 2. Existing Context

- The workspace already documents safety rules in `../../.claude/rules/` and concrete incidents in
  `../../docs/friction-catalog.md`; Tripwire operationalizes a small high-confidence subset.
- The original proposal is `../../docs/seeds/seed_tripwire.md`; `seed_tripwire_command.md` is folded
  into this project rather than becoming a second rule owner.
- Tripwire is a new standalone utility project and is fully independent: it takes no build, import,
  or project-name-specific dependency on any other utility project, and it works fully in isolation.
  Other projects may invoke its CLI, but none depend on an in-process Python API or shared service;
  every cross-project seam is a general interface contract — the CLI invocation form, the JSON
  report shape, the exit-code map, and well-known marker paths — so any consumer or substitute tool
  speaking the same formats works identically.
- The tool is one-shot and operator/agent invoked. It has no daemon, scheduler, or always-on behavior.

## 3. Scope

**In:** Python 3.12+ and uv; argparse CLI; versioned rule IDs; read-only workspace probes; command-text
classification; text and JSON reports; Windows path normalization; frozen positive/negative fixtures.

**Out:** command execution, shell interception, automatic fixes, remote policy, universal PowerShell
parsing, and assurances that an unflagged command is safe.

## 4. Impact Analysis

| File | Change Type | Reason | Verified |
|---|---|---|---|
| `plans/plan.md` | add | Canonical project plan | Created from approved seed; no existing project code |
| `../../docs/seeds/seed_tripwire.md` | read-only input | Baseline workspace-state proposal | Read directly; no edit planned |
| `../../docs/seeds/seed_tripwire_command.md` | read-only input | Command classifier folded into Tripwire | Read directly; no edit planned |
| `../../docs/friction-catalog.md` | read-only input | Source evidence for candidate rules | Grep confirmed recurring cwd/worktree/staging incidents |

No existing function signatures, schemas, or shared constants are modified in v1.

## 5. New Components

- `pyproject.toml`, `CLAUDE.md`, and `README.md`.
- `src/tripwire/models.py`: finding, evidence, severity, and report shapes. The fields Steps 2-4
  assert against are pinned below; everything beyond these rows stays builder-decided in Step 1.

  | Finding field | Type / values | Notes |
  |---|---|---|
  | `rule_id` | `TW-<AREA>-<NNN>@v<M>` | per the §6 rule-identifier decision |
  | `severity` | `warn` \| `fail` \| `unknown` | tripwire-local vocabulary (deliberate per-tool choice) |
  | `message` | str | human-readable explanation |
  | `observed` | str | the observed value behind the verdict |
  | `provenance` | str | source policy/incident per the §6 admission bar |
  | `evaluator` | `workspace` \| `command` | which evaluator produced the finding |

  | Report field | Type / values | Notes |
  |---|---|---|
  | `schema_version` | int, `1` | from day one; readers tolerate older versions, refuse newer with an explicit error |
  | `target` | str | the resolved target root (§6 target-root resolution) |
  | `findings` | list of Finding | |
  | exit code | 0 \| 1 \| 2 | JSON mirrors the §6 exit contract |

  JSON output mirrors these fields; deterministic key ordering is locked by Step 4.
- `src/tripwire/rules.py`: one canonical rule registry with provenance.
- `src/tripwire/workspace.py`: read-only git/worktree/session probes.
- `src/tripwire/command.py`: conservative command tokenizer and classifier.
- `src/tripwire/cli.py`: `check` and `command explain`.
- `tests/fixtures/`: frozen good, bad, and ambiguous cases.

## 6. Design Decisions

**One rule owner.** Workspace checks and command explanations share IDs, severity, rationale, and
provenance in one registry. A rule may expose one or both evaluators without duplicating policy text.

**Evidence before verdict.** Every warn/fail includes the observed value and source rule. Unknown or
unparsed input is explicit; it never becomes a success-shaped result.

**Strict admission bar.** V1 contains only rules backed by a written workspace policy or recorded
incident and a stable fixture pair. This limits alert fatigue.

**Exit contract.** Exit 0 means no blocking findings, exit 1 means blocking findings, and exit 2
means invalid input or incomplete evaluation. JSON output carries the same distinction. The 0/1/2
map and the warn|fail|unknown severity vocabulary are tripwire-local, stated here deliberately;
sibling utilities define their own maps and no cross-tool family is implied.

**Target-root resolution.** `tripwire check` probes the enclosing git root of the cwd by default;
`--root <path>` overrides it. No enclosing repository and no `--root` is invalid input (exit 2),
never a heuristic fallback. Session/state-file probes never assume the dev layout: they discover
the coding-root by walking up from the target root to the outermost git root containing the
well-known marker file `.claude/observatory/registry.toml` — a path convention only (any tree
carrying the marker qualifies; no dependency on the tool that maintains that file). If no marker
is found, those probes report severity `unknown` with the walked path as evidence — never a clean
pass.

**Rule identifiers.** Rule IDs use the versioned categorical format `TW-<AREA>-<NNN>@v<M>` —
example: `TW-GIT-001@v1` (broad staging at the coding-root). AREA is one of {GIT, WTR, SES, CMD,
SHL, SEC}; NNN is scoped per area. IDs are defined once, in the `rules.py` registry, and consumed
by fixtures, JSON reports, and `command explain` output. A semantic change bumps `@v<M>`
(bump = supersede); an ID is never reused or re-meant.

### V1 rule inventory

The ten v1 rules, each with its evaluator surface and the written provenance the admission bar
requires. Steps 2 and 3 implement from this table.

| # | Rule | Evaluator | Source |
|---|---|---|---|
| 1 | Wrong-repo-layer commit target | workspace | `../../.claude/rules/working-directory.md` |
| 2 | Broad staging / bare `git stash` at the coding-root | workspace, command | `../../.claude/rules/working-directory.md` |
| 3 | Wrong-worktree branch mismatch | workspace | `../../CLAUDE.md` § Session wrap & commit discipline |
| 4 | Stale worktree (>1 day or >3 commits behind) | workspace | `../../.claude/rules/worktree-hygiene.md` |
| 5 | Concurrent `.plan-expedite-state.*` state files | workspace | `../../CLAUDE.md` § Parallel session safety |
| 6 | Active worktrees / recent other-branch commits | workspace | `../../CLAUDE.md` § Parallel session safety |
| 7 | Destructive git (`reset --hard`, `push --force`, `checkout --`) | command | `../../.claude/rules/worktree-hygiene.md` (merge-check before `--force`) + `../../docs/friction-catalog.md` (force-delete incidents) |
| 8 | Name-based process kill (`taskkill /IM`, `Stop-Process -Name`) | command | `../../docs/lessons-learned.md` § Subprocess tree-kill on Windows (kill by PID, never by name) |
| 9 | Shell mismatch (`&&`/bash-isms handed to PowerShell 5.1) | command | `../../.claude/rules/windows-shell.md` |
| 10 | Secret-file dump via `cat`/`type`/`grep` | command | `../../.claude/rules/security.md` § Never dump secret file contents |

## 7. Build Steps

### Step 1: Scaffold the project and report contract
- **Problem:** Create the uv package, CLI shell, canonical typed finding/report shapes, and quality gates.
- **Type:** code
- **Issue:** #1
- **Flags:** --reviewers code --isolation worktree
- **Produces:** project scaffold, `models.py`, CLI entry point, baseline tests
- **Done when:** `uv sync --extra dev`, pytest, Ruff, and mypy strict pass
- **Depends on:** none
- **Status:** DONE (2026-07-27)

<!-- autofix-applied: 2026-07-25 -->
### Step 2: Build the rule registry and workspace preflight
- **Problem:** Implement the workspace-evaluator rules from the §6 V1 rule inventory: evidence-backed read-only checks for cwd, git root, branch/worktree, staged scope, and concurrent state files.
- **Type:** code
- **Issue:** #2
- **Flags:** --reviewers deep --isolation worktree
- **Produces:** `rules.py`, `workspace.py`, `tripwire check` (default target = enclosing git root of cwd, `--root <path>` override per §6 target-root resolution), JSON/text reports
- **Done when:** every frozen bad fixture emits its expected stable rule ID in the §6 `TW-<AREA>-<NNN>@v<M>` format; clean fixtures stay clean; baseline check completes in under 10 seconds
- **Depends on:** 1
- **Status:** DONE (2026-07-27)

<!-- autofix-applied: 2026-07-25 -->
### Step 3: Fold in command-risk explanation
- **Problem:** Implement `tripwire command explain -- <command>` for the command-evaluator rules in the §6 V1 rule inventory — every row whose Evaluator column includes `command` (rules 2, 7, 8, 9, 10); the table is the sole rule list. This step extends the shared `rules.py` registry that Step 2 produces rather than creating a second one.
- **Type:** code
- **Issue:** #3
- **Flags:** --reviewers deep --isolation worktree
- **Produces:** `command.py`, command findings, safer-form suggestions where deterministic
- **Done when:** risky fixtures match expected IDs, scoped equivalents avoid the same high-risk finding, and ambiguous commands return unknown/warn rather than pass
- **Depends on:** 1, 2
- **Status:** DONE (2026-07-27)

<!-- autofix-applied: 2026-07-25 -->
### Step 4: Harden Windows parsing and report behavior
- **Problem:** Cover quoting, PowerShell 5.1 syntax, executable aliases, path casing, separators, malformed input, and deterministic JSON ordering.
- **Type:** code
- **Issue:** #4
- **Flags:** --reviewers deep --isolation worktree
- **Produces:** expanded fixture pack and error-path tests
- **Done when:** reports are deterministic; malformed input exits 2; suggested PowerShell commands parse in the supported shell subset
- **Depends on:** 2, 3
- **Status:** DONE (2026-07-27)

### Step 5: Validate the CLI against real workspace cases
- **Problem:** Run the production CLI read-only against the dev workspace and a disposable fixture repository, recording false positives and runtime without changing either target.
- **Type:** code
- **Issue:** #5
- **Flags:** --reviewers code --isolation worktree
- **Produces:** `docs/findings/v1-validation.md`
- **Done when:** all seeded failures are found, clean-case nuisance rate is below 5%, runtime is under 10 seconds, and every finding has evidence and provenance
- **Depends on:** 4
- **Status:** DONE (2026-07-27)

## 8. Risks and Open Questions

| Item | Risk | Mitigation |
|---|---|---|
| False assurance | Unmatched commands appear safe | Use unknown, never an approval verdict |
| Alert fatigue | Users ignore noisy findings | Evidence-backed admission and fixture calibration |
| Policy drift | Rules diverge from workspace guidance | Store source provenance and test stable IDs |
| Parser ambition | Project grows into a shell parser | Support only documented high-confidence patterns |

## 9. Testing Strategy

Use unit tests for each rule and tokenizer branch, table-driven safe/risky/ambiguous fixtures,
temporary git repositories for worktree state, and subprocess tests for CLI exit codes and JSON.
The final validation step runs the real one-shot CLI; the autonomous-behavior trigger does not fire.

## Appendix: Decision Inventory

| ID | P/D | Choice | Status |
|---|---|---|---|
| P1 | P | Treat Tripwire as a standalone utility project and fold Tripwire Command into it | accepted |
| D1 | D | Use Python 3.12+, uv, argparse, pytest, Ruff, and mypy strict | accepted |
| D2 | D | Keep v1 one-shot, local-only, read-only, and service-free | accepted |
| D3 | D | Initialize a separate nested GitHub repository before build | accepted |

## 10. Build and Run Contract

Bootstrap with Python 3.12+ and `uv sync --extra dev`. Quality gates are `uv run pytest -q`,
`uv run ruff check .`, and `uv run mypy --strict src`. The installed CLI entry point is
`tripwire`; no server, port, environment variable, or external account is required.
`tripwire check` targets the enclosing git root of the cwd by default; `--root <path>` overrides
it (e.g. `uv run tripwire check --root <path>`), and no enclosing repository with no `--root`
exits 2 per the §6 target-root resolution decision.
