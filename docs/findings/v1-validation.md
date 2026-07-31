# Tripwire v1 Validation Report

**Step 5 (plan `plans/plan.md`, Issue #5).** Read-only validation of the production
`tripwire` CLI against seeded-failure fixtures, a clean fixture, a safe-command
corpus, and the live dev workspace. No production behaviour was changed and no
target was modified.

- **Date:** 2026-07-27
- **Commit under test:** `c987245` (step 4 complete)
- **CLI build:** `tripwire` 0.1.0 (`src/tripwire`), 190 tests passing
- **Verdict:** **PASS** — 28/28 seeded failures detected, 0.0% clean-case nuisance
  rate, live-workspace check 0.37 s best-of-3 (budget 10 s), every finding carries
  evidence + provenance. No production defects found; one by-design nuisance vector
  recorded for v1.1 consideration.

---

## 1. Methodology

All runs invoke the **production** CLI as a subprocess through its real entry point
(`python -m tripwire.cli`, which is exactly what the `tripwire` console script
maps to — `tripwire.cli:main`), parse the `--json` report, and inspect
`findings[].rule_id` / `severity` / `observed` / `provenance`. Nothing calls the
probes in-process, so the exercised path is identical to an operator/agent typing
`tripwire check` or `tripwire command explain`.

- **Harness:** `scripts/validate_v1.py` (typed, `mypy --strict` clean, `ruff`
  clean). It reuses the frozen fixture builders in `tests/fixtures/repos.py` and
  the frozen command corpora in `tests/fixtures/commands.py` rather than
  re-implementing them, so validation and the unit suite agree on what "bad" and
  "safe" mean. It is not collected by pytest (`testpaths = ["tests"]`) and does not
  affect the 190-test gate.
- **Workspace fixtures:** each built with real `git` in a throwaway
  `tempfile.TemporaryDirectory`, then probed via `tripwire check --root <fixture>
  --json`. Real git state means the probes observe genuine repositories, not mocks.
- **Command corpus:** each command passed as a single argument after `--` to
  `tripwire command explain --json`, so the CLI's own tokenizer/classifier runs.
- **Live workspace:** `tripwire check --root <dev-root> --json`, read-only.
- **Runtime:** wall-clock of the end-to-end subprocess (interpreter startup +
  probe execution) via `time.perf_counter()` — best-of-three (the minimum of three
  back-to-back live runs, which the harness itself performs and prints) for the live
  workspace check, and a single timed run for each seeded fixture and the clean
  fixture.
- **Reproduce:**
  ```
  uv run python scripts/validate_v1.py --dev-root <dev-root> \
      --json-out <path>/dev-findings.json
  ```

The measurement scope matches the decision scope: the claim under test is exactly
"v1 detects every seeded bad state at its expected rule ID, stays quiet on clean
inputs (< 5% nuisance), and completes a real-workspace check in < 10 s."

---

## 2. Seeded-failure coverage

### 2a. Workspace rules 1–6 (one disposable repo per rule)

Every fixture is engineered to trip one primary rule. Two fixtures (detached and
stale worktrees) unavoidably also trip rule 6 — any linked worktree is, by
definition, an active worktree — so the pass criterion is that the **expected**
rule ID is present, not that it is the only finding. All six were detected.

| # | Seeded bad state | Fixture builder | Detected? | Rule ID(s) observed | Exit |
|---|---|---|---|---|---|
| 1 | Wrong-repo-layer (coding-root with nested project repo) | `build_nested_repo_layer` | YES | `TW-GIT-002@v1` | 0 |
| 2 | Broad staging at the coding-root | `build_staged_coding_root` | YES | `TW-GIT-001@v1` | 0 |
| 3 | Wrong-worktree / detached HEAD in a linked worktree | `build_detached_worktree` | YES | `TW-WTR-001@v1` (+`TW-SES-002@v1`) | 1 |
| 4 | Stale worktree (>3 commits behind base) | `build_stale_worktree` | YES | `TW-WTR-002@v1` (+`TW-SES-002@v1`) | 0 |
| 5 | Concurrent `.plan-expedite-state.*` at coding-root | `build_concurrent_state_files` | YES | `TW-SES-001@v1` | 0 |
| 6 | Active worktrees / recent other-branch commits | `build_active_parallel_sessions` | YES | `TW-SES-002@v1` | 0 |

**Workspace coverage: 6/6.** Rule 3's exit 1 is correct — `TW-WTR-001` is a `fail`
(a detached-HEAD commit advances no branch), so the blocking exit code is expected.
The stale/detached fixtures' incidental `TW-SES-002` co-finding is a true property
of the fixture (a real second worktree exists), not a false positive.

### 2b. Command rules 2, 7, 8, 9, 10 (risky-form corpus)

The 22 frozen risky commands span every command-evaluator rule. Each was required
to emit its expected rule ID **at its expected severity**. All 22 matched.

| Rule | Rule ID | Risky forms | Detected | Examples |
|---|---|---|---|---|
| 2 | `TW-GIT-001@v1` (warn) | 5 | 5/5 | `git add -A`, `git add .`, `git stash`, `git stash push -m wip`, `git stash save wip` |
| 7 | `TW-GIT-003@v1` (fail) | 6 | 6/6 | `git reset --hard`, `git push --force`, `git push -f`, `git checkout -- <path>`, `git.exe reset --hard`, `GIT reset --hard` |
| 8 | `TW-CMD-001@v1` (fail) | 3 | 3/3 | `taskkill /IM notepad.exe /F`, `Stop-Process -Name node`, `spps -Name node` |
| 9 | `TW-SHL-001@v1` (warn) | 2 | 2/2 | `git status && git log`, `git fetch \|\| git pull` |
| 10 | `TW-SEC-001@v1` (fail) | 6 | 6/6 | `cat secrets.env`, `type .env.local`, `gc credentials.json`, `grep AKIA id_rsa`, `type ...\id_ed25519`, `Get-Content ...\PROD.env` |

**Command coverage: 22/22.**

### Seeded total: **28/28 detected (0 misses).**

---

## 3. Clean-case nuisance rate

A nuisance (false positive) is any finding raised against a target that has no
actual bad state. Two clean surfaces were exercised:

| Clean surface | Trials | False positives |
|---|---|---|
| Clean coding-root repo (`build_clean_coding_root`) via `tripwire check` | 1 | 0 |
| Safe commands via `command explain` (24 unique: `SCOPED` 22 + `SAFER_FORMS` 7 − 5 verbatim duplicates) | 24 | 0 |
| **Total** | **25** | **0** |

**Nuisance rate = 0 / 25 = 0.0%** — far below the < 5% target (a 5% ceiling on 25
trials would tolerate 1 false positive; there were none).

- The clean coding-root produced **zero** findings (exit 0, runtime 0.353 s): it
  carries the marker, has one worktree/branch, no nested repos, no staged changes,
  and no state files, so every probe stayed silent.
- All 24 unique safe commands (scoped `git add <path>`, `git stash push -- <paths>`,
  `git reset --soft`, `git push --force-with-lease`, PID-based kills, metadata-only
  reads, `.env.example`/`.sample`/`.template` placeholders, and every rendered
  safer-form suggestion the tool itself emits) produced zero findings. The
  safer-forms in particular confirm the tool never flags its own advice.

The `SAFER_FORMS` corpus doubles as the "suggested command parses in the supported
shell subset" calibration: each rendered suggestion (`git status; if ($?) { git log
}`, etc.) is a valid PowerShell-5.1-subset command that does not re-trip the rule it
steers away from. Five of the seven safer-forms are verbatim `SCOPED` entries, so
the harness dedupes them and they count once toward the 24 unique trials above; only
the two shell-chain forms (`taskkill /T /F /PID 4242`, `git status; if ($?) { git log
}`) are unique to this corpus.

---

## 4. Live dev-workspace findings

`tripwire check --root <dev-root> --json` — read-only, exit 0 (warn-only),
runtime 0.37 s (best of 3). Full JSON captured during the run; each finding below is
quoted from the tool's own `observed` + `provenance` fields.

| Rule ID | Sev | Verdict | Evidence (tool `observed`) | Provenance |
|---|---|---|---|---|
| `TW-GIT-002@v1` | warn | **TRUE positive** | `nested git repositories under target: <sibling project repos redacted> (40 total)` | `.claude/rules/working-directory.md` |
| `TW-SES-001@v1` | warn | **TRUE positive** | `3 state file(s) at coding-root <dev-root>: .plan-expedite-state.* (filenames redacted)` | `CLAUDE.md (Parallel session safety)` |
| `TW-SES-002@v1` | warn | **TRUE positive** | `3 linked worktrees active` | `CLAUDE.md (Parallel session safety)` |

**All three are true positives, not nuisance — the tool is correct about the live
workspace:**

- **`TW-GIT-002` (wrong-repo-layer):** `<dev-root>` genuinely *is* a
  coding-root layer with ~40 nested project repositories. This is precisely the hazard the rule names: a
  `git`/`gh` run at the dev layer resolves to the dev repo, so a commit or broad
  stage there lands against the wrong repo layer. Correct to flag.
- **`TW-SES-001` (concurrent state files):** three real `.plan-expedite-state.*`
  files left by other/earlier sessions sit at the coding-root — exactly the
  collision hazard the rule guards against. Correct to flag. (These are the
  operator's real workspace artifacts, not seeded by this validation.)
- **`TW-SES-002` (active worktrees):** three linked worktrees are genuinely active,
  including this build-step worktree. Correct to flag.

This is the intended distinction from Section 3: a finding on the *clean fixture* is
a nuisance to drive to zero (achieved: 0), whereas a finding on the *live workspace*
that reflects real state is a true positive and must fire. v1 gets both right — 0
false positives on clean targets, 3 correct positives on a genuinely-busy workspace.

The exit code is 0 because all three are `warn` (advisory), matching the plan's
section 6 exit contract: `warn`-only reports do not block.

---

## 5. Runtime

| Run | Wall-clock | Budget | Margin |
|---|---|---|---|
| Live dev check (`--root <dev-root>`), best of 3 (0.376 / 0.367 / 0.389 s) | **0.37 s** | 10 s | ~27x |
| Clean coding-root fixture check | 0.353 s | 10 s | ~28x |
| Seeded workspace fixtures (slowest of 6) | 0.529 s | 10 s | ~19x |

The live check is the runtime-critical path because rule 1 walks the full dev tree
(`os.walk`, depth 3) to enumerate nested repos; it still completes in ~0.4 s because
the scan prunes dependency/cache dirs (`.venv`, `node_modules`, ...) and stops
descending once it enters a nested repo. Comfortably under the 10 s budget.

---

## 6. Recorded for v1.1 (no production change in this step)

No production defects were found — every seeded failure was detected, the clean-case
nuisance rate is 0%, and the live-workspace findings are all correct. One
observation is recorded as a **design-tradeoff consideration** (explicitly *not* a
bug — it is the plan's section 6 "never a clean pass" contract working as specified):

- **V1.1-1 — Markerless standalone repo raises `TW-SES-001` `unknown` (exit 2).**
  Running `tripwire check` on an ordinary standalone project that is *not* inside a
  coding-root (no `.claude/observatory/registry.toml` marker on any ancestor) makes
  the rule-5 concurrent-state-file probe report `unknown` with the walked path as
  evidence — by design, so a missing coding-root never degrades to a false
  all-clear. Observed in validation: `markerless repo -> exit=2 ids=['TW-SES-001@v1']`.
  This is correct per plan section 6, but for the standalone-project audience it is a
  guaranteed non-actionable `unknown` on every run (and a non-zero exit). A future
  version could add an explicit standalone/`--no-coding-root` mode (or downgrade to
  silent when the target is unambiguously a leaf project with no ancestor marker),
  *without* weakening the never-clean-pass guarantee inside a real coding-root.
  Scope note: this changes rule semantics, so it belongs in a plan revision, not a
  patch — filed here for the operator to weigh, not fixed in Step 5.

---

## 7. Verdict

**v1 PASSES its Step 5 done-when criteria:**

- [x] All seeded failures found — **28/28** (workspace 6/6 at expected rule IDs;
      command 22/22 at expected rule ID + severity).
- [x] Clean-case nuisance rate below 5% — **0.0%** (0 / 25 clean trials).
- [x] Runtime under 10 seconds — **0.37 s** live workspace (best of 3), **0.353 s**
      clean fixture, **0.529 s** slowest seeded fixture.
- [x] Every finding carries evidence and provenance — verified from the tool's own
      `observed` + `provenance` fields (Sections 2 and 4).

The tool correctly distinguishes a busy-but-valid live workspace (3 true positives,
all advisory `warn`) from a clean target (0 findings), which is the core plan
section 8 risk-mitigation ("alert fatigue" via evidence-backed admission; "false
assurance"
via `unknown`, never approval). v1 is validated for release.
