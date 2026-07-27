"""Frozen command fixtures for the command-classifier tests (plan step 3).

Three calibrated buckets mirror the Step-3 done-when:

* ``RISKY``   -- each command trips its expected command rule id at the stated
  severity (``warn`` for rules 2/9, ``fail`` for rules 7/8/10).
* ``SCOPED``  -- the safe/scoped equivalent of a risky case; it must *avoid* the
  paired high-risk rule id (the calibration against over-flagging).
* ``AMBIGUOUS_INVALID`` -- empty or unparseable input that is invalid input (the
  CLI maps it to exit 2); the classifier returns no findings and an
  ``invalid_reason``.
* ``AMBIGUOUS_UNKNOWN`` -- a recognized high-risk command whose risk-determining
  position (a flag OR a bare mode/target/selector) is a shell substitution; it is
  reported ``unknown`` (exit 2), never cleared.

Neither ambiguous bucket may produce a pass-shaped success (plan section 8).
"""

from __future__ import annotations

#: (command, expected rule id, expected severity)
RISKY: tuple[tuple[str, str, str], ...] = (
    ("git add -A", "TW-GIT-001@v1", "warn"),
    ("git add .", "TW-GIT-001@v1", "warn"),
    ("git stash", "TW-GIT-001@v1", "warn"),
    ("git stash push -m wip", "TW-GIT-001@v1", "warn"),
    ("git reset --hard HEAD~1", "TW-GIT-003@v1", "fail"),
    ("git push --force origin main", "TW-GIT-003@v1", "fail"),
    ("git push -f", "TW-GIT-003@v1", "fail"),
    ("git checkout -- src/app.py", "TW-GIT-003@v1", "fail"),
    ("taskkill /IM notepad.exe /F", "TW-CMD-001@v1", "fail"),
    ("Stop-Process -Name node", "TW-CMD-001@v1", "fail"),
    ("git status && git log", "TW-SHL-001@v1", "warn"),
    ("git fetch || git pull", "TW-SHL-001@v1", "warn"),
    ("cat secrets.env", "TW-SEC-001@v1", "fail"),
    ("type .env.local", "TW-SEC-001@v1", "fail"),
    ("gc credentials.json", "TW-SEC-001@v1", "fail"),
    ("grep AKIA id_rsa", "TW-SEC-001@v1", "fail"),
)

#: (command, rule id it must NOT trip)
SCOPED: tuple[tuple[str, str], ...] = (
    ("git add src/app.py", "TW-GIT-001@v1"),
    ("git stash push -- src/app.py", "TW-GIT-001@v1"),
    ("git stash pop", "TW-GIT-001@v1"),
    # `git stash create` is read-only (prints a commit object, no stash entry).
    ("git stash create", "TW-GIT-001@v1"),
    ("git reset --soft HEAD~1", "TW-GIT-003@v1"),
    ("git push --force-with-lease origin main", "TW-GIT-003@v1"),
    # A bare refspec is not a risk-determining position for push (only --force is).
    ("git push origin $BRANCH", "TW-GIT-003@v1"),
    ("git restore src/app.py", "TW-GIT-003@v1"),
    ("git checkout main", "TW-GIT-003@v1"),
    ("taskkill /PID 4242 /T /F", "TW-CMD-001@v1"),
    # A confirmed PID/Id selector with a variable value stays PID-based (not name).
    ("taskkill /PID $PID /F", "TW-CMD-001@v1"),
    ("Stop-Process -Id 4242", "TW-CMD-001@v1"),
    ("Stop-Process -Id $PID", "TW-CMD-001@v1"),
    ("git status; git log", "TW-SHL-001@v1"),
    ("wc -c secrets.env", "TW-SEC-001@v1"),
    ("Get-Item secrets.env", "TW-SEC-001@v1"),
    ("cat README.md", "TW-SEC-001@v1"),
    # Committed placeholder templates are not secrets (example/sample/template).
    ("cat .env.example", "TW-SEC-001@v1"),
    ("cat credentials.sample", "TW-SEC-001@v1"),
    ("type .env.template", "TW-SEC-001@v1"),
)

#: Empty / unparseable -> invalid input (CLI exit 2, no finding).
AMBIGUOUS_INVALID: tuple[str, ...] = (
    "",
    "   ",
    'cat "secrets.env',
    "echo 'unterminated",
)

#: (command, rule id) -- a recognized risky family whose risk-determining
#: position is a shell substitution; must be reported ``unknown`` (exit 2), never
#: cleared as safe. Both flag-shaped (``--$MODE``) and BARE (``$MODE``) forms
#: count -- a bare mode/target/selector could still expand to the risky form.
AMBIGUOUS_UNKNOWN: tuple[tuple[str, str], ...] = (
    # Flag-shaped substitution in the risk-determining position.
    ("git reset --$MODE HEAD~1", "TW-GIT-003@v1"),
    ("git push --$FORCE origin main", "TW-GIT-003@v1"),
    ("taskkill /$WHICH notepad.exe", "TW-CMD-001@v1"),
    ("Stop-Process -$SEL node", "TW-CMD-001@v1"),
    ("git add --$WHAT", "TW-GIT-001@v1"),
    # Bare substitution in the risk-determining position -- previously cleared as
    # a pass, now correctly unknown (never cleared as safe).
    ("git reset $MODE HEAD~1", "TW-GIT-003@v1"),
    ("git checkout $TARGET", "TW-GIT-003@v1"),
    ("taskkill $SEL notepad.exe", "TW-CMD-001@v1"),
    ("Stop-Process $SEL node", "TW-CMD-001@v1"),
    ("git add $WHAT", "TW-GIT-001@v1"),
)
