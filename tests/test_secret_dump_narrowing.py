"""TW-SEC-001 narrowing: only a file the command PRINTS is judged (v0.1.2).

Before 0.1.2 the rule fired on any secrets-shaped token anywhere in a dump tool's
arguments, and on any shell substitution there -- so searching FOR the text
``.env``, writing a file through a heredoc, or a grep pattern with ``$`` in it all
tripped it. The shadow log showed it on about 13% of shell commands, nearly all
false positives. These fixtures pin both directions: the false-positive shapes go
quiet, and printing a real secrets-bearing file still fails.

Replay (2026-11-23; v0.1.1 vs 0.1.2 classifier over the 8,247 pre-screened Claude
shell commands of the shadow-log window from 2026-11-22 23:27 UTC): TW-SEC-001
hook rows 1,156 -> 6 (fail 41 -> 6, unknown 1,115 -> 0). Of the 31 dropped fails,
17 were heredoc bodies, 12 search patterns and 2 source files named after
secrets; the 6 that remain print a ``.env`` file (5) or are a quoted prose
argument containing "secret" (1, a known residual false positive).
"""

from __future__ import annotations

import pytest

from tripwire.command import classify, strip_heredoc_bodies

SEC = "TW-SEC-001@v1"


def _sec(command: str) -> list[str]:
    return [f.severity for f in classify(command).findings if f.rule_id == SEC]


QUIET = [
    # searching FOR secret-ish text prints no secrets file
    'grep -rn "\\.env" src',
    'grep -rn ".env" .',
    "grep -n secret src/app.py",
    "grep -rn --include=*.py password tests",
    "grep -e .env -e id_rsa README.md",
    'Select-String -Pattern ".env" -Path README.md',
    "sls '\\.env' notes.txt",
    "Select-String -Pattern secret -Path docs\\a.md,docs\\b.md",
    "awk '/password/ {print $1}' log.txt",
    "awk -F= '/TOKEN/ {print $1}' config.txt",
    # a grep pattern carrying $, a backtick or %...% is not a substituted FILE
    "grep -n 'foo$' a.txt",
    "grep -n '`passing-notes`' docs/a.md",
    "grep -n '$env:HOME' a.ps1",
    "grep -c '%d%' fmt.txt",
    # heredoc / here-string bodies are data
    "git commit -F - <<'EOF'\nfix: stop the cat .env noise; type secrets.env\nEOF",
    "git commit -m \"$(cat <<'EOF'\nfix(sec): grep .env | cat id_rsa\nEOF\n)\"",
    "cat > notes.md <<'EOF'\nnever cat .env\nEOF",
    "cat <<EOF > out.txt\nsecrets.env\nEOF",
    "$m = @'\ncat .env; type id_rsa\n'@\ngit commit -m $m",
    # redirect targets are written, not printed
    "cat > .env",
    "echo x | cat >> secrets.env",
    "type nul > credentials.txt",
    # code / prose ABOUT secrets
    "cat docs/secrets-handling.md",
    "head tests/secret-read-guard.tests.py",
    "Get-Content .claude/hooks/secret-read-guard.ps1",
    "cat src/credential_store.ts",
    # unchanged clears
    "cat .env.example",
    "cat README.md",
    "wc -c secrets.env",
]

FIRES = [
    "cat .env",
    "cat secrets.env",
    "type .env.local",
    "Get-Content C:\\proj\\.env",
    "gc credentials.json",
    "head -n 5 secrets.env",
    "tail ~/.ssh/id_ed25519",
    "cat server.pem",
    "cat < .env",
    "cut -d= -f2 .env",
    "grep TOKEN .env",
    "grep AKIA id_rsa",
    "grep -rn TOKEN -- .env",
    "grep TOKEN .env -n",
    "grep -e TOKEN .env",
    "grep -A 2 TOKEN .env",
    "Select-String foo .env",
    "sls -Pattern foo -Path .env",
    "Select-String -Path:.env -Pattern x",
    "awk '{print}' .env",
    "awk -F= '{print $2}' secrets.env",
    "cat notes.md .env > out.txt",
    "cat secret.txt",
    "cat ~/.config/credentials",
    # a heredoc does not hide a dump on its own line
    "cat .env <<'EOF'\nbody\nEOF",
]


@pytest.mark.parametrize("command", QUIET)
def test_false_positive_shapes_are_quiet(command: str) -> None:
    assert _sec(command) == [], command


@pytest.mark.parametrize("command", FIRES)
def test_printing_a_secrets_file_still_fails(command: str) -> None:
    assert _sec(command) == ["fail"], command


@pytest.mark.parametrize(
    "command",
    ["cat $VAR", "type %SECRET%", "grep AKIA $FILE", "Get-Content $path", "sls x -Path $p"],
)
def test_substituted_file_operand_is_not_reported(command: str) -> None:
    # The unknown branch is retired (see the module docstring for the replay).
    assert _sec(command) == [], command


def test_unterminated_heredoc_leaves_text_unchanged() -> None:
    text = "python -c 'print(1 << shift)'; cat .env"
    assert strip_heredoc_bodies(text) == text
    assert _sec(text) == ["fail"]


def test_heredoc_body_removed_and_following_command_kept() -> None:
    text = "cat > a.txt <<'EOF'\ncat .env\nEOF\n"
    assert ".env" not in strip_heredoc_bodies(text)


def test_heredoc_strip_quiets_other_rules_in_commit_messages() -> None:
    # A commit message body is data for every rule, not only TW-SEC-001.
    text = "git commit -F - <<'EOF'\ndocs: never git push --force && reset\nEOF"
    assert classify(text).findings == ()
