"""Conservative command tokenizer + classifier for the command-evaluator rules.

Implements the command-surface evaluation for the ``plans/plan.md`` section 6
V1 rules whose Evaluator column includes ``command``:

* rule 2  -- ``TW-GIT-001`` broad staging / bare ``git stash``   (warn)
* rule 7  -- ``TW-GIT-003`` destructive git                       (fail)
* rule 8  -- ``TW-CMD-001`` name-based process kill               (fail)
* rule 9  -- ``TW-SHL-001`` shell mismatch (bash-ism to PS 5.1)   (warn)
* rule 10 -- ``TW-SEC-001`` secret-file dump                      (fail)

Scope (plan Steps 3-4): command evaluation only. The tokenizer is intentionally
CONSERVATIVE (plan section 8, "Parser ambition" -- documented high-confidence
patterns only, no universal PowerShell parser). Step 4 hardening -- adjacent /
mixed quoting concatenation, unbalanced-quote -> invalid input, ``.exe`` /
path-qualified / case-insensitive executable normalization (:func:`_normalize_tool`),
the ``spps`` Stop-Process alias, and Windows path casing/separators in secret
detection -- lives here. Nothing here touches the workspace probes.

Ambiguity discipline (plan section 8, "False assurance"; section 6, "Evidence
before verdict"): input is never given a pass-shaped success it did not earn.
Empty or unparseable text is *invalid input* -- :class:`Classification` carries
an ``invalid_reason`` the CLI maps to exit 2 (mirroring ``check``'s invalid-input
handling) rather than fabricating a finding for text it could not parse. When a
token occupying a risk-determining position is a shell substitution (``$VAR``,
``${...}``, ``$(...)``, ``%VAR%`` or a backtick) -- flag-shaped OR bare -- so the
risky form cannot be ruled out, the finding is reported ``unknown`` (exit 2) and
NEVER cleared as safe. ``git push`` is the one narrow exception: its only
destructive form is the ``--force``/``-f`` FLAG, so only a substitution in that
flag position is indeterminate; a bare refspec (``git push origin $BRANCH``) is
not a risk-determining position and stays clean.

Field contract (plan section 5): ``Finding.observed`` holds the observed value
behind the verdict, never a prescription. Where a safer form is deterministic it
is folded into the finding's ``message`` (via the per-finding message override
:mod:`tripwire.rules` exposes), not into ``observed``. Message, provenance and
default severity remain owned by :mod:`tripwire.rules`; this module supplies only
the observed evidence and the optional per-finding suggestion text.
"""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass

from tripwire import rules
from tripwire.models import Finding, Severity

#: bash-only chaining operators that are a parser error in PowerShell 5.1
#: (``.claude/rules/windows-shell.md``). ``;`` and ``|`` are valid in PS and are
#: deliberately excluded.
_BASH_ONLY_OPERATORS = ("&&", "||")

#: Shell variable / command-substitution shapes: ``$VAR``, ``${VAR}``, ``$(``, a
#: backtick, or ``%VAR%``. In a risk-determining position these make the verdict
#: indeterminate (section 8 ambiguity handling).
_SUBST_RE = re.compile(r"\$\w+|\$\{[^}]*\}|\$\(|`|%[^%]+%")

#: Broad ``git add`` forms that stage everything (rule 2 command side).
_BROAD_ADD_FLAGS = frozenset({"-A", "--all", "."})

#: ``git stash`` subcommands that do not stash the whole tree (rule 2 clears).
#: ``create`` is read-only -- it prints a commit object and creates no stash
#: entry, touching neither the index nor the worktree.
_SAFE_STASH_SUBCMDS = frozenset(
    {"list", "show", "pop", "apply", "drop", "clear", "branch", "create"}
)

#: ``git`` subcommands with an irrecoverable form (rule 7).
_DESTRUCTIVE_SUBCMDS = frozenset({"reset", "push", "checkout"})

#: ``Stop-Process`` and its unambiguous PowerShell alias ``spps`` (rule 8). The
#: ``kill`` alias is deliberately excluded: it collides with Unix ``kill <pid>``
#: (PID-based, safe), so flagging it would over-fire against a documented pattern.
_STOPPROCESS_TOOLS = frozenset({"stop-process", "spps"})

#: Tools that print file *contents* (not metadata). A secrets-bearing argument to
#: any of these is the rule-10 dump footgun (``.claude/rules/security.md``).
_DUMP_TOOLS = frozenset(
    {
        "cat",
        "type",
        "gc",
        "get-content",
        "grep",
        "sls",
        "select-string",
        "head",
        "tail",
        "more",
        "less",
        "od",
        "awk",
        "cut",
        "nl",
        "strings",
        "xxd",
        "hexdump",
    }
)

#: Signals that a path is secrets-bearing (substring / suffix / basename).
_SECRET_SUBSTRINGS = (
    "secret",
    "credential",
    "password",
    "passwd",
    "id_rsa",
    "id_ed25519",
    "id_dsa",
)
_SECRET_SUFFIXES = (".pem", ".key", ".pfx", ".p12")
_SECRET_BASENAMES = frozenset({".env", ".netrc", ".npmrc", ".pgpass"})

#: Placeholder-template suffixes: committed example/sample files carry no real
#: secret, so a basename ending in one of these is exempt from rule 10.
_TEMPLATE_SUFFIXES = (".example", ".sample", ".template")


@dataclass(frozen=True)
class Classification:
    """Result of classifying one command string.

    ``findings`` are the (possibly empty) risk findings. ``invalid_reason`` is
    set only for empty/unparseable input; the CLI maps it to exit 2 at the
    boundary rather than inventing a finding for text it could not parse.
    """

    findings: tuple[Finding, ...] = ()
    invalid_reason: str | None = None


@dataclass(frozen=True)
class _Token:
    """One tokenizer output unit, carrying whether it is an UNQUOTED operator.

    ``is_operator`` is ``True`` only for a control operator (``&&``/``||``/``;``/
    ``|``) the tokenizer read in unquoted position -- a real segment separator. A
    quoted operator (``git reset "&&" --hard``) concatenates into a content token
    with ``is_operator=False`` and is a literal argument, never a separator. This
    is what lets segment-splitting and the rule-9 bash-ism check consider only
    genuinely-unquoted operators (plan section 8, "False assurance").
    """

    text: str
    is_operator: bool


def _tokenize_rich(command: str) -> list[_Token] | None:
    """Split ``command`` into :class:`_Token`s (with quote state), or ``None``.

    Conservative by design (plan section 8, "Parser ambition" -- no universal
    PowerShell parser). Whitespace and the UNQUOTED control operators ``&&``/
    ``||``/``;``/``|`` separate tokens; everything else accumulates into the
    current content token so that **adjacent quoted and bare spans concatenate
    into one token**, matching real shell behaviour: ``"foo"bar``, ``foo"bar"``
    and ``'id_''rsa'`` are each a single token, not two. Both quote styles are
    honoured -- a single-quoted span treats an inner ``"`` as literal and
    vice-versa -- so mixed quoting parses. A control operator seen inside quotes
    is part of the content token, so it emits ``is_operator=False`` (a literal
    argument, not a separator). An **unbalanced quote** (no matching close) makes
    the command unparseable and returns ``None``; the CLI maps that to invalid
    input (exit 2), never a pass.
    """
    tokens: list[_Token] = []
    current: list[str] = []
    have_token = False  # a token is open even if empty (e.g. from ``""``)
    i, n = 0, len(command)

    def _flush() -> None:
        """Emit the accumulated bare/quoted characters as one content token.

        A content token is never an operator (``is_operator=False``); the
        UNQUOTED-operator branches append their own :class:`_Token` directly.
        A token stays open even when empty (``have_token`` set with no chars,
        e.g. from ``""``) so an explicitly-empty quoted argument survives.
        """
        nonlocal have_token
        if have_token:
            tokens.append(_Token("".join(current), is_operator=False))
            current.clear()
            have_token = False

    while i < n:
        ch = command[i]
        if ch.isspace():
            _flush()
            i += 1
            continue
        if command.startswith("&&", i) or command.startswith("||", i):
            _flush()
            tokens.append(_Token(command[i : i + 2], is_operator=True))
            i += 2
            continue
        if ch in (";", "|"):
            _flush()
            tokens.append(_Token(ch, is_operator=True))
            i += 1
            continue
        if ch in ('"', "'"):
            close = command.find(ch, i + 1)
            if close == -1:
                return None  # unbalanced quote -> unparseable
            current.append(command[i + 1 : close])  # concatenates onto current token
            have_token = True
            i = close + 1
            continue
        start = i
        while i < n:
            cj = command[i]
            if cj.isspace() or cj in ('"', "'", ";", "|"):
                break
            if command.startswith("&&", i) or command.startswith("||", i):
                break
            i += 1
        current.append(command[start:i])
        have_token = True
    _flush()
    return tokens


def tokenize(command: str) -> list[str] | None:
    """Split ``command`` into token strings, or ``None`` if it cannot be parsed.

    Thin wrapper over :func:`_tokenize_rich` that drops the per-token operator
    flag and returns just the token text (the historical, quote-state-agnostic
    view). Classification uses :func:`_tokenize_rich` directly so a quoted
    operator is not mistaken for a separator; see :class:`_Token`.
    """
    rich = _tokenize_rich(command)
    return None if rich is None else [t.text for t in rich]


def _segments(tokens: list[_Token]) -> list[list[str]]:
    """Split a token stream into command segments on UNQUOTED control operators.

    Only a token the tokenizer marked ``is_operator`` (an unquoted ``&&``/``||``/
    ``;``/``|``) separates segments; a quoted operator is a content token and
    stays inside its segment as a literal argument. Each segment is the list of
    its content-token texts.
    """
    segments: list[list[str]] = []
    current: list[str] = []
    for token in tokens:
        if token.is_operator:
            if current:
                segments.append(current)
            current = []
        else:
            current.append(token.text)
    if current:
        segments.append(current)
    return segments


def _normalize_tool(token: str) -> str:
    """Normalize an executable token to a bare, case-folded program name.

    Handles the Windows path-shape variations the classifier must see through
    (plan Step 4: path casing / separators / aliases): case-insensitive match
    (``TASKKILL`` == ``taskkill``), either path separator, a leading directory
    (``C:\\Windows\\System32\\taskkill.exe`` -> ``taskkill``, ``/usr/bin/grep`` ->
    ``grep``), and a trailing ``.exe`` (``git.exe`` -> ``git``). Surrounding
    quotes are stripped so a quoted program path still resolves.
    """
    low = token.strip("\"'").lower().replace("\\", "/")
    base = low.rsplit("/", 1)[-1]
    if base.endswith(".exe"):
        base = base[:-4]
    return base


def _is_git(segment: list[str]) -> bool:
    """True if ``segment`` is a ``git <subcommand> ...`` invocation (``git.exe`` too)."""
    return len(segment) >= 2 and _normalize_tool(segment[0]) == "git"


def _is_subst(token: str) -> bool:
    """True if ``token`` contains a shell substitution ($VAR/${...}/$(...)/%VAR%/backtick)."""
    return _SUBST_RE.search(token) is not None


def _flag_with_subst(token: str) -> bool:
    """True if ``token`` is a flag (``-``/``/`` lead) carrying a shell substitution."""
    return (token.startswith("-") or token.startswith("/")) and _is_subst(token)


def _first_subst(args: list[str]) -> str | None:
    """Return the first arg carrying a shell substitution, flag-shaped or bare.

    Used for risk-determining positions where the risky form may appear without a
    flag (a bare ``git reset $MODE`` or ``taskkill $SEL``): any substitution there
    is indeterminate and must resolve to ``unknown``, never a clean pass.
    """
    return next((a for a in args if _is_subst(a)), None)


def _first_subst_flag(args: list[str]) -> str | None:
    """Return the first flag-shaped arg whose value is a shell substitution.

    Used where the only risky form is itself a flag (``git push --force``): a bare
    substitution there is a non-risk-determining argument (a refspec) and does not
    make the verdict indeterminate.
    """
    return next((a for a in args if _flag_with_subst(a)), None)


def _finding(
    rule: rules.Rule,
    observed: str,
    *,
    suggestion: str | None = None,
    severity: Severity | None = None,
) -> Finding:
    """Build a command finding from a rule, its observed evidence, and options.

    ``observed`` carries only the observed value behind the verdict (plan section
    5). A deterministic safer-form ``suggestion`` is folded into the finding's
    ``message`` -- the rule's owned message plus a ``Suggested: ...`` clause --
    rather than into ``observed``. ``severity`` overrides the rule default (used
    for the ``unknown`` incomplete-evaluation case).
    """
    message = None if suggestion is None else f"{rule.message} Suggested: {suggestion}."
    return rule.finding(observed, evaluator="command", severity=severity, message=message)


# --- Rule 2: broad staging / bare git stash (TW-GIT-001, warn) --------------


def _match_broad_staging(segment: list[str]) -> Finding | None:
    """Rule 2 (TW-GIT-001, warn): flag broad ``git add`` / whole-tree ``git stash``.

    A definite broad flag (``-A`` / ``--all`` / ``.``) warns; otherwise a
    substitution in the staging-scope position is reported ``unknown`` (the scope
    cannot be confirmed). Scoped forms (``git add <path>``, ``git stash push --
    <paths>``, read-only stash subcommands including ``create``) clear.
    """
    if not _is_git(segment):
        return None
    sub = segment[1].lower()
    args = segment[2:]
    if sub == "add":
        hit = next((a for a in args if a in _BROAD_ADD_FLAGS or a.lower() == "--all"), None)
        if hit is not None:
            return _finding(
                rules.RULE_BROAD_STAGING,
                f"broad staging: git add {hit}",
                suggestion="git add <specific paths>",
            )
        subst = _first_subst(args)
        if subst is not None:
            return _finding(
                rules.RULE_BROAD_STAGING,
                f"git add scope is a shell substitution ({subst}); scope cannot be confirmed",
                severity="unknown",
            )
        return None
    if sub == "stash":
        action = args[0].lower() if args else ""
        if action in _SAFE_STASH_SUBCMDS:
            return None
        if action == "push":
            if "--" in args:
                return None  # git stash push -- <paths>: scoped, cleared
            observed = "git stash push without a `--` path separator (stashes all changes)"
        elif action == "save":
            observed = "git stash save (stashes all changes)"
        elif action == "":
            observed = "bare `git stash` (stashes all changes)"
        else:
            observed = f"git stash {args[0]} (may stash all changes)"
        return _finding(
            rules.RULE_BROAD_STAGING,
            observed,
            suggestion="git stash push -- <paths>",
        )
    return None


# --- Rule 7: destructive git (TW-GIT-003, fail) -----------------------------


def _destructive(observed: str, suggestion: str) -> Finding:
    """Build a fail-severity rule-7 finding with a deterministic safer-form suggestion."""
    return _finding(rules.RULE_DESTRUCTIVE_GIT, observed, suggestion=suggestion)


def _destructive_unknown(observed: str) -> Finding:
    """Build an ``unknown``-severity rule-7 finding for an indeterminate substitution."""
    return _finding(rules.RULE_DESTRUCTIVE_GIT, observed, severity="unknown")


def _match_destructive_git(segment: list[str]) -> Finding | None:
    """Rule 7 (TW-GIT-003, fail): flag irrecoverable git operations.

    ``reset --hard`` / ``push --force`` / ``checkout -- <path>`` are the
    destructive forms. When the risk-determining position (reset mode/target,
    checkout mode/target, or the push force flag) is a shell substitution so the
    risky form cannot be ruled out, the finding is ``unknown`` -- never cleared as
    safe. For ``push`` only a flag-shaped substitution is indeterminate; a bare
    refspec is not a risk-determining position.
    """
    if not _is_git(segment):
        return None
    sub = segment[1].lower()
    if sub not in _DESTRUCTIVE_SUBCMDS:
        return None
    args = segment[2:]
    if sub == "reset":
        if "--hard" in args:
            return _destructive(
                "git reset --hard",
                "stash or branch first; run git merge-base --is-ancestor before discarding",
            )
        subst = _first_subst(args)
        if subst is not None:
            return _destructive_unknown(
                f"git reset mode/target is a shell substitution ({subst}); may be --hard"
            )
        return None
    if sub == "push":
        if "--force" in args or "-f" in args:
            return _destructive(
                "git push --force",
                "git push --force-with-lease after a merge-base/ancestor check",
            )
        subst = _first_subst_flag(args)
        if subst is not None:
            return _destructive_unknown(
                f"git push flag is a shell substitution ({subst}); may be --force"
            )
        return None
    # checkout
    if "--" in args:
        return _destructive(
            "git checkout -- <path>",
            "git stash push -- <path> to preserve, or git restore knowingly",
        )
    subst = _first_subst(args)
    if subst is not None:
        return _destructive_unknown(
            f"git checkout mode/target is a shell substitution ({subst}); "
            "may be a '-- <path>' worktree discard"
        )
    return None


# --- Rule 8: name-based process kill (TW-CMD-001, fail) ---------------------


def _is_taskkill_name_flag(token: str) -> bool:
    """True if ``token`` is a ``taskkill`` name selector (``/IM`` or ``/IM:<name>``)."""
    low = token.lower()
    return low == "/im" or low.startswith("/im:")


def _is_taskkill_pid_flag(token: str) -> bool:
    """True if ``token`` is a ``taskkill`` PID selector (``/PID`` or ``/PID:<pid>``)."""
    low = token.lower()
    return low == "/pid" or low.startswith("/pid:")


def _is_stopprocess_name_flag(token: str) -> bool:
    """True if ``token`` is a ``Stop-Process`` name selector (``-Name`` or ``-Name:<name>``)."""
    low = token.lower()
    return low == "-name" or low.startswith("-name:")


def _is_stopprocess_id_flag(token: str) -> bool:
    """True if ``token`` is a ``Stop-Process`` id selector (``-Id`` or ``-Id:<pid>``)."""
    low = token.lower()
    return low == "-id" or low.startswith("-id:")


def _name_kill(observed: str, suggestion: str) -> Finding:
    """Build a fail-severity rule-8 finding with a PID-based safer-form suggestion."""
    return _finding(rules.RULE_NAME_BASED_KILL, observed, suggestion=suggestion)


def _name_kill_unknown(observed: str) -> Finding:
    """Build an ``unknown``-severity rule-8 finding for an indeterminate selector."""
    return _finding(rules.RULE_NAME_BASED_KILL, observed, severity="unknown")


def _match_name_kill(segment: list[str]) -> Finding | None:
    """Rule 8 (TW-CMD-001, fail): flag name-based process kills.

    ``taskkill /IM`` and ``Stop-Process -Name`` (including its ``spps`` alias, and
    an ``.exe``/path-qualified ``taskkill`` per :func:`_normalize_tool`) target by
    name (can hit unrelated processes). A substitution in the selector position
    that is not a confirmed PID/Id selector is ``unknown`` -- it may expand to a
    name selector -- never a clean pass. Explicit PID/Id selectors (even with a
    variable value) clear.
    """
    if not segment:
        return None
    tool = _normalize_tool(segment[0])
    args = segment[1:]
    if tool == "taskkill":
        if any(_is_taskkill_name_flag(a) for a in args):
            return _name_kill("taskkill /IM <name>", "taskkill /T /F /PID <pid>")
        subst = _first_subst(args)
        if subst is not None and not any(_is_taskkill_pid_flag(a) for a in args):
            return _name_kill_unknown(
                f"taskkill selector is a shell substitution ({subst}); may target by name"
            )
        return None
    if tool in _STOPPROCESS_TOOLS:
        if any(_is_stopprocess_name_flag(a) for a in args):
            return _name_kill("Stop-Process -Name <name>", "Stop-Process -Id <pid>")
        subst = _first_subst(args)
        if subst is not None and not any(_is_stopprocess_id_flag(a) for a in args):
            return _name_kill_unknown(
                f"Stop-Process selector is a shell substitution ({subst}); may target by name"
            )
        return None
    return None


# --- Rule 10: secret-file dump (TW-SEC-001, fail) ---------------------------


def _looks_secret(token: str) -> bool:
    """True if ``token`` names a secrets-bearing file (rule 10 dump target).

    Placeholder templates (``*.example`` / ``*.sample`` / ``*.template``) are
    committed non-secrets and are exempted first, so ``cat .env.example`` does not
    trip. Otherwise a secret substring, an ``.env``-family basename, a known
    secret basename, or a private-key suffix marks the token secrets-bearing.
    """
    low = token.lower().strip("\"'")
    if not low:
        return False
    base = low.replace("\\", "/").rsplit("/", 1)[-1]
    if base.endswith(_TEMPLATE_SUFFIXES):
        return False
    if any(sub in low for sub in _SECRET_SUBSTRINGS):
        return True
    if base == ".env" or base.startswith(".env.") or low.endswith(".env"):
        return True
    if base in _SECRET_BASENAMES:
        return True
    return any(low.endswith(suffix) for suffix in _SECRET_SUFFIXES)


def _looks_secret_literal(token: str) -> bool:
    """True if the token's non-substituted text names a secret (a CONFIRMED literal).

    A shell substitution's expansion is unknown, so a confirmed-secret verdict must
    rest on the literal portion: ``$DIR/id_rsa`` is a confirmed secret (``id_rsa``
    is literal) but ``%SECRET%`` / ``$VAR`` are not -- the only secret-shaped text
    lives inside the variable *name*, whose expansion cannot be seen, so those fall
    through to the substitution -> ``unknown`` branch instead of a false-confident
    ``fail``. With no substitution present this is identical to :func:`_looks_secret`.
    """
    return _looks_secret(_SUBST_RE.sub("", token))


def _match_secret_dump(segment: list[str]) -> Finding | None:
    """Rule 10 (TW-SEC-001, fail): flag dumping a secrets-bearing file's contents.

    A content-printing tool (``cat``/``type``/``grep``/...) with a secrets-bearing
    argument is the dump footgun; the safer form (metadata-only / effect-based
    verification) is folded into the finding message. Mirroring rules 2/7/8: when
    no argument is a confirmed secret but a dumped-target argument is a shell
    substitution (``cat $VAR``, ``type %SECRET%``) so it cannot be ruled out as
    naming a secret, the finding is ``unknown`` (exit 2) -- never cleared as safe.
    """
    if not segment:
        return None
    tool = _normalize_tool(segment[0])
    if tool not in _DUMP_TOOLS:
        return None
    args = segment[1:]
    secret = next((a for a in args if _looks_secret_literal(a)), None)
    if secret is None:
        subst = _first_subst(args)
        if subst is None:
            return None
        return _finding(
            rules.RULE_SECRET_FILE_DUMP,
            f"{tool} target is a shell substitution ({subst}); may name a secrets-bearing file",
            severity="unknown",
        )
    return _finding(
        rules.RULE_SECRET_FILE_DUMP,
        f"{tool} reads a secrets-bearing file ({secret})",
        suggestion="metadata-only checks (Get-Item / stat / wc -c) or effect-based verification",
    )


# --- Rule 9: shell mismatch (TW-SHL-001, warn) ------------------------------


def _match_shell_mismatch(tokens: list[_Token]) -> Finding | None:
    """Rule 9 (TW-SHL-001, warn): flag bash-only chaining operators in a PS 5.1 context.

    ``&&`` / ``||`` are parser errors in PowerShell 5.1; ``;`` and ``|`` are valid
    and excluded. Only an UNQUOTED operator token counts -- a quoted ``"&&"`` is a
    literal argument (a commit message, a grep pattern), not a shell operator, so
    it must not false-positive this rule. The safer form (split statements or
    ``; if ($?) { ... }``) is folded into the finding message.
    """
    hits = sorted({t.text for t in tokens if t.is_operator and t.text in _BASH_ONLY_OPERATORS})
    if not hits:
        return None
    return _finding(
        rules.RULE_SHELL_MISMATCH,
        f"bash-only operator(s) {' '.join(hits)} in a PowerShell 5.1 context",
        suggestion="split into separate statements, or use '; if ($?) { ... }'",
    )


#: Per-segment matchers in inventory (rule-number) order for deterministic output.
_SEGMENT_MATCHERS: tuple[Callable[[list[str]], Finding | None], ...] = (
    _match_broad_staging,
    _match_destructive_git,
    _match_name_kill,
    _match_secret_dump,
)


def classify(command: str) -> Classification:
    """Classify a proposed command string against the command-evaluator rules.

    Returns a :class:`Classification`. Empty or unparseable input yields an
    ``invalid_reason`` (no findings); otherwise the risk findings are returned in
    a deterministic order (per-segment matchers in rule-number order, then the
    whole-command shell-mismatch check). An empty ``findings`` tuple with no
    ``invalid_reason`` means no documented risky pattern matched -- which the CLI
    reports as "no known risky pattern" and never as an endorsement.
    """
    if not command.strip():
        return Classification(invalid_reason="no command text to evaluate")
    tokens = _tokenize_rich(command)
    if tokens is None:
        return Classification(invalid_reason="could not parse command text (unbalanced quote)")
    findings: list[Finding] = []
    for segment in _segments(tokens):
        for matcher in _SEGMENT_MATCHERS:
            found = matcher(segment)
            if found is not None:
                findings.append(found)
    shell = _match_shell_mismatch(tokens)
    if shell is not None:
        findings.append(shell)
    return Classification(findings=tuple(findings))
