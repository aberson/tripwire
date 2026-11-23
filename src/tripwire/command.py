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
not a risk-determining position and stays clean. Rule 10 has no ``unknown``
branch since 0.1.2 (see :func:`_match_secret_dump` for the replay evidence).

Wrappers and data (0.1.2): a PowerShell ``-Command`` wrapper line -- the shape
the Codex CLI hands hooks for every shell call -- is unwrapped and its inner
command classified as PowerShell (:func:`unwrap_powershell`; any shape it cannot
read unambiguously is classified as given). Heredoc and here-string bodies are
data and are removed before tokenizing (:func:`strip_heredoc_bodies`).

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

#: Source / documentation suffixes. A file whose basename ends in one of these is
#: code or prose ABOUT secrets (``secret_scanner.py``, ``secrets-handling.md``),
#: not a secret store, so the substring signal (``secret`` / ``credential`` /
#: ``password`` ...) does not mark it. The basename and private-key-suffix
#: signals are unaffected.
_SOURCE_SUFFIXES = (
    ".md",
    ".markdown",
    ".rst",
    ".html",
    ".htm",
    ".py",
    ".pyi",
    ".ps1",
    ".psm1",
    ".psd1",
    ".sh",
    ".bash",
    ".js",
    ".mjs",
    ".cjs",
    ".ts",
    ".tsx",
    ".jsx",
    ".rs",
    ".go",
    ".java",
    ".kt",
    ".cs",
    ".rb",
    ".c",
    ".h",
    ".cpp",
    ".hpp",
    ".css",
    ".svg",
    ".mmd",
    ".ipynb",
)

#: Search tools whose FIRST operand is a pattern/program, not a file (rule 10
#: judges only the file operands; see :func:`_dump_file_operands`).
_GREP_TOOLS = frozenset({"grep"})
_SELECT_STRING_TOOLS = frozenset({"sls", "select-string"})
_AWK_TOOLS = frozenset({"awk"})

#: grep short options that take a value (the next token, or the bundle's rest).
_GREP_SHORT_VALUE = frozenset("efmABCdD")
#: grep long options that take a separate value when written without ``=``.
_GREP_LONG_VALUE = frozenset(
    {
        "--regexp",
        "--file",
        "--max-count",
        "--after-context",
        "--before-context",
        "--context",
        "--include",
        "--exclude",
        "--exclude-dir",
        "--exclude-from",
        "--label",
        "--binary-files",
        "--devices",
        "--directories",
        "--group-separator",
    }
)
#: Select-String parameters that take a value (case-folded); ``-Pattern`` and the
#: path parameters are handled separately.
_SLS_VALUE_PARAMS = frozenset(
    {"-context", "-encoding", "-include", "-exclude", "-culture", "-inputobject"}
)
_SLS_PATH_PARAMS = frozenset({"-path", "-literalpath", "-lp", "-pspath"})

#: Output-redirection operators whose NEXT token is a write target, not an input.
_REDIRECT_OUT = frozenset({">", ">>", "1>", "2>", "1>>", "2>>", "&>", "&>>", "*>", "*>>", ">|"})
_REDIRECT_OUT_ATTACHED = re.compile(r"^(?:[0-9&*]?>>?|>\|)")

#: A bash heredoc operator: ``<<WORD``, ``<<-WORD``, ``<<'WORD'``, ``<<"WORD"``,
#: ``<<\WORD`` (not the ``<<<`` here-string). Group ``dash`` marks ``<<-`` (tab-
#: stripped terminator); one of ``sq`` / ``dq`` / ``bare`` is the delimiter.
_HEREDOC_RE = re.compile(
    r"(?<!<)<<(?P<dash>-?)[ \t]*"
    r"(?:'(?P<sq>[^'\n]+)'|\"(?P<dq>[^\"\n]+)\"|\\?(?P<bare>[A-Za-z_][\w-]*))"
)
#: A PowerShell here-string opener at end of line (``@'`` / ``@"``).
_HERESTRING_OPEN_RE = re.compile(r"@(['\"])[ \t]*\r?$")


#: Shell names a :class:`Classification` reports. ``unspecified`` means tripwire
#: did not establish the shell: the text was classified as given, and the caller's
#: host context decides which shell it runs in (the historical behaviour).
#: ``powershell`` means the text was a recognised PowerShell ``-Command`` wrapper
#: and the inner command was classified as PowerShell.
SHELL_UNSPECIFIED = "unspecified"
SHELL_POWERSHELL = "powershell"


@dataclass(frozen=True)
class Classification:
    """Result of classifying one command string.

    ``findings`` are the (possibly empty) risk findings. ``invalid_reason`` is
    set only for empty/unparseable input; the CLI maps it to exit 2 at the
    boundary rather than inventing a finding for text it could not parse.
    ``shell`` / ``unwrapped`` / ``inner_command`` say what was classified: when a
    PowerShell ``-Command`` wrapper was recognised (:func:`unwrap_powershell`),
    ``unwrapped`` is true, ``shell`` is ``powershell`` and ``inner_command`` holds
    the extracted inner text the findings were judged on.
    """

    findings: tuple[Finding, ...] = ()
    invalid_reason: str | None = None
    shell: str = SHELL_UNSPECIFIED
    unwrapped: bool = False
    inner_command: str | None = None


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
    if not base.endswith(_SOURCE_SUFFIXES) and any(sub in low for sub in _SECRET_SUBSTRINGS):
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


def _strip_redirections(args: list[str]) -> list[str]:
    """Drop output-redirection targets and heredoc markers from a dump tool's args.

    ``cat > notes.md`` / ``type x 2> err.log`` WRITE the redirect target; it is not
    an input, so it is never a dump target. ``cat < .env`` reads its input
    redirect, which IS a dump target, so the input file is kept. A heredoc marker
    (``<<'EOF'``) ends the scan: whatever the tokenizer sees after it on that
    line is the heredoc's own wiring, not a file being printed.
    """
    kept: list[str] = []
    i = 0
    while i < len(args):
        token = args[i]
        if token.startswith("<<"):
            break
        if token in _REDIRECT_OUT:
            i += 2
            continue
        if _REDIRECT_OUT_ATTACHED.match(token):
            i += 1
            continue
        if token == "<":
            if i + 1 < len(args):
                kept.append(args[i + 1])
            i += 2
            continue
        if token.startswith("<"):
            kept.append(token[1:])
            i += 1
            continue
        kept.append(token)
        i += 1
    return kept


def _grep_file_operands(args: list[str]) -> list[str]:
    """Return grep's FILE operands: the positionals minus the pattern.

    The first positional is the pattern unless ``-e`` / ``-f`` / ``--regexp`` /
    ``--file`` supplied it. Option values (``-A 3``, ``--include *.py``) are
    skipped. GNU grep permutes, so options may follow the operands.
    """
    positionals: list[str] = []
    explicit_pattern = False
    end_of_options = False
    i = 0
    while i < len(args):
        token = args[i]
        if end_of_options or not token.startswith("-") or token == "-":
            positionals.append(token)
            i += 1
            continue
        if token == "--":
            end_of_options = True
            i += 1
            continue
        if token.startswith("--"):
            name = token.split("=", 1)[0]
            if name in ("--regexp", "--file"):
                explicit_pattern = True
            i += 2 if ("=" not in token and name in _GREP_LONG_VALUE) else 1
            continue
        takes_next = False
        for j, ch in enumerate(token[1:], start=1):
            if ch in _GREP_SHORT_VALUE:
                explicit_pattern = explicit_pattern or ch in "ef"
                takes_next = j == len(token) - 1
                break
        i += 2 if takes_next else 1
    return positionals if explicit_pattern else positionals[1:]


def _select_string_file_operands(args: list[str]) -> list[str]:
    """Return Select-String's path operands (``-Path`` / ``-LiteralPath`` / 2nd positional).

    ``-Pattern`` (any abbreviation from ``-pat``) and the first positional are the
    pattern. Parameter names are case-insensitive and may carry an attached
    ``-Name:value``. Comma-separated path arrays are split.
    """
    paths: list[str] = []
    pattern_seen = False
    i = 0
    while i < len(args):
        token = args[i]
        if token.startswith("-") and len(token) > 1:
            name, sep, attached = token.partition(":")
            name = name.lower()
            value: str | None = attached if sep else None
            consumed = 1 if sep else 2
            if len(name) >= 4 and "-pattern".startswith(name):
                pattern_seen = True
                i += consumed
                continue
            if name in _SLS_PATH_PARAMS:
                if value is None and i + 1 < len(args):
                    value = args[i + 1]
                if value is not None:
                    paths.extend(v for v in value.split(",") if v)
                i += consumed
                continue
            if name in _SLS_VALUE_PARAMS:
                i += consumed
                continue
            i += 1  # a switch (-SimpleMatch, -Quiet, -Raw, ...)
            continue
        if not pattern_seen:
            pattern_seen = True
        else:
            paths.extend(v for v in token.split(",") if v)
        i += 1
    return paths


def _awk_file_operands(args: list[str]) -> list[str]:
    """Return awk's FILE operands: the positionals minus the program text.

    ``-F <sep>`` / ``-v <var=val>`` take a value; ``-f <progfile>`` supplies the
    program, after which every positional is a file.
    """
    positionals: list[str] = []
    program_from_file = False
    i = 0
    while i < len(args):
        token = args[i]
        if token in ("-F", "-v", "-f"):
            program_from_file = program_from_file or token == "-f"
            i += 2
            continue
        if token.startswith(("-F", "-v")) and len(token) > 2:
            i += 1
            continue
        if token.startswith("-f") and len(token) > 2:
            program_from_file = True
            i += 1
            continue
        if token == "--":
            positionals.extend(args[i + 1 :])
            break
        if token.startswith("-") and token != "-":
            i += 1
            continue
        positionals.append(token)
        i += 1
    return positionals if program_from_file else positionals[1:]


def _dump_file_operands(tool: str, args: list[str]) -> list[str]:
    """Return the arguments of a dump tool that name a file it PRINTS (rule 10).

    Redirect targets and heredoc wiring are dropped first
    (:func:`_strip_redirections`). For the search tools the pattern / program
    operand is excluded -- searching FOR the text ``.env`` or ``password`` prints
    nothing from a secrets file -- so only their file operands are judged. Every
    other dump tool prints every operand, so all of its remaining args are kept
    (option tokens such as ``-n`` never look like a secret).
    """
    args = _strip_redirections(args)
    if tool in _GREP_TOOLS:
        return _grep_file_operands(args)
    if tool in _SELECT_STRING_TOOLS:
        return _select_string_file_operands(args)
    if tool in _AWK_TOOLS:
        return _awk_file_operands(args)
    return args


def _match_secret_dump(segment: list[str]) -> Finding | None:
    """Rule 10 (TW-SEC-001, fail): flag dumping a secrets-bearing file's contents.

    A content-printing tool (``cat``/``type``/``grep``/...) with a secrets-bearing
    FILE operand is the dump footgun; the safer form (metadata-only / effect-based
    verification) is folded into the finding message. Only the operands the tool
    prints are judged (:func:`_dump_file_operands`): a grep / Select-String / awk
    pattern, a redirect target and a heredoc body are not files being printed.
    Unlike rules 2/7/8 there is NO ``unknown`` branch since 0.1.2: a file operand
    that is a shell substitution (``cat $f``, ``Get-Content $path``) is not
    reported. A substitution's literal part still counts (``cat $DIR/id_rsa``
    fails). Evidence for retiring the branch (2026-11-23 replay of the 8,247
    pre-screened Claude shell commands in the shadow-log window from 2026-11-22
    23:27 UTC): it produced 1,115 of the rule's 1,156 hook rows, the hook never
    surfaces an ``unknown``, and the substitutions were loop variables and paths;
    real dumps are blocked separately by the workspace secret-read-guard hook.
    """
    if not segment:
        return None
    tool = _normalize_tool(segment[0])
    if tool not in _DUMP_TOOLS:
        return None
    args = _dump_file_operands(tool, segment[1:])
    secret = next((a for a in args if _looks_secret_literal(a)), None)
    if secret is None:
        return None
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


# --- PowerShell -Command wrapper (Codex CLI shell calls) -------------------------

#: Program basenames (case-folded) recognised as a PowerShell host.
_POWERSHELL_PROGRAMS = frozenset({"powershell.exe", "powershell", "pwsh.exe", "pwsh"})

#: Value-less PowerShell host switches accepted before ``-Command`` (with their
#: documented abbreviations). Anything not listed here makes the shape unknown.
_POWERSHELL_SWITCHES = frozenset(
    {"-noprofile", "-nop", "-noninteractive", "-noni", "-nologo", "-nol"}
)

#: PowerShell host parameters that take exactly one value, accepted before ``-Command``.
_POWERSHELL_VALUE_PARAMS = frozenset({"-executionpolicy", "-ep", "-ex", "-exec"})

#: The command parameter spellings accepted: ``-Command`` and its alias ``-c``.
_POWERSHELL_COMMAND_PARAMS = frozenset({"-command", "-c"})


def _split_windows_command_line(line: str) -> list[str] | None:
    """Split a Windows command line into argv, or ``None`` when it is ambiguous.

    Implements the Microsoft C runtime / ``CommandLineToArgvW`` rules, which are
    what ``powershell.exe`` itself uses to read its arguments and what a
    Rust-``std::process::Command``-style quoter (the Codex CLI's spawner) emits:

    * argv[0] (the program) is either a double-quoted span with no escape
      processing, or a run of non-blank characters containing no quote;
    * later arguments are separated by spaces/tabs outside quotes; ``"`` toggles
      quoting; ``2n`` backslashes before a ``"`` yield ``n`` backslashes and the
      quote toggles, ``2n+1`` yield ``n`` backslashes and a literal ``"``; other
      backslashes are literal.

    It refuses (``None``) everything whose meaning differs between C-runtime
    versions or that no conforming quoter would emit: an unterminated quote, a
    ``""`` pair inside a quoted span, a quoted program followed directly by a
    non-blank character, and a line break outside quotes.
    """
    n = len(line)
    i = 0
    while i < n and line[i] in " \t":
        i += 1
    if i >= n:
        return None
    argv: list[str] = []
    if line[i] == '"':
        close = line.find('"', i + 1)
        if close == -1:
            return None
        argv.append(line[i + 1 : close])
        i = close + 1
        if i < n and line[i] not in " \t":
            return None
    else:
        start = i
        while i < n and line[i] not in " \t":
            if line[i] == '"' or line[i] in "\r\n":
                return None
            i += 1
        argv.append(line[start:i])
    while True:
        while i < n and line[i] in " \t":
            i += 1
        if i >= n:
            return argv
        buf: list[str] = []
        in_quotes = False
        while i < n:
            ch = line[i]
            if ch == "\\":
                run = i
                while run < n and line[run] == "\\":
                    run += 1
                count = run - i
                if run < n and line[run] == '"':
                    buf.append("\\" * (count // 2))
                    if count % 2:
                        buf.append('"')
                        i = run + 1
                    else:
                        i = run  # the quote toggles on the next pass
                else:
                    buf.append("\\" * count)
                    i = run
                continue
            if ch == '"':
                if in_quotes and i + 1 < n and line[i + 1] == '"':
                    return None  # "" inside quotes: C-runtime-version dependent
                in_quotes = not in_quotes
                i += 1
                continue
            if not in_quotes and ch in " \t":
                break
            if not in_quotes and ch in "\r\n":
                return None
            buf.append(ch)
            i += 1
        if in_quotes:
            return None  # unterminated quote
        argv.append("".join(buf))


def unwrap_powershell(command: str) -> str | None:
    """Return the inner command of a PowerShell ``-Command`` wrapper, or ``None``.

    The Codex CLI runs every shell call on Windows as
    ``"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe" -Command "<cmd>"``
    and hands hooks that whole line as the command, so tripwire would otherwise
    judge the wrapper instead of the real (PowerShell) command. Accepted shape,
    and nothing else:

    * the program: a quoted or unquoted path whose basename is ``powershell.exe``
      or ``pwsh.exe`` (or the bare names, with or without ``.exe``), any case;
    * optionally ``-NoProfile`` / ``-NonInteractive`` / ``-NoLogo`` (or their
      abbreviations ``-nop`` / ``-noni`` / ``-nol``) and ``-ExecutionPolicy
      <value>`` (``-ep`` / ``-ex`` / ``-exec``), in any order and case;
    * then ``-Command`` or ``-c`` followed by EXACTLY ONE argument.

    The line is split with :func:`_split_windows_command_line`. Anything else --
    another parameter (``-File``, ``-EncodedCommand``), several arguments after
    ``-Command`` (PowerShell would re-join them, losing their quoting), an
    ambiguous quote, an empty inner command, or ``-`` (read from stdin) -- is not
    unwrapped, and the caller falls back to classifying the text as given.
    """
    argv = _split_windows_command_line(command)
    if argv is None or len(argv) < 3:
        return None
    program = argv[0].lower().replace("\\", "/").rsplit("/", 1)[-1]
    if program not in _POWERSHELL_PROGRAMS:
        return None
    i = 1
    while i < len(argv):
        param = argv[i].lower()
        if param in _POWERSHELL_SWITCHES:
            i += 1
            continue
        if param in _POWERSHELL_VALUE_PARAMS:
            i += 2
            continue
        if param in _POWERSHELL_COMMAND_PARAMS:
            rest = argv[i + 1 :]
            if len(rest) != 1:
                return None
            inner = rest[0]
            if not inner.strip() or inner.strip() == "-":
                return None
            return inner
        return None
    return None


def strip_heredoc_bodies(command: str) -> str:
    """Remove bash heredoc bodies and PowerShell here-string bodies from ``command``.

    A heredoc / here-string body is DATA fed to a command (a commit message, a
    file being written), never command text, yet the tokenizer would otherwise
    read its words as arguments -- and its stray ``;`` / ``|`` / quotes as
    structure. Removed:

    * bash ``<<WORD`` / ``<<-WORD`` / ``<<'WORD'`` / ``<<"WORD"`` / ``<<\\WORD``:
      every following line up to and including the terminator line (exactly
      ``WORD``; leading tabs allowed for ``<<-``), several heredocs on one line
      consumed in order;
    * PowerShell ``@'`` / ``@"`` at the end of a line: the lines up to (not
      including) the closing ``'@`` / ``"@`` line.

    Conservative: if ANY opener has no terminator the text is returned
    unchanged, because an operator-looking ``<<`` (a C++ shift in an inline
    script) must not swallow real commands.
    """
    lines = command.split("\n")
    out: list[str] = []
    i = 0
    while i < len(lines):
        line = lines[i]
        out.append(line)
        i += 1
        delimiters = [
            (m.group("sq") or m.group("dq") or m.group("bare") or "", bool(m.group("dash")))
            for m in _HEREDOC_RE.finditer(line)
        ]
        if delimiters:
            for word, dash in delimiters:
                j = i
                while j < len(lines):
                    candidate = lines[j].rstrip("\r")
                    if (candidate.lstrip("\t") if dash else candidate) == word:
                        break
                    j += 1
                else:
                    return command  # unterminated heredoc: leave the text as given
                i = j + 1
            continue
        opener = _HERESTRING_OPEN_RE.search(line)
        if opener is not None:
            closer = opener.group(1) + "@"
            j = i
            while j < len(lines) and not lines[j].startswith(closer):
                j += 1
            if j >= len(lines):
                return command  # unterminated here-string
            i = j  # keep the closing line; drop only the body
    return "\n".join(out)


def _classify_text(command: str) -> Classification:
    """Classify ``command`` as given (no wrapper detection).

    Heredoc / here-string bodies are removed first (:func:`strip_heredoc_bodies`).
    """
    if not command.strip():
        return Classification(invalid_reason="no command text to evaluate")
    tokens = _tokenize_rich(strip_heredoc_bodies(command))
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


def classify(command: str) -> Classification:
    """Classify a proposed command string against the command-evaluator rules.

    Returns a :class:`Classification`. Empty or unparseable input yields an
    ``invalid_reason`` (no findings); otherwise the risk findings are returned in
    a deterministic order (per-segment matchers in rule-number order, then the
    whole-command shell-mismatch check). An empty ``findings`` tuple with no
    ``invalid_reason`` means no documented risky pattern matched -- which the CLI
    reports as "no known risky pattern" and never as an endorsement.

    A recognised PowerShell ``-Command`` wrapper (:func:`unwrap_powershell`) is
    unwrapped first and its inner command is classified as PowerShell. When the
    inner command cannot be classified (unparseable for the tokenizer), the
    wrapper text is classified as given instead -- the pre-unwrap behaviour.
    """
    inner = unwrap_powershell(command)
    if inner is not None:
        result = _classify_text(inner)
        if result.invalid_reason is None:
            return Classification(
                findings=result.findings,
                shell=SHELL_POWERSHELL,
                unwrapped=True,
                inner_command=inner,
            )
    return _classify_text(command)
