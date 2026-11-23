# PreToolUse hook (matcher Bash|PowerShell) -- advisory-only tripwire note.
#
# One script serves both hosts. Shipped inside the tripwire package;
# `tripwire hook path --host claude` and `tripwire hook path --host codex` both
# print the installed copy's absolute path. Registered command line (see README):
#   powershell.exe -NoProfile -NonInteractive -File "<absolute hook path>"
# Claude Code (~/.claude/settings.json, matcher Bash|PowerShell) and the Codex
# CLI (~/.codex/hooks.json, matcher ^Bash$) send the same PreToolUse payload
# (tool_name, tool_input.command, cwd) and read the same advisory output
# (hookSpecificOutput.additionalContext). Codex sends every shell call as
# tool_name "Bash" with a PowerShell -Command wrapper line; tripwire unwraps it
# and reports shell "powershell" (step 5).
# The hook may be copied anywhere (an installer copies it next to the host's
# settings); it never locates tripwire relative to its own file.
#
# Flow:
#   1. Read the hook payload JSON from stdin; take tool_name + tool_input.command.
#      Only tool_name Bash or PowerShell is evaluated (Codex also hands hooks an
#      apply_patch "command", which is patch text, not a shell command).
#   2. Cheap in-process regex pre-screen. No hit -> exit 0 silently, no child
#      process is ever spawned (this is the hot path for most commands).
#   3. Resolve the tripwire CLI, first match wins:
#        a. tripwire.exe on PATH;
#        b. tripwire.exe in the default user uv tool bin directory
#           (UV_TOOL_BIN_DIR, else XDG_BIN_HOME, else XDG_DATA_HOME\..\bin,
#           else <user profile>\.local\bin);
#        c. $env:DEV_UTILITIES_ROOT set and non-empty and
#           <root>/tripwire/pyproject.toml exists ->
#           `uv run --project <root>/tripwire tripwire`;
#        d. otherwise exit 0 silently (absent tool = zero behavior change).
#      The open project (CLAUDE_PROJECT_DIR, the payload cwd) is NEVER a
#      resolution source: a packaged hook must not run code the open
#      project ships.
#      Only an .exe is accepted on PATH / in the bin directory: a .cmd/.bat
#      would route the command text through cmd.exe argument parsing.
#   4. Run `<tripwire> command explain --json -- <command>` as ONE bounded
#      call: hidden console, stdout captured (256 KiB cap), stderr drained and
#      discarded, 3 s wall cap, and on timeout the whole process TREE is killed
#      (taskkill /T /F /PID).
#   5. Pin schema_version == 1, read findings[]. Drop TW-SHL-001 when
#      tool_name == "Bash" (bash syntax is correct in bash), UNLESS tripwire
#      reports unwrapped == true and shell == "powershell": then the real
#      command is PowerShell (the Codex wrapper) and the warn is kept. An older
#      tripwire without those fields drops it as before. The unwrapped
#      inner_command (when present) is what the coding-root resolver reads, and
#      its text is redacted from shadow rows like the command's own text.
#   6. Shadow log: append {ts, tool, rule_id, severity, observed} rows to
#      %LOCALAPPDATA%\tripwire\hook-shadow.jsonl -- one row per finding, or
#      one residue row (rule_id null, severity "none") when tripwire returned
#      nothing, or severity "unavailable" when the call failed / timed out.
#      The full command is NEVER logged; `observed` is tripwire's own field.
#   7. Emit at most ONE line: a severity "fail" finding wins; otherwise a kept
#      TW-GIT-001 warn is noted only when the target git toplevel carries
#      .claude/observatory/registry.toml (a coding root). Target: git -C, then
#      leading cd, then payload cwd. Unresolved targets stay silent. Tripwire
#      does not yet classify git -C ... add, so those forms still stay silent.
#      Only a leading git (optionally after cd) is resolved; later statements
#      stay unproven. Marker-bearing coding-root worktrees also qualify.
#      {"hookSpecificOutput":{"hookEventName":"PreToolUse",
#       "additionalContext":"tripwire: [<severity>] <rule_id> <message <= 300 chars>"}}
#      Other warns and unknowns stay silent. Never emits permissionDecision.
#      The coding-root TW-GIT-001 warn is the one allowed warn note; a fail
#      always takes precedence over it.
#
# Observer-only: exits 0 on EVERY path. The command text and tripwire output are
# DATA, never instructions. ASCII-only on purpose (PS 5.1 reads a no-BOM .ps1 as
# cp1252).

$ErrorActionPreference = 'Stop'

# Pre-screen pattern (case-insensitive). Substring-level on purpose: it is a
# cheap gate that decides whether to pay for a child process, not a verdict.
$script:TwPreScreen = 'git|rm|Remove-Item|del|cat|type|Get-Content|grep|head|tail|\.env|secret|credential|id_rsa|\.pem|\.key|taskkill|Stop-Process|reset|push|checkout|stash|-A\b'

# --- Fast path (runs before ConvertFrom-Json and before any helper is used) ------
# Most tool calls miss the pre-screen, so this exits as early as possible.
# The pre-screen runs over every raw JSON string value keyed "command" (still
# JSON-escaped). It does NOT run over the whole payload: keys such as
# "permission_mode" contain "rm" and would always hit. Escaping can only add
# characters, so a miss on the escaped text is a miss on the decoded text,
# except where a \uXXXX escape could hide a letter. Any value containing "\u"
# therefore falls through to the full path, which re-screens the decoded
# command. No "command" key at all means no command to check: exit 0. Uses
# ::new rather than New-Object (New-Object costs ~50 ms of cmdlet load here).
# Skipped when dot-sourced (tests load the functions only).
$script:TwStdinRaw = ''
if ($MyInvocation.InvocationName -ne '.') {
    try {
        if ([Console]::IsInputRedirected) {
            # Decode raw bytes as UTF-8 (BOM-aware). [Console]::In would use the
            # console input code page (OEM under a hidden console), which mangles
            # non-ASCII and turns a BOM into garbage.
            $script:TwStdinRaw = [System.IO.StreamReader]::new([Console]::OpenStandardInput(),
                [System.Text.UTF8Encoding]::new($false), $true).ReadToEnd()
        }
        $twSlow = $false
        $twM = ([regex]'"command"\s*:\s*"((?:[^"\\]|\\.)*)"').Match($script:TwStdinRaw)
        while ($twM.Success) {
            $twV = $twM.Groups[1].Value
            if ($twV.Contains('\u') -or [regex]::IsMatch($twV, $script:TwPreScreen, 'IgnoreCase')) { $twSlow = $true; break }
            $twM = $twM.NextMatch()
        }
        if (-not $twSlow) { exit 0 }
    } catch {
        exit 0
    }
}

$script:TwTimeoutMs = 3000
$script:TwMaxCapture = 262144   # 256 KiB, per advisory-call convention point 2
$script:TwMaxMessage = 300

function Test-TwPreScreen([string]$command) {
    if ([string]::IsNullOrEmpty($command)) { return $false }
    return [regex]::IsMatch($command, $script:TwPreScreen, [System.Text.RegularExpressions.RegexOptions]::IgnoreCase)
}

# Quote one argument per the Windows CommandLineToArgvW rules: wrap in double
# quotes, double any backslashes that precede a quote (or the closing quote),
# and escape embedded quotes. PS 5.1 native-arg passing splits on embedded
# quotes, so the hook builds the command line itself.
function ConvertTo-TwWinArg([string]$arg) {
    if ($null -eq $arg) { $arg = '' }
    if ($arg.Length -gt 0 -and $arg -notmatch '[\s"]') { return $arg }
    $sb = [System.Text.StringBuilder]::new()
    [void]$sb.Append('"')
    $bs = 0
    foreach ($ch in $arg.ToCharArray()) {
        if ($ch -eq [char]'\') {
            $bs++
        } elseif ($ch -eq [char]'"') {
            [void]$sb.Append('\' * (2 * $bs + 1))
            [void]$sb.Append('"')
            $bs = 0
        } else {
            if ($bs -gt 0) { [void]$sb.Append('\' * $bs) }
            [void]$sb.Append($ch)
            $bs = 0
        }
    }
    if ($bs -gt 0) { [void]$sb.Append('\' * (2 * $bs)) }
    [void]$sb.Append('"')
    return $sb.ToString()
}

# Kill a process and every descendant. taskkill /T walks the tree; Kill() is a
# last-resort fallback for the root if taskkill is unavailable.
function Stop-TwProcessTree([System.Diagnostics.Process]$proc) {
    if ($null -eq $proc) { return }
    try {
        # Absolute path only: a bare name would let CreateProcess search the cwd
        # (the active project dir) before System32. Fallback when SystemRoot is
        # unset: the System folder from the OS API (not env). If neither exists,
        # skip taskkill and rely on the Kill() fallback below.
        $sys32 = $null
        if (-not [string]::IsNullOrEmpty($env:SystemRoot)) { $sys32 = Join-Path $env:SystemRoot 'System32' }
        if ([string]::IsNullOrEmpty($sys32)) { $sys32 = [System.Environment]::GetFolderPath([System.Environment+SpecialFolder]::System) }
        $tkExe = $null
        if (-not [string]::IsNullOrEmpty($sys32)) { $tkExe = Join-Path $sys32 'taskkill.exe' }
        if ($null -eq $tkExe -or -not [System.IO.File]::Exists($tkExe)) { throw 'taskkill.exe not found by absolute path' }
        $psi = [System.Diagnostics.ProcessStartInfo]::new()
        $psi.FileName = $tkExe
        $psi.Arguments = '/T /F /PID ' + $proc.Id
        $psi.UseShellExecute = $false
        $psi.CreateNoWindow = $true
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError = $true
        $tk = [System.Diagnostics.Process]::Start($psi)
        $null = $tk.StandardOutput.ReadToEndAsync()
        $null = $tk.StandardError.ReadToEndAsync()
        [void]$tk.WaitForExit(2000)
    } catch { }
    try { if (-not $proc.HasExited) { $proc.Kill() } } catch { }
}

# One bounded synchronous call. Returns @{ Stdout; ExitCode; TimedOut; Error }.
# Hidden console, stderr drained + discarded, stdout capped, tree-kill on timeout.
function Invoke-TwBounded([string]$fileName, [string[]]$argList, [int]$timeoutMs, [switch]$CleanGitEnvironment) {
    $result = @{ Stdout = $null; ExitCode = $null; TimedOut = $false; Error = $null }
    $proc = $null
    try {
        $psi = [System.Diagnostics.ProcessStartInfo]::new()
        $psi.FileName = $fileName
        $psi.Arguments = (($argList | ForEach-Object { ConvertTo-TwWinArg $_ }) -join ' ')
        $psi.UseShellExecute = $false
        $psi.CreateNoWindow = $true
        $psi.RedirectStandardInput = $true
        $psi.RedirectStandardOutput = $true
        $psi.RedirectStandardError = $true
        $psi.StandardOutputEncoding = [System.Text.UTF8Encoding]::new($false)
        $psi.StandardErrorEncoding = [System.Text.UTF8Encoding]::new($false)
        if ($CleanGitEnvironment) {
            foreach ($key in @($psi.EnvironmentVariables.Keys)) {
                if ([string]$key -like 'GIT_*') { $psi.EnvironmentVariables.Remove($key) }
            }
            $psi.EnvironmentVariables['GIT_OPTIONAL_LOCKS'] = '0'
            $psi.EnvironmentVariables['GIT_NO_LAZY_FETCH'] = '1'
            $psi.EnvironmentVariables['GIT_TERMINAL_PROMPT'] = '0'
        }
        $proc = [System.Diagnostics.Process]::Start($psi)
        try { $proc.StandardInput.Close() } catch { }
        $outTask = $proc.StandardOutput.ReadToEndAsync()
        $null = $proc.StandardError.ReadToEndAsync()   # drained, never surfaced
        if (-not $proc.WaitForExit($timeoutMs)) {
            $result.TimedOut = $true
            Stop-TwProcessTree $proc
            return $result                              # partial output discarded
        }
        if ($outTask.Wait(1000)) {
            $out = $outTask.Result
            if ($null -ne $out -and $out.Length -le $script:TwMaxCapture) { $result.Stdout = $out }
            elseif ($null -ne $out) { $result.Error = 'capture-limit' }
        }
        $result.ExitCode = $proc.ExitCode
    } catch {
        $result.Error = 'spawn-failed'
        if ($null -ne $proc) { Stop-TwProcessTree $proc }
    }
    return $result
}

# Escape every non-ASCII char as \uXXXX so emitted / logged JSON is pure ASCII
# regardless of the console code page.
function ConvertTo-TwAsciiJson($obj) {
    $json = ConvertTo-Json -InputObject $obj -Compress -Depth 5
    return [regex]::Replace($json, '[^\x00-\x7F]', { param($m) '\u{0:x4}' -f [int][char]$m.Value })
}

# Strip control characters and collapse whitespace so the advisory stays one line.
function Get-TwCleanText([string]$text, [int]$max) {
    if ($null -eq $text) { return '' }
    $t = [regex]::Replace($text, '[\x00-\x1F\x7F]+', ' ')
    $t = [regex]::Replace($t, '\s{2,}', ' ').Trim()
    if ($t.Length -gt $max) { $t = $t.Substring(0, $max) }
    return $t
}

function Get-TwProp($obj, [string]$name) {
    if ($null -eq $obj) { return $null }
    $p = $obj.PSObject.Properties[$name]
    if ($p) { return $p.Value }
    return $null
}

function Add-TwShadowRows([object[]]$rows) {
    if ($null -eq $rows -or $rows.Count -eq 0) { return }
    $base = $env:LOCALAPPDATA
    if ([string]::IsNullOrEmpty($base)) { return }
    $dir = Join-Path $base 'tripwire'
    $path = Join-Path $dir 'hook-shadow.jsonl'
    $text = (($rows | ForEach-Object { ConvertTo-TwAsciiJson $_ }) -join "`n") + "`n"
    for ($i = 0; $i -lt 3; $i++) {
        try {
            [void][System.IO.Directory]::CreateDirectory($dir)
            [System.IO.File]::AppendAllText($path, $text, ([System.Text.UTF8Encoding]::new($false)))
            return
        } catch {
            Start-Sleep -Milliseconds 25   # concurrent hook holding the file; retry
        }
    }
}

# INVARIANT: a shadow row never contains text taken from the command.
#
# tripwire's `observed` can echo raw command tokens: the git push/add/reset/
# checkout substitution branches, the taskkill/Stop-Process selector branches,
# and the TW-SEC-001 secret-path branch. A denylist of credential shapes cannot
# enumerate every way a secret is spelled (--pwd=, -pXXX, user:pw@host, a
# space-separated value, ...). So layer 1 removes the command's OWN text: every
# whitespace token, the token with its quotes stripped, and every part of the
# token split on separators, if it is 3+ chars. Each is replaced with
# [REDACTED], longest first, case-insensitive, in a single pass so replacements
# are never re-scanned. Only tripwire's fixed rule wording, which does not come
# from the command, survives. Fragments under 3 chars are kept, so short
# shared words do not shred the wording.
#
# Layer 2, defense in depth for text that is not literally a command token
# (e.g. a tripwire-normalized form):
#   key[:=]value (common credential key names) -> key[:=][REDACTED]
#   any 32+ char base64/base64url/hex run      -> [REDACTED]
# Then the 200-char cap. Redaction runs BEFORE the cap so truncation cannot
# split a key from its value. The emitted additionalContext carries only
# tripwire's message, never `observed`, so it is not redacted.
$script:TwMaxObserved = 200
$script:TwFragmentSplit = '[=:@/\\"''`$;,(){}&|<>]'

function Get-TwCommandFragments([string]$command) {
    $set = [System.Collections.Generic.HashSet[string]]::new([System.StringComparer]::OrdinalIgnoreCase)
    if (-not [string]::IsNullOrEmpty($command)) {
        # Token boundary must be a SUPERSET of tripwire's Python str.isspace(),
        # which also treats U+001C-U+001F as whitespace (.NET \s does not).
        foreach ($tok in [regex]::Split($command, '[\s\x1C-\x1F]+')) {
            if ([string]::IsNullOrEmpty($tok)) { continue }
            $cands = @($tok, ($tok -replace '["''`]', '')) + [regex]::Split($tok, $script:TwFragmentSplit)
            foreach ($c in $cands) { if ($null -ne $c -and $c.Length -ge 3) { [void]$set.Add($c) } }
        }
    }
    return , @($set | Sort-Object -Property Length -Descending)
}

function Protect-TwObserved($text, [string]$command) {
    # $text untyped on purpose: a [string] parameter would turn $null into ''.
    if ($null -eq $text) { return $null }
    # Redact on the UNCUT text first, then clean and cap. Cleaning or truncating
    # first would cut a long command token in `observed` so it no longer matches
    # its own fragment, and its prefix would survive. No pre-cap is needed:
    # `observed` is bounded by the 256 KiB stdout capture cap, and fragments are
    # bounded by the command length.
    $t = [string]$text
    # Layer 1: strip every command-derived fragment.
    $frags = Get-TwCommandFragments $command
    if ($frags.Count -gt 0) {
        $pattern = ($frags | ForEach-Object { [regex]::Escape($_) }) -join '|'
        $opts = [System.Text.RegularExpressions.RegexOptions]'IgnoreCase, CultureInvariant'
        $t = [regex]::Replace($t, $pattern, '[REDACTED]', $opts)
    }
    # Layer 2: credential shapes + long encoded runs.
    $t = [regex]::Replace($t, '(?i)((?:api[_-]?key|token|secret|password|passwd|bearer|auth)\s*[:=]\s*)\S+', '$1[REDACTED]')
    $t = [regex]::Replace($t, '[A-Za-z0-9+/_-]{32,}={0,2}', '[REDACTED]')
    # Then control-char clean, whitespace collapse and the 200-char cap.
    return (Get-TwCleanText $t $script:TwMaxObserved)
}

function New-TwRow([string]$tool, $ruleId, $severity, $observed, [string]$command) {
    $o = $null
    if ($null -ne $observed) { $o = Protect-TwObserved ([string]$observed) $command }
    return [ordered]@{
        ts       = [System.DateTime]::UtcNow.ToString('yyyy-MM-ddTHH:mm:ss.fffZ')
        tool     = $tool
        rule_id  = $ruleId
        severity = $severity
        observed = $o
    }
}

# Resolve literal directory operands only; never evaluate shell command text.
# A missing/ambiguous directory or failed git probe cannot establish a coding root.
function Test-TwCodingRoot([string]$command, [string]$cwd) {
    try {
        if ([string]::IsNullOrWhiteSpace($cwd) -or $cwd -match '^(\\\\|//)') { return $false }
        $base = $cwd
        $rest = $command.TrimStart()
        $word = '(?:"[^"\r\n]*"|''[^''\r\n]*''|[^\s;|&]+)'
        $cd = [regex]::Match($rest, '^cd\s+(?<dir>' + $word + ')\s*(?:&&|;)\s*')
        $dirs = @()
        if ($cd.Success) {
            $dirs += $cd.Groups['dir'].Value
            $rest = $rest.Substring($cd.Length)
        }
        # Require a leading git command: do not attribute another statement's
        # -C operand or a quoted "git" example to the broad-staging finding.
        $gitHead = [regex]::Match($rest, '^git\s+')
        if (-not $gitHead.Success) { return $false }
        $rest = $rest.Substring($gitHead.Length)
        while ($true) {
            $c = [regex]::Match($rest, '^-C\s+(?<dir>' + $word + ')\s+')
            if (-not $c.Success) { break }
            $dirs += $c.Groups['dir'].Value
            $rest = $rest.Substring($c.Length)
        }
        # Current classifier only supplies broad-staging findings for these
        # subcommands. Avoid attributing a later command to an earlier target.
        if ($rest -notmatch '^(?:add|stash)(?:\s|$)') { return $false }
        foreach ($dir in $dirs) {
            if ($dir -match '^["'']') { $dir = $dir.Substring(1, $dir.Length - 2) }
            if ($dir -match '[$`*?\[\]~]' -or $dir -match '^\\\\') { return $false }
            # Git Bash drive spelling, passed to native Windows git.
            if ($dir -match '^/([A-Za-z])/(.*)$') { $dir = $Matches[1] + ':/' + $Matches[2] }
            if ([IO.Path]::IsPathRooted($dir)) { $base = $dir }
            else { $base = Join-Path $base $dir }
        }
        if (-not [IO.Path]::IsPathRooted($base)) { return $false }
        $git = Get-Command 'git' -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
        if ($null -eq $git) { return $false }
        $r = Invoke-TwBounded $git.Source @('--no-optional-locks', '-C', $base, 'rev-parse', '--show-toplevel') 500 -CleanGitEnvironment
        if ($r.TimedOut -or $r.ExitCode -ne 0 -or [string]::IsNullOrWhiteSpace($r.Stdout)) { return $false }
        $top = $r.Stdout.Trim()
        if ($top -match '[\r\n]') { return $false }
        return [IO.File]::Exists((Join-Path $top '.claude/observatory/registry.toml'))
    } catch { return $false }
}

# Default user uv tool bin directory, in uv's own order. The profile folder
# comes from the OS (as uv does), not from the USERPROFILE variable. Only a
# rooted, non-UNC directory is accepted. Returns $null when none applies.
function Get-TwToolBinDir {
    $cands = @()
    if (-not [string]::IsNullOrEmpty($env:UV_TOOL_BIN_DIR)) { $cands += $env:UV_TOOL_BIN_DIR }
    elseif (-not [string]::IsNullOrEmpty($env:XDG_BIN_HOME)) { $cands += $env:XDG_BIN_HOME }
    elseif (-not [string]::IsNullOrEmpty($env:XDG_DATA_HOME)) { $cands += (Join-Path (Split-Path -Parent $env:XDG_DATA_HOME) 'bin') }
    else {
        $prof = [System.Environment]::GetFolderPath([System.Environment+SpecialFolder]::UserProfile)
        if (-not [string]::IsNullOrEmpty($prof)) { $cands += (Join-Path $prof '.local\bin') }
    }
    foreach ($c in $cands) {
        if ([string]::IsNullOrEmpty($c) -or $c -match '^(\\\\|//)') { continue }
        if (-not [System.IO.Path]::IsPathRooted($c)) { continue }
        return $c
    }
    return $null
}

# Resolve how to run tripwire. Returns @{ File; Prefix } (Prefix = argv before
# the `command explain ...` shape) or $null to skip silently. Order: PATH, uv
# tool bin dir, DEV_UTILITIES_ROOT checkout. The open project directory is
# never consulted (it may be hostile).
function Resolve-TwInvocation {
    $exe = Get-Command 'tripwire.exe' -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($null -ne $exe -and [System.IO.Path]::IsPathRooted($exe.Source)) {
        return @{ File = $exe.Source; Prefix = @() }
    }
    $bin = Get-TwToolBinDir
    if ($null -ne $bin) {
        $binExe = Join-Path $bin 'tripwire.exe'
        if ([System.IO.File]::Exists($binExe)) { return @{ File = $binExe; Prefix = @() } }
    }
    $root = $env:DEV_UTILITIES_ROOT
    if ([string]::IsNullOrEmpty($root)) { return $null }
    $project = Join-Path $root 'tripwire'
    if (-not (Test-Path -LiteralPath (Join-Path $project 'pyproject.toml') -PathType Leaf)) { return $null }
    $uv = Get-Command 'uv' -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
    if ($null -eq $uv) { return $null }
    return @{ File = $uv.Source; Prefix = @('run', '--project', $project, 'tripwire') }
}

function Invoke-TwMain([string]$stdinRaw) {
    if ([string]::IsNullOrWhiteSpace($stdinRaw)) { return }
    # A writer using a UTF-8 code page may prepend a BOM; ConvertFrom-Json rejects it.
    $stdinRaw = $stdinRaw.TrimStart([char]0xFEFF, [char]0xFFFE)
    $payload = $null
    try { $payload = $stdinRaw | ConvertFrom-Json } catch { return }
    if ($null -eq $payload) { return }

    $toolName = [string](Get-TwProp $payload 'tool_name')
    if ($toolName -ne 'Bash' -and $toolName -ne 'PowerShell') { return }
    $command  = Get-TwProp (Get-TwProp $payload 'tool_input') 'command'
    if ($null -eq $command -or -not ($command -is [string])) { return }
    if (-not (Test-TwPreScreen $command)) { return }    # hot path: no child process

    $tw = Resolve-TwInvocation
    if ($null -eq $tw) { return }                       # absent tool: silent skip

    $argList = @($tw.Prefix) + @('command', 'explain', '--json', '--', $command)
    $r = Invoke-TwBounded $tw.File $argList $script:TwTimeoutMs

    $findings = $null
    $psInner = $null   # unwrapped PowerShell inner command, when tripwire reports one
    if (-not $r.TimedOut -and $null -ne $r.Stdout) {
        try {
            $doc = $r.Stdout | ConvertFrom-Json
            # Pin schema_version before reading any field (convention point 4).
            if ($null -ne $doc -and [string](Get-TwProp $doc 'schema_version') -eq '1' -and
                $doc.PSObject.Properties['findings']) {
                # @() + null filter: [] -> empty, null -> empty, objects kept.
                $findings = @(@($doc.findings) | Where-Object { $null -ne $_ })
                # Additive schema_version 1 fields (tripwire >= 0.1.2); absent -> $null.
                $inner = Get-TwProp $doc 'inner_command'
                if ((Get-TwProp $doc 'unwrapped') -eq $true -and [string](Get-TwProp $doc 'shell') -eq 'powershell' -and
                    $inner -is [string] -and $inner.Length -gt 0) {
                    $psInner = $inner
                }
            }
        } catch { $findings = $null; $psInner = $null }
    }

    if ($null -eq $findings) {
        # Unreachable / timeout / unparseable: count it, stay silent.
        Add-TwShadowRows @(New-TwRow $toolName $null 'unavailable' $null)
        return
    }

    $kept = @()
    foreach ($fd in $findings) {
        $rid = [string](Get-TwProp $fd 'rule_id')
        # Bash syntax is correct in bash -- but a Codex PowerShell wrapper's inner
        # command is PowerShell, so its TW-SHL-001 is real.
        if ($toolName -eq 'Bash' -and $null -eq $psInner -and $rid -match '^TW-SHL-001(@|$)') { continue }
        $kept += $fd
    }
    # The text the coding-root resolver reads, and the text redacted from rows.
    $judged = $command
    $redactText = $command
    if ($null -ne $psInner) { $judged = $psInner; $redactText = $command + "`n" + $psInner }

    if ($kept.Count -eq 0) {
        # Residue: a pre-screen hit tripwire had nothing to say about.
        Add-TwShadowRows @(New-TwRow $toolName $null 'none' $null)
        return
    }

    $rows = @()
    foreach ($fd in $kept) {
        $rows += (New-TwRow $toolName ([string](Get-TwProp $fd 'rule_id')) ([string](Get-TwProp $fd 'severity')) (Get-TwProp $fd 'observed') $redactText)
    }
    Add-TwShadowRows $rows

    $notes = @($kept | Where-Object { [string](Get-TwProp $_ 'severity') -eq 'fail' })
    if ($notes.Count -eq 0) {
        $broad = @($kept | Where-Object {
            [string](Get-TwProp $_ 'severity') -eq 'warn' -and
            [string](Get-TwProp $_ 'rule_id') -match '^TW-GIT-001(@|$)'
        })
        if ($broad.Count -gt 0 -and (Test-TwCodingRoot $judged ([string](Get-TwProp $payload 'cwd')))) {
            $notes = $broad
        }
    }
    foreach ($fd in $notes) {
        $severity = [string](Get-TwProp $fd 'severity')
        $rid = Get-TwCleanText ([string](Get-TwProp $fd 'rule_id')) 64
        $rid = $rid -replace '@v\d+$', ''
        $msg = Get-TwCleanText ([string](Get-TwProp $fd 'message')) $script:TwMaxMessage
        $line = [ordered]@{
            hookSpecificOutput = [ordered]@{
                hookEventName     = 'PreToolUse'
                additionalContext = ('tripwire: [' + $severity + '] ' + $rid + ' ' + $msg)
            }
        }
        [System.Console]::Out.Write((ConvertTo-TwAsciiJson $line))
        return                                          # at most ONE line
    }
}

# Dot-sourcing (tests) loads the functions only; running via -File executes.
if ($MyInvocation.InvocationName -ne '.') {
    try {
        # Stdin was already read (UTF-8, BOM-aware) by the fast path at the top.
        Invoke-TwMain $script:TwStdinRaw
    } catch {
        # Observer-only: never surface errors, never block the tool call.
    }
    exit 0
}
