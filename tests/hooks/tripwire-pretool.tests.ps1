# Behavioural suite for the packaged Claude Code hook hooks/claude/tripwire-pretool.ps1.
#
# Run (Windows PowerShell 5.1):
#   powershell -NoProfile -ExecutionPolicy Bypass -File tests/hooks/tripwire-pretool.tests.ps1
#     [-HookPath <hook under test>] [-TripwireBin <dir holding the real tripwire.exe>]
# Exit 0 = ALL PASS, exit 1 = at least one FAIL. tests/test_hook_powershell.py
# runs it from pytest (and runs it against the red-on-garbage anchor fixture).
#
# PRODUCTION ENTRY POINT. The hook under test is first copied the way an
# installer copies it (into <home>\.claude\hooks\companions\, a path with a
# space), then every behavioural case runs the exact command line the installer
# registers for PreToolUse:
#   powershell.exe -NoProfile -NonInteractive -File "<absolute hook path>"
# with the hook payload JSON written to stdin.
#
# ISOLATION. Every child gets its own temp LOCALAPPDATA (the real one is never
# written), a controlled PATH (System32, PowerShell, git, uv, and a tripwire
# directory only where a case wants one), UV_TOOL_BIN_DIR pointing at an empty
# temp dir unless a case overrides it, and no DEV_UTILITIES_ROOT /
# CLAUDE_PROJECT_DIR / XDG_* / VIRTUAL_ENV unless a case sets them.
#
# TRIPWIRE SOURCES. Real-tripwire cases use the real tripwire.exe from
# -TripwireBin (default: this repository's .venv\Scripts) on PATH, and this
# repository through a DEV_UTILITIES_ROOT junction for the uv run tier. If the
# real CLI is missing the real-tripwire cases FAIL loudly -- a skipped gate
# proves nothing. Deterministic finding shapes come from a fake tripwire.exe
# compiled here (it prints <its dir>\out.json and logs its argv).
#
# CODEX HOST. The same script is the Codex hook (`tripwire hook path --host
# codex`). Codex cases send tool_name "Bash" with the PowerShell -Command wrapper
# line Codex hands hooks, and also run the Codex registration form
#   powershell.exe -NoProfile -NonInteractive -File <path without a blank>
#
# Red anchors: a bogus root, a fake tripwire project (spawn evidence), a hostile
# project whose build backend leaves a marker (reached only via the trusted
# DEV_UTILITIES_ROOT tier; the open project is never run), a spy uv.exe, the
# Bash-vs-PowerShell TW-SHL-001 split, and tests/hooks/fixtures/garbage-hook.ps1
# (run the whole suite with -HookPath on it: it must FAIL).
#
# ASCII-only on purpose (PS 5.1 reads a no-BOM .ps1 as cp1252).
param(
    [string]$HookPath = '',
    [string]$TripwireBin = ''
)
$ErrorActionPreference = 'Stop'
$fail = 0; $total = 0
function Check([string]$name, [bool]$cond, [string]$detail = '') {
    $script:total++
    if ($cond) { Write-Host "PASS  $name" }
    else {
        $script:fail++
        if ($detail) { Write-Host "FAIL  $name -- $detail" } else { Write-Host "FAIL  $name" }
    }
}

# --- Layout (from this script's location, not cwd) -------------------------------
$TestsDir   = Split-Path -Parent $PSScriptRoot
$RepoRoot   = Split-Path -Parent $TestsDir
$SourceHook = Join-Path $RepoRoot 'hooks\claude\tripwire-pretool.ps1'
if (-not $HookPath) { $HookPath = $SourceHook }
$HookPath = (Resolve-Path -LiteralPath $HookPath).Path
if (-not $TripwireBin) { $TripwireBin = Join-Path $RepoRoot '.venv\Scripts' }
$TempRoot = Join-Path ([System.IO.Path]::GetTempPath()) ('tw-pretool-tests-' + [guid]::NewGuid().ToString('N'))
[void][System.IO.Directory]::CreateDirectory($TempRoot)
$script:Junctions = @()
# This process's own virtualenv must not leak into uv run children.
Remove-Item Env:VIRTUAL_ENV -ErrorAction SilentlyContinue
Write-Host "#     hook under test: $HookPath"

function New-TempDir([string]$tag) {
    $d = Join-Path $script:TempRoot ($tag + '-' + [guid]::NewGuid().ToString('N').Substring(0, 8))
    [void][System.IO.Directory]::CreateDirectory($d)
    return $d
}

# --- Installed copy + the registered command line ---------------------------------
$HomeDir = New-TempDir 'home dir'
$CompanionsDir = Join-Path $HomeDir '.claude\hooks\companions'
[void][System.IO.Directory]::CreateDirectory($CompanionsDir)
$InstalledHook = Join-Path $CompanionsDir 'tripwire-pretool.ps1'
[System.IO.File]::Copy($HookPath, $InstalledHook, $true)
$Registered = 'powershell.exe -NoProfile -NonInteractive -File "' + $InstalledHook + '"'
Write-Host "#     registered command: $Registered"
$RegFile = $null; $RegArgs = $null
if ($Registered -match '^(\S+)\s+(.+)$') { $RegFile = $Matches[1]; $RegArgs = $Matches[2] }
Check 'install: copied hook is byte-identical to the hook under test' (
    ([Convert]::ToBase64String([IO.File]::ReadAllBytes($InstalledHook))) -ceq ([Convert]::ToBase64String([IO.File]::ReadAllBytes($HookPath))))
Check 'install: installed path is absolute, ends in .ps1, has no double quote' (
    [IO.Path]::IsPathRooted($InstalledHook) -and $InstalledHook.EndsWith('.ps1') -and -not $InstalledHook.Contains('"'))

# --- Static checks -----------------------------------------------------------------
$garbageFixture = Join-Path $PSScriptRoot 'fixtures\garbage-hook.ps1'
foreach ($f in @($HookPath, $MyInvocation.MyCommand.Path, $garbageFixture)) {
    if (-not (Test-Path -LiteralPath $f)) { Check "static: $f exists" $false; continue }
    $bytes = [System.IO.File]::ReadAllBytes($f)
    $nonAscii = @($bytes | Where-Object { $_ -gt 127 }).Count
    Check ("static: $(Split-Path -Leaf $f) is pure ASCII (byte check)") ($nonAscii -eq 0) "$nonAscii non-ASCII bytes"
}
$parseErrors = $null
[void][System.Management.Automation.Language.Parser]::ParseFile($HookPath, [ref]$null, [ref]$parseErrors)
Check 'static: hook parses with zero errors' (@($parseErrors).Count -eq 0) "$(@($parseErrors).Count) parse errors"

# --- Controlled child environment --------------------------------------------------
$Sys32 = Join-Path $env:SystemRoot 'System32'
$gitCmd = Get-Command 'git.exe' -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
$uvCmd  = Get-Command 'uv.exe' -CommandType Application -ErrorAction SilentlyContinue | Select-Object -First 1
Check 'env: git.exe found (coding-root resolution needs it)' ($null -ne $gitCmd)
Check 'env: uv.exe found (uv run tier needs it)' ($null -ne $uvCmd)
$pathDirs = @($Sys32, $PSHOME)
if ($null -ne $gitCmd) {
    $gitDir = Split-Path -Parent $gitCmd.Source
    Check 'env: git directory holds no tripwire.exe' (-not (Test-Path -LiteralPath (Join-Path $gitDir 'tripwire.exe')))
    $pathDirs += $gitDir
}
$UvExe = $null
if ($null -ne $uvCmd) {
    $UvExe = $uvCmd.Source
    $uvDir = Split-Path -Parent $UvExe
    if (Test-Path -LiteralPath (Join-Path $uvDir 'tripwire.exe')) {
        # uv lives in the user tool bin dir next to an installed tripwire: copy
        # uv alone so PATH never offers the installed tripwire to a case.
        $uvDir = New-TempDir 'uv-only'
        [System.IO.File]::Copy($UvExe, (Join-Path $uvDir 'uv.exe'))
        $UvExe = Join-Path $uvDir 'uv.exe'
    }
    $pathDirs += $uvDir
}
$BasePath = $pathDirs -join ';'
$EmptyBin = New-TempDir 'empty-bin'

$script:AllOutputs = New-Object System.Collections.Generic.List[string]
$script:AllLa = New-Object System.Collections.Generic.List[string]

# Runs the registered command line with $stdin on stdin. $envOverrides: name ->
# value ($null removes the variable). LOCALAPPDATA is always a temp dir.
function Invoke-Wired([string]$stdin, [hashtable]$envOverrides = @{}, [string]$fileName = $script:RegFile,
                      [string]$argsLine = $script:RegArgs, [switch]$prefixBom) {
    $psi = New-Object System.Diagnostics.ProcessStartInfo
    $psi.FileName = $fileName
    $psi.Arguments = $argsLine
    $psi.UseShellExecute = $false
    $psi.CreateNoWindow = $true
    $psi.RedirectStandardInput = $true
    $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true
    $psi.WorkingDirectory = $script:TempRoot
    foreach ($k in @('DEV_UTILITIES_ROOT', 'CLAUDE_PROJECT_DIR', 'XDG_BIN_HOME', 'XDG_DATA_HOME', 'VIRTUAL_ENV', 'UV_TOOL_BIN_DIR')) {
        if ($psi.EnvironmentVariables.ContainsKey($k)) { $psi.EnvironmentVariables.Remove($k) }
    }
    $psi.EnvironmentVariables['PATH'] = $script:BasePath
    $psi.EnvironmentVariables['UV_TOOL_BIN_DIR'] = $script:EmptyBin
    $la = New-TempDir 'la'
    $psi.EnvironmentVariables['LOCALAPPDATA'] = $la
    foreach ($k in $envOverrides.Keys) {
        if ($psi.EnvironmentVariables.ContainsKey($k)) { $psi.EnvironmentVariables.Remove($k) }
        if ($null -ne $envOverrides[$k]) { $psi.EnvironmentVariables[$k] = [string]$envOverrides[$k] }
    }
    $la = $psi.EnvironmentVariables['LOCALAPPDATA']
    $script:AllLa.Add([string]$la)
    $sw = [System.Diagnostics.Stopwatch]::StartNew()
    $p = [System.Diagnostics.Process]::Start($psi)
    $outTask = $p.StandardOutput.ReadToEndAsync()
    $errTask = $p.StandardError.ReadToEndAsync()
    # Raw UTF-8 bytes, no BOM -- what Claude Code writes.
    # A child that exits without reading stdin ends the pipe; that is the
    # child's behaviour under test, not a harness error.
    try {
        if ($null -ne $stdin) {
            $bytes = (New-Object System.Text.UTF8Encoding($false)).GetBytes($stdin)
            if ($prefixBom) { $bytes = [byte[]](0xEF, 0xBB, 0xBF) + $bytes }
            $p.StandardInput.BaseStream.Write($bytes, 0, $bytes.Length)
            $p.StandardInput.BaseStream.Flush()
        }
        $p.StandardInput.Close()
    } catch { }
    $exited = $p.WaitForExit(15000)
    $sw.Stop()
    if (-not $exited) { try { $p.Kill() } catch { } }
    [void]$outTask.Wait(2000); [void]$errTask.Wait(2000)
    $res = [PSCustomObject]@{
        Out  = [string]$outTask.Result
        Err  = [string]$errTask.Result
        Code = $(if ($exited) { $p.ExitCode } else { -999 })
        Ms   = $sw.ElapsedMilliseconds
        La   = [string]$la
    }
    if ($fileName -eq $script:RegFile -and $argsLine -eq $script:RegArgs) {
        $script:AllOutputs.Add($res.Out + "`n" + $res.Err)
    }
    return $res
}

# Realistic PreToolUse payload shape. The keys matter for the fast path:
# "permission_mode" contains "rm", and transcript_path/cwd carry escaped
# backslashes, so a whole-payload pre-screen would always hit.
function New-Payload([string]$tool, [string]$command, [string]$cwd = 'C:\work\project') {
    return (ConvertTo-Json -Compress -InputObject ([ordered]@{
        session_id = 'tw-test'
        transcript_path = 'C:\Users\example\.claude\projects\example-project\tw-test.jsonl'
        cwd = $cwd
        permission_mode = 'default'
        hook_event_name = 'PreToolUse'; tool_name = $tool
        tool_input = [ordered]@{ command = $command; description = 'test fixture' }
    }))
}

# Quote one argument by the C-runtime rules (what the Codex CLI's spawner emits):
# wrap in quotes, double backslashes before a quote, escape embedded quotes.
function ConvertTo-CrtArg([string]$arg) {
    $sb = New-Object System.Text.StringBuilder
    [void]$sb.Append('"')
    $bs = 0
    foreach ($ch in $arg.ToCharArray()) {
        if ($ch -eq [char]'\') { $bs++; continue }
        if ($ch -eq [char]'"') { [void]$sb.Append('\' * (2 * $bs + 1)); [void]$sb.Append('"') }
        else { if ($bs -gt 0) { [void]$sb.Append('\' * $bs) }; [void]$sb.Append($ch) }
        $bs = 0
    }
    if ($bs -gt 0) { [void]$sb.Append('\' * (2 * $bs)) }
    [void]$sb.Append('"')
    return $sb.ToString()
}

# Codex CLI PreToolUse payload: tool_name "Bash" and the PowerShell wrapper line.
function New-CodexPayload([string]$inner, [string]$cwd = 'C:\work\project') {
    $line = '"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe" -Command ' + (ConvertTo-CrtArg $inner)
    return (ConvertTo-Json -Compress -InputObject ([ordered]@{
        session_id = 'tw-codex-test'; turn_id = 'turn-1'; tool_use_id = 'call-1'
        transcript_path = $null; cwd = $cwd; model = 'fixture-model'
        permission_mode = 'default'; hook_event_name = 'PreToolUse'; tool_name = 'Bash'
        tool_input = [ordered]@{ command = $line }
    }))
}

function Get-ShadowPath([string]$la) { return (Join-Path $la 'tripwire\hook-shadow.jsonl') }
function Get-ShadowRows([string]$la) {
    $p = Get-ShadowPath $la
    if (-not (Test-Path -LiteralPath $p)) { return @() }
    return @([System.IO.File]::ReadAllLines($p) | Where-Object { $_.Trim() } | ForEach-Object { $_ | ConvertFrom-Json })
}
function Get-ShadowText([string]$la) {
    $p = Get-ShadowPath $la
    if (-not (Test-Path -LiteralPath $p)) { return '' }
    return [System.IO.File]::ReadAllText($p)
}
function Get-OutLines($r) { return @($r.Out -split "`r?`n" | Where-Object { $_.Trim() }) }

# Assert exactly one note line '<prefix>' whose JSON is advisory only.
function Check-NoteLine([string]$label, $r, [string]$severity, [string]$rule, [switch]$Full) {
    $lines = @(Get-OutLines $r)
    Check "$label -> exactly one output line" ($lines.Count -eq 1) "got $($lines.Count): $($r.Out) err=$($r.Err)"
    $ctx = $null; $evt = $null; $obj = $null; $hso = $null
    try { $obj = $lines[0] | ConvertFrom-Json; $hso = $obj.hookSpecificOutput; $ctx = $hso.additionalContext; $evt = $hso.hookEventName } catch { }
    Check "$label -> additionalContext 'tripwire: [$severity] $rule ...'" ($ctx -and $ctx.StartsWith("tripwire: [$severity] $rule ")) "ctx=$ctx"
    if (-not $Full) { return }
    Check "$label -> exit 0" ($r.Code -eq 0) "exit $($r.Code)"
    Check "$label -> hookEventName PreToolUse" ($evt -ceq 'PreToolUse')
    Check "$label -> advisory JSON only (hookSpecificOutput{additionalContext,hookEventName})" (
        $null -ne $obj -and (@($obj.PSObject.Properties.Name) -join ',') -ceq 'hookSpecificOutput' -and
        (@($hso.PSObject.Properties.Name | Sort-Object) -join ',') -ceq 'additionalContext,hookEventName') "out=$($r.Out)"
    $msgLen = 0
    if ($ctx) { $msgLen = ($ctx -replace '^tripwire: \[\w+\] \S+ ', '').Length }
    Check "$label -> message <= 300 chars" ($msgLen -le 300) "len=$msgLen"
    Check "$label -> no permissionDecision" ($r.Out -notmatch 'permissionDecision')
    Check "$label -> output is pure ASCII" ($r.Out -notmatch '[^\x00-\x7F]')
}
function Check-FailLine([string]$label, $r, [string]$rule, [switch]$Full) {
    Check-NoteLine $label $r 'fail' $rule -Full:$Full
}
function Check-Silent([string]$label, $r) {
    Check "$label -> exit 0, no output" ($r.Code -eq 0 -and -not $r.Out.Trim()) "exit=$($r.Code) out=$($r.Out) err=$($r.Err)"
}

# --- Fake tripwire.exe -------------------------------------------------------------
# Prints <its own dir>\out.json (when present) and appends its argv, joined by
# U+001F, to <its own dir>\calls.log. A real .exe, because the hook accepts only
# tripwire.exe from PATH / the tool bin directory.
$FakeSrc = @'
using System;
using System.IO;
public static class TwFakeTripwireMain {
    public static int Main(string[] args) {
        string dir = AppDomain.CurrentDomain.BaseDirectory;
        File.AppendAllText(Path.Combine(dir, "calls.log"), string.Join("\u001f", args) + "\n");
        string outPath = Path.Combine(dir, "out.json");
        if (File.Exists(outPath)) { Console.Out.Write(File.ReadAllText(outPath)); Console.Out.Flush(); }
        return 0;
    }
}
'@
$FakeExeMaster = Join-Path (New-TempDir 'fake-build') 'tripwire.exe'
try {
    Add-Type -TypeDefinition $FakeSrc -Language CSharp -OutputAssembly $FakeExeMaster -OutputType ConsoleApplication
} catch { }
Check 'fixture: fake tripwire.exe compiled' (Test-Path -LiteralPath $FakeExeMaster)

# A directory holding a fake tripwire.exe that will print the given findings.
function New-FakeBin([object[]]$findings, [string]$tag = 'fakebin') {
    $d = New-TempDir $tag
    [System.IO.File]::Copy($script:FakeExeMaster, (Join-Path $d 'tripwire.exe'))
    Set-FakeFindings $d $findings
    return $d
}
function Set-FakeFindings([string]$dir, [object[]]$findings) {
    $doc = [ordered]@{ schema_version = 1; target = 'fixture'; findings = @($findings) }
    [System.IO.File]::WriteAllText((Join-Path $dir 'out.json'), (ConvertTo-Json -InputObject $doc -Depth 5 -Compress))
    $log = Join-Path $dir 'calls.log'
    if (Test-Path -LiteralPath $log) { [System.IO.File]::Delete($log) }
}
function New-Finding([string]$rule, [string]$sev, [string]$msg = 'fixture message', [string]$obs = 'fixture observed') {
    return [ordered]@{ rule_id = $rule; severity = $sev; message = $msg; observed = $obs; provenance = 'fixture' }
}
function Get-FakeCalls([string]$dir) {
    $log = Join-Path $dir 'calls.log'
    if (-not (Test-Path -LiteralPath $log)) { return @() }
    return @([System.IO.File]::ReadAllLines($log) | Where-Object { $_ })
}

# No-spawn proof for the uv run tier: a FAKE tripwire project. If uv is ever
# spawned against it, uv creates .venv / uv.lock there (spawn evidence).
function New-FakeRoot {
    $root = New-TempDir 'fake'
    $proj = Join-Path $root 'tripwire'
    [void][System.IO.Directory]::CreateDirectory($proj)
    [System.IO.File]::WriteAllText((Join-Path $proj 'pyproject.toml'),
        "[project]`nname = `"fake-tripwire`"`nversion = `"0.0.0`"`nrequires-python = `">=3.8`"`ndependencies = []`n")
    return $root
}
function Test-SpawnEvidence([string]$root) {
    $proj = Join-Path $root 'tripwire'
    return ((Test-Path -LiteralPath (Join-Path $proj '.venv')) -or (Test-Path -LiteralPath (Join-Path $proj 'uv.lock')))
}

# A HOSTILE project: <root>\tripwire\pyproject.toml names an in-tree build
# backend that writes <root>\tripwire\HOSTILE-CODE-RAN as soon as it is imported
# (any uv run --project against it imports it), then refuses to build.
$HostilePyproject = @'
[project]
name = "hostile-tripwire"
version = "0.0.0"
requires-python = ">=3.8"
dependencies = []

[project.scripts]
tripwire = "hostile_backend:main"

[build-system]
requires = []
build-backend = "hostile_backend"
backend-path = ["."]
'@
$HostileBackend = @'
import os
open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "HOSTILE-CODE-RAN"), "w").close()
raise SystemExit("hostile fixture: refusing to build")
'@
function New-HostileRoot {
    $root = New-TempDir 'hostile project'
    $proj = Join-Path $root 'tripwire'
    [void][System.IO.Directory]::CreateDirectory($proj)
    $enc = New-Object System.Text.UTF8Encoding($false)
    [System.IO.File]::WriteAllText((Join-Path $proj 'pyproject.toml'), ($script:HostilePyproject -replace "`r`n", "`n"), $enc)
    [System.IO.File]::WriteAllText((Join-Path $proj 'hostile_backend.py'), ($script:HostileBackend -replace "`r`n", "`n"), $enc)
    return $root
}
function Test-HostileRan([string]$root) {
    return (Test-Path -LiteralPath (Join-Path $root 'tripwire\HOSTILE-CODE-RAN'))
}

# --- Git fixture repos (coding root = git toplevel with the registry marker) -------
$markerRepo = New-TempDir 'coding root'
$plainRepo = New-TempDir 'ordinary repo'
foreach ($repo in @($markerRepo, $plainRepo)) {
    & git -C $repo init --quiet
    if ($LASTEXITCODE -ne 0) { throw "Could not create fixture repo: $repo" }
}
$markerDir = Join-Path $markerRepo '.claude/observatory'
[void][IO.Directory]::CreateDirectory($markerDir)
[IO.File]::WriteAllText((Join-Path $markerDir 'registry.toml'), '', [Text.UTF8Encoding]::new($false))
$subDir = Join-Path $markerRepo 'subdir'
[void][IO.Directory]::CreateDirectory($subDir)
$nonGit = New-TempDir 'not git'
$literalDollarDir = Join-Path $markerRepo '$TARGET'
[void][IO.Directory]::CreateDirectory($literalDollarDir)

try {
    # Dot-source the hook: its main block is guarded, so this loads functions only
    # for the direct/unit sections below.
    . $HookPath
    $hasFns = $true
    foreach ($fn in @('Invoke-TwBounded', 'Protect-TwObserved', 'Test-TwCodingRoot', 'Get-TwToolBinDir', 'Resolve-TwInvocation')) {
        $has = $null -ne (Get-Command $fn -CommandType Function -ErrorAction SilentlyContinue)
        Check "static: hook defines $fn (dot-source loads functions only)" $has
        $hasFns = $hasFns -and $has
    }

    # ===== Real tripwire cases (PATH tier, real CLI) ================================
    $RealExe = Join-Path $TripwireBin 'tripwire.exe'
    $realOk = Test-Path -LiteralPath $RealExe -PathType Leaf
    Check "real tripwire.exe found at $RealExe" $realOk 'real-tripwire assertions cannot run'
    if ($realOk) {
        $ver = (& $RealExe --version) -join ''
        Check 'real tripwire --version exits 0 and prints "tripwire <version>"' ($LASTEXITCODE -eq 0 -and $ver -match '^tripwire \d+\.\d+\.\d+') "got '$ver'"
        $RealEnv = @{ PATH = ($TripwireBin + ';' + $BasePath) }

        # cat .env -> TW-SEC-001 fail line + shadow row, under the 3.5 s budget.
        $r = Invoke-Wired (New-Payload 'PowerShell' 'cat .env') $RealEnv
        Check-FailLine 'cat .env' $r 'TW-SEC-001' -Full
        Check "cat .env -> completes in < 3500 ms (fail path, PATH tier)" ($r.Ms -lt 3500) "$($r.Ms) ms"
        $FailPathMs = $r.Ms
        $rows = @(Get-ShadowRows $r.La)
        Check 'cat .env -> one shadow row at %LOCALAPPDATA%\tripwire\hook-shadow.jsonl (TW-SEC-001, fail)' `
            ($rows.Count -eq 1 -and ([string]$rows[0].rule_id) -match '^TW-SEC-001' -and $rows[0].severity -eq 'fail') "rows=$(Get-ShadowText $r.La)"
        Check 'cat .env -> shadow row has exactly {ts, tool, rule_id, severity, observed}' `
            ($rows.Count -eq 1 -and (($rows[0].PSObject.Properties.Name | Sort-Object) -join ',') -eq 'observed,rule_id,severity,tool,ts')
        Check 'cat .env -> shadow row does not contain the full command' ((Get-ShadowText $r.La) -notmatch [regex]::Escape('cat .env'))

        # cat .env.example -> no output, one residue row.
        $r = Invoke-Wired (New-Payload 'PowerShell' 'cat .env.example') $RealEnv
        Check-Silent 'cat .env.example' $r
        $rows = @(Get-ShadowRows $r.La)
        Check 'cat .env.example -> one residue row (rule_id null, severity none)' `
            ($rows.Count -eq 1 -and $null -eq $rows[0].rule_id -and $rows[0].severity -eq 'none') "rows=$(Get-ShadowText $r.La)"
        Check 'cat .env.example -> shadow row does not contain the full command' ((Get-ShadowText $r.La) -notmatch [regex]::Escape('cat .env.example'))

        # git push --force origin main -> TW-GIT-003.
        $r = Invoke-Wired (New-Payload 'Bash' 'git push --force origin main') $RealEnv
        Check-FailLine 'git push --force origin main' $r 'TW-GIT-003'
        Check 'git push --force -> shadow row does not contain the full command' `
            ((Get-ShadowText $r.La) -notmatch [regex]::Escape('git push --force origin main'))

        # Embedded double quotes + backslashes reach tripwire intact.
        $r = Invoke-Wired (New-Payload 'PowerShell' 'cat "C:\x y\.env"') $RealEnv
        Check-FailLine 'cat "C:\x y\.env" (quoted arg)' $r 'TW-SEC-001'
        function Invoke-TripwireDirect([string]$cmd) {
            if (-not $script:hasFns) { return $null }
            $res = Invoke-TwBounded $script:RealExe @('command', 'explain', '--json', '--', $cmd) 10000
            try { return ($res.Stdout | ConvertFrom-Json) } catch { return $null }
        }
        $doc = Invoke-TripwireDirect 'cat "C:\x y\.env"'
        Check 'cat "C:\x y\.env" -> tripwire target equals the command byte-for-byte (argv quoting intact)' `
            ($null -ne $doc -and $doc.target -ceq 'cat "C:\x y\.env"') "target=$($doc.target)"

        # ===== Redaction invariant: a shadow row never contains command text =====
        # Precondition per row: tripwire really echoes the secret into `observed`
        # (else the check is vacuous).
        $redactCases = @(
            @{ Cmd = 'git push --pwd=hunter2$X origin main';               Secret = 'hunter2';         Wording = 'shell substitution' },
            @{ Cmd = 'git push --authorization=Bearer$X origin main';      Secret = 'Bearer';          Wording = 'shell substitution' },
            @{ Cmd = 'git reset --authorization=Bearer abc123tok$X';       Secret = 'abc123tok';       Wording = 'shell substitution' },
            @{ Cmd = 'git push -pSuperS3cretPw$X origin main';             Secret = 'SuperS3cretPw';   Wording = 'shell substitution' },
            @{ Cmd = 'git checkout https://user:hunter2pass@host/$X';      Secret = 'hunter2pass';     Wording = 'shell substitution' },
            @{ Cmd = 'git push --password="abc tailpart$X" origin main';   Secret = 'tailpart';        Wording = 'shell substitution' },
            @{ Cmd = 'git reset --password hunter2$X';                     Secret = 'hunter2';         Wording = 'shell substitution' },
            @{ Cmd = 'git reset Bearer abc123$X';                          Secret = 'abc123';          Wording = 'shell substitution' },
            @{ Cmd = 'git push --zz=s3cr$X origin main';                   Secret = 's3cr';            Wording = 'shell substitution' },
            # U+001C is whitespace to tripwire (Python isspace) but not to .NET \s.
            @{ Cmd = ('git reset' + [char]0x1C + 'mysecretvalue$X');       Secret = 'mysecretvalue';   Wording = 'shell substitution' },
            # One token longer than 4096 chars: redaction must run before any cut.
            @{ Cmd = ('git reset ' + ('Pw!9x' * 1000) + '$X');             Secret = 'Pw!9x';           Wording = 'shell substitution' },
            @{ Cmd = 'taskkill /FI hunter2sel$X';                          Secret = 'hunter2sel';      Wording = 'shell substitution' },
            @{ Cmd = 'cat C:\secrets\token=abc123SECRETxyz';               Secret = 'abc123SECRETxyz'; Wording = 'bearing file' },
            @{ Cmd = 'cat secret-0123456789abcdef0123456789abcdef0123.json'; Secret = '0123456789abcdef'; Wording = 'secrets-bearing file' }
        )
        foreach ($rc in $redactCases) {
            $sec = [regex]::Escape($rc.Secret)
            $doc = Invoke-TripwireDirect $rc.Cmd
            $rawObs = (@($doc.findings) | ForEach-Object { [string]$_.observed }) -join ' || '
            $r = Invoke-Wired (New-Payload 'PowerShell' $rc.Cmd) $RealEnv
            $txt = Get-ShadowText $r.La; $rows = @(Get-ShadowRows $r.La)
            $ok = ($rawObs -match $sec) -and ($rows.Count -ge 1) -and ($r.Code -eq 0) -and
                  ($txt -notmatch $sec) -and ($r.Out -notmatch $sec)
            foreach ($row in $rows) {
                $ok = $ok -and -not [string]::IsNullOrEmpty([string]$row.rule_id) -and
                      -not [string]::IsNullOrEmpty([string]$row.severity) -and
                      ([string]$row.observed).Contains($rc.Wording) -and ([string]$row.observed).Contains('[REDACTED]') -and
                      ([string]$row.observed).Length -le 200
            }
            $label = $rc.Cmd -replace '[\x00-\x1F]', '<ctl>'
            if ($label.Length -gt 80) { $label = $label.Substring(0, 60) + "...(len $($rc.Cmd.Length))" }
            Check ("redact-table: {0} -> tripwire echoes '{1}'; row has rule_id+severity+wording '{2}', secret absent from row and output" -f `
                $label, $rc.Secret, $rc.Wording) $ok "raw=$rawObs rows=$txt out=$($r.Out)"
        }

        # Fast-path escape hatch: a \u-escaped letter must not hide a hit.
        $escaped = (New-Payload 'PowerShell' 'XXCMDXX').Replace('XXCMDXX', 'c\u0061t .env')
        $r = Invoke-Wired $escaped $RealEnv
        Check-FailLine 'JSON \u-escaped command (c\u0061t .env)' $r 'TW-SEC-001'

        # Bash `echo a && echo b` -> pre-screen miss: no output, no row.
        $r = Invoke-Wired (New-Payload 'Bash' 'echo a && echo b') $RealEnv
        Check-Silent 'Bash echo a && echo b' $r
        Check 'Bash echo a && echo b -> no shadow row' (-not (Test-Path -LiteralPath (Get-ShadowPath $r.La)))

        # TW-SHL-001 drop: same pre-screen-hit command, Bash vs PowerShell.
        $r = Invoke-Wired (New-Payload 'Bash' 'git status && git diff') $RealEnv
        $rows = @(Get-ShadowRows $r.La)
        Check-Silent 'Bash git status && git diff' $r
        Check 'Bash git status && git diff -> TW-SHL-001 dropped (residue row only)' `
            ($rows.Count -eq 1 -and $null -eq $rows[0].rule_id -and $rows[0].severity -eq 'none') "rows=$(Get-ShadowText $r.La)"
        $r = Invoke-Wired (New-Payload 'PowerShell' 'git status && git diff') $RealEnv
        $rows = @(Get-ShadowRows $r.La)
        Check 'red-anchor: PowerShell git status && git diff -> TW-SHL-001 warn row kept' `
            ($rows.Count -eq 1 -and ([string]$rows[0].rule_id) -match '^TW-SHL-001' -and $rows[0].severity -eq 'warn') "rows=$(Get-ShadowText $r.La)"
        Check-Silent 'PowerShell git status && git diff (warn)' $r
        # The same non-GIT-001 warn at a coding root stays silent too (CC-D12).
        $r = Invoke-Wired (New-Payload 'PowerShell' 'git status && git diff' $markerRepo) $RealEnv
        $rows = @(Get-ShadowRows $r.La)
        Check 'CC-D12 real: TW-SHL-001 warn at a coding root -> warn row kept' `
            ($rows.Count -eq 1 -and ([string]$rows[0].rule_id) -match '^TW-SHL-001' -and $rows[0].severity -eq 'warn') "rows=$(Get-ShadowText $r.La)"
        Check-Silent 'CC-D12 real: TW-SHL-001 warn at a coding root' $r

        # ===== Codex host: every shell call is tool_name "Bash" + a PowerShell wrapper =====
        # Codex CLI (0.167+) sends the PreToolUse payload with extra keys and the
        # command line it spawns: the quoted powershell.exe path, -Command, and
        # the real PowerShell command quoted by the C-runtime rules.
        $r = Invoke-Wired (New-CodexPayload 'git status && git diff') $RealEnv
        $rows = @(Get-ShadowRows $r.La)
        Check 'codex: wrapped git status && git diff -> TW-SHL-001 warn row KEPT (inner command is PowerShell)' `
            ($rows.Count -eq 1 -and ([string]$rows[0].rule_id) -match '^TW-SHL-001' -and $rows[0].severity -eq 'warn') "rows=$(Get-ShadowText $r.La)"
        Check-Silent 'codex: wrapped git status && git diff (warn stays silent)' $r
        $r = Invoke-Wired (New-CodexPayload 'git commit -m "a && b"') $RealEnv
        $rows = @(Get-ShadowRows $r.La)
        Check 'codex: wrapped git commit -m "a && b" -> quoted && is no mismatch (residue row only)' `
            ($rows.Count -eq 1 -and $null -eq $rows[0].rule_id -and $rows[0].severity -eq 'none') "rows=$(Get-ShadowText $r.La)"
        $r = Invoke-Wired (New-CodexPayload 'Get-Content C:\proj\.env') $RealEnv
        Check-FailLine 'codex: wrapped Get-Content C:\proj\.env' $r 'TW-SEC-001' -Full
        $r = Invoke-Wired (New-CodexPayload 'git push --force origin main') $RealEnv
        Check-FailLine 'codex: wrapped git push --force origin main' $r 'TW-GIT-003' -Full
        Check 'codex: wrapped git push --force -> shadow row holds neither the wrapper nor the inner command' (
            (Get-ShadowText $r.La) -notmatch [regex]::Escape('git push --force origin main') -and
            (Get-ShadowText $r.La) -notmatch [regex]::Escape('powershell.exe')) "rows=$(Get-ShadowText $r.La)"
        $r = Invoke-Wired (New-CodexPayload 'git add -A' $markerRepo) $RealEnv
        Check-NoteLine 'codex: wrapped git add -A at a coding root (resolver reads the inner command)' $r 'warn' 'TW-GIT-001' -Full
        $r = Invoke-Wired (New-CodexPayload 'git add -A' $plainRepo) $RealEnv
        Check-Silent 'codex: wrapped git add -A in an ordinary repo' $r
        # A non-shell tool's "command" (Codex apply_patch carries patch text) is never evaluated.
        $r = Invoke-Wired (New-Payload 'apply_patch' 'cat .env') $RealEnv
        Check-Silent 'codex: tool_name apply_patch -> not evaluated' $r
        Check 'codex: tool_name apply_patch -> no shadow row' (-not (Test-Path -LiteralPath (Get-ShadowPath $r.La)))
        # The Codex registration form: no quoted leading token, path without a blank.
        $codexHookDir = New-TempDir 'codexhooks'
        $codexHook = Join-Path $codexHookDir 'tripwire-pretool.ps1'
        [System.IO.File]::Copy($HookPath, $codexHook, $true)
        $r = Invoke-Wired (New-CodexPayload 'Get-Content C:\proj\.env') $RealEnv 'powershell.exe' ('-NoProfile -NonInteractive -File ' + $codexHook)
        Check-FailLine 'codex registration (powershell.exe -NoProfile -NonInteractive -File <path>): wrapped .env read' $r 'TW-SEC-001' -Full
        $pc = (& $RealExe hook path --host codex) -join ''
        $pl = (& $RealExe hook path --host claude) -join ''
        Check 'codex: tripwire hook path --host codex prints the same packaged script as --host claude' (
            $pc -and $pc -eq $pl -and (Test-Path -LiteralPath $pc -PathType Leaf)) "codex=$pc claude=$pl"

        # Coding-root TW-GIT-001 warn (the one allowed warn note), real classifier,
        # actual git toplevels. Command strings are data: no add/stash/push runs.
        $cases = @(
            @{ Name = 'marker repo broad add'; Cmd = 'git add -A'; Cwd = $markerRepo; Note = 'warn'; Rule = 'TW-GIT-001' },
            @{ Name = 'ordinary repo broad add'; Cmd = 'git add -A'; Cwd = $plainRepo; Note = ''; Rule = '' },
            @{ Name = 'leading quoted cd overrides cwd'; Cmd = ('cd "' + $markerRepo + '" && git add --all'); Cwd = $plainRepo; Note = 'warn'; Rule = 'TW-GIT-001' },
            @{ Name = 'leading cd out of coding root'; Cmd = ('cd "' + $plainRepo + '" && git add --all'); Cwd = $markerRepo; Note = ''; Rule = '' },
            @{ Name = 'scoped add'; Cmd = 'git add -- f.txt'; Cwd = $markerRepo; Note = ''; Rule = '' },
            @{ Name = 'fail takes precedence'; Cmd = 'git add -A; git push --force'; Cwd = $markerRepo; Note = 'fail'; Rule = 'TW-GIT-003' },
            @{ Name = 'bare stash at coding root'; Cmd = 'git stash'; Cwd = $markerRepo; Note = 'warn'; Rule = 'TW-GIT-001' },
            @{ Name = 'bare stash in ordinary repo'; Cmd = 'git stash'; Cwd = $plainRepo; Note = ''; Rule = '' },
            @{ Name = 'subdirectory resolves git toplevel'; Cmd = 'git add .'; Cwd = $subDir; Note = 'warn'; Rule = 'TW-GIT-001' },
            @{ Name = 'relative cd from subdir'; Cmd = 'cd .. && git add -A'; Cwd = $subDir; Note = 'warn'; Rule = 'TW-GIT-001' },
            # The classifier does not yet emit a finding for git -C ... add.
            @{ Name = 'git -C classifier limitation'; Cmd = ('git -C "' + $markerRepo + '" add -A'); Cwd = $plainRepo; Note = ''; Rule = '' },
            @{ Name = 'dynamic cd is unproven despite existing literal directory'; Cmd = 'cd "$TARGET" && git add -A'; Cwd = $markerRepo; Note = ''; Rule = '' },
            @{ Name = 'non-git cwd'; Cmd = 'git add -A'; Cwd = $nonGit; Note = ''; Rule = '' },
            @{ Name = 'nonexistent cwd'; Cmd = 'git add -A'; Cwd = (Join-Path $nonGit 'absent'); Note = ''; Rule = '' }
        )
        foreach ($case in $cases) {
            $r = Invoke-Wired (New-Payload 'Bash' $case.Cmd $case.Cwd) $RealEnv
            if ($case.Name -eq 'fail takes precedence') {
                $rows = @(Get-ShadowRows $r.La)
                Check 'coding root: fail precedence has both a classified warn and fail in shadow rows' (
                    @($rows | Where-Object { $_.rule_id -match '^TW-GIT-001(@|$)' -and $_.severity -eq 'warn' }).Count -gt 0 -and
                    @($rows | Where-Object { $_.rule_id -match '^TW-GIT-003(@|$)' -and $_.severity -eq 'fail' }).Count -gt 0
                ) "rows=$(Get-ShadowText $r.La)"
            }
            if (-not $case.Note) {
                Check-Silent ('coding root: ' + $case.Name) $r
            } else {
                Check-NoteLine ('coding root: ' + $case.Name) $r $case.Note $case.Rule -Full
            }
        }
        $r = Invoke-Wired (New-Payload 'Bash' 'git add -A' $markerRepo) ($RealEnv + @{
            GIT_DIR = (Join-Path $plainRepo '.git'); GIT_WORK_TREE = $plainRepo
            GIT_INDEX_FILE = (Join-Path $plainRepo '.git/index'); GIT_COMMON_DIR = (Join-Path $plainRepo '.git')
        })
        Check 'coding root: inherited git target variables cannot redirect marker-repo resolution' (
            $r.Code -eq 0 -and $r.Out -match 'tripwire: \[warn\] TW-GIT-001'
        ) "out=$($r.Out) err=$($r.Err)"

        # ls -la with the real CLI on PATH -> no output, no row.
        $r = Invoke-Wired (New-Payload 'Bash' 'ls -la') $RealEnv
        Check-Silent 'ls -la' $r
        Check 'ls -la -> no shadow row' (-not (Test-Path -LiteralPath (Get-ShadowPath $r.La)))

        # Stdin robustness: a UTF-8 BOM and non-ASCII command text still parse.
        $r = Invoke-Wired (New-Payload 'PowerShell' 'cat .env') $RealEnv -prefixBom
        Check 'stdin with UTF-8 BOM -> still parsed (TW-SEC-001 line)' ($r.Code -eq 0 -and $r.Out -match 'TW-SEC-001') "out=$($r.Out)"
        $nonAsciiCmd = 'cat .env # caf' + [char]0x00E9
        $r = Invoke-Wired (New-Payload 'PowerShell' $nonAsciiCmd) $RealEnv
        Check-FailLine 'non-ASCII command text' $r 'TW-SEC-001' -Full

        # ===== Checkout tiers (uv run --project), real repository ===================
        # DEV_UTILITIES_ROOT holds <slug> checkouts; a junction named "tripwire"
        # points at this repository.
        $JRoot = New-TempDir 'utilities root'
        $JLink = Join-Path $JRoot 'tripwire'
        $null = New-Item -ItemType Junction -Path $JLink -Target $RepoRoot
        $script:Junctions += $JLink
        $junctionOk = Test-Path -LiteralPath (Join-Path $JLink 'pyproject.toml')
        Check 'fixture: utilities-root junction resolves to this repository' $junctionOk
        if ($junctionOk -and $null -ne $UvExe) {
            # Warm up uv (first run may rebuild the editable install) outside the 3 s cap.
            $prevEap = $ErrorActionPreference; $ErrorActionPreference = 'Continue'
            $null = & $UvExe run --project $JLink tripwire --version 2>$null
            $ErrorActionPreference = $prevEap
            $r = Invoke-Wired (New-Payload 'PowerShell' 'cat .env') @{ DEV_UTILITIES_ROOT = $JRoot }
            Check-FailLine 'tier DEV_UTILITIES_ROOT checkout (uv run): cat .env' $r 'TW-SEC-001'
            # The open project is never a source, even when it holds a working
            # tripwire checkout (there is no CLAUDE_PROJECT_DIR tier).
            $r = Invoke-Wired (New-Payload 'PowerShell' 'cat .env') @{ CLAUDE_PROJECT_DIR = $JRoot }
            Check-Silent 'no project tier: CLAUDE_PROJECT_DIR with a real checkout (DEV_UTILITIES_ROOT unset) is not used' $r
            Check 'no project tier: CLAUDE_PROJECT_DIR (unset root) -> no shadow row' (-not (Test-Path -LiteralPath (Get-ShadowPath $r.La)))
            $r = Invoke-Wired (New-Payload 'PowerShell' 'cat .env') @{ DEV_UTILITIES_ROOT = ''; CLAUDE_PROJECT_DIR = $JRoot }
            Check-Silent 'no project tier: CLAUDE_PROJECT_DIR with a real checkout (DEV_UTILITIES_ROOT empty) is not used' $r
            $bogus = New-TempDir 'bogus'
            $r = Invoke-Wired (New-Payload 'PowerShell' 'cat .env') @{ DEV_UTILITIES_ROOT = $bogus; CLAUDE_PROJECT_DIR = $JRoot }
            Check-Silent 'no project tier: a set DEV_UTILITIES_ROOT without tripwire does not fall through to CLAUDE_PROJECT_DIR' $r
            Check 'no project tier: tripwire-less DEV_UTILITIES_ROOT -> no shadow row' (-not (Test-Path -LiteralPath (Get-ShadowPath $r.La)))
        }
    }

    # ===== Resolution order with fake CLIs (deterministic) ==========================
    $fakeOk = Test-Path -LiteralPath $FakeExeMaster
    if ($fakeOk) {
        $pathBin = New-FakeBin @(New-Finding 'TW-SEC-001@v1' 'fail' 'from-path-tier') 'path-bin'
        $toolBin = New-FakeBin @(New-Finding 'TW-SEC-001@v1' 'fail' 'from-tool-bin') 'tool-bin'
        $fakeRoot = New-FakeRoot

        $r = Invoke-Wired (New-Payload 'PowerShell' 'cat .env') @{ PATH = ($pathBin + ';' + $BasePath) }
        Check-FailLine 'tier PATH: fake tripwire.exe on PATH' $r 'TW-SEC-001' -Full
        $calls = @(Get-FakeCalls $pathBin)
        $want = (@('command', 'explain', '--json', '--', 'cat .env') -join [string][char]0x1F)
        Check 'tier PATH: exactly one call with argv "command explain --json -- <command>"' (
            $calls.Count -eq 1 -and $calls[0] -ceq $want) "calls=$($calls -join ' | ')"

        Set-FakeFindings $pathBin @(New-Finding 'TW-SEC-001@v1' 'fail' 'from-path-tier')
        $r = Invoke-Wired (New-Payload 'PowerShell' 'cat .env') @{
            PATH = ($pathBin + ';' + $BasePath); UV_TOOL_BIN_DIR = $toolBin; DEV_UTILITIES_ROOT = $fakeRoot }
        Check 'tier order: PATH beats the tool bin dir and DEV_UTILITIES_ROOT' (
            $r.Out -match 'from-path-tier' -and (Get-FakeCalls $toolBin).Count -eq 0 -and -not (Test-SpawnEvidence $fakeRoot)) "out=$($r.Out)"

        $r = Invoke-Wired (New-Payload 'PowerShell' 'cat .env') @{ UV_TOOL_BIN_DIR = $toolBin; DEV_UTILITIES_ROOT = $fakeRoot }
        Check 'tier bin: UV_TOOL_BIN_DIR tripwire.exe used, beats DEV_UTILITIES_ROOT (no uv spawn)' (
            $r.Out -match 'tripwire: \[fail\] TW-SEC-001 from-tool-bin' -and -not (Test-SpawnEvidence $fakeRoot)) "out=$($r.Out)"
        $r = Invoke-Wired (New-Payload 'PowerShell' 'cat .env') @{ UV_TOOL_BIN_DIR = $null; XDG_BIN_HOME = $toolBin }
        Check 'tier bin: XDG_BIN_HOME tripwire.exe used when UV_TOOL_BIN_DIR is unset' ($r.Out -match 'from-tool-bin') "out=$($r.Out)"
        $xdgData = Join-Path (New-TempDir 'xdg') 'data'
        [void][IO.Directory]::CreateDirectory($xdgData)
        $xdgBin = Join-Path (Split-Path -Parent $xdgData) 'bin'
        [void][IO.Directory]::CreateDirectory($xdgBin)
        [IO.File]::Copy($FakeExeMaster, (Join-Path $xdgBin 'tripwire.exe'))
        Set-FakeFindings $xdgBin @(New-Finding 'TW-SEC-001@v1' 'fail' 'from-xdg-data')
        $r = Invoke-Wired (New-Payload 'PowerShell' 'cat .env') @{ UV_TOOL_BIN_DIR = $null; XDG_DATA_HOME = $xdgData }
        Check 'tier bin: XDG_DATA_HOME\..\bin tripwire.exe used when UV_TOOL_BIN_DIR/XDG_BIN_HOME are unset' ($r.Out -match 'from-xdg-data') "out=$($r.Out)"

        # Only an .exe is accepted: a tripwire.cmd on PATH or in the bin dir is ignored
        # (it would route the command text through cmd.exe parsing).
        $cmdBin = New-TempDir 'cmd-bin'
        $cmdMarker = Join-Path $cmdBin 'ran.txt'
        [IO.File]::WriteAllText((Join-Path $cmdBin 'tripwire.cmd'), "@echo ran> `"$cmdMarker`"`r`n")
        $r = Invoke-Wired (New-Payload 'PowerShell' 'cat .env') @{ PATH = ($cmdBin + ';' + $BasePath); UV_TOOL_BIN_DIR = $cmdBin }
        Check-Silent 'tier guard: tripwire.cmd on PATH / in the bin dir is never run' $r
        Check 'tier guard: tripwire.cmd left no run marker and no shadow row' (
            -not (Test-Path -LiteralPath $cmdMarker) -and -not (Test-Path -LiteralPath (Get-ShadowPath $r.La)))

        # Absent everywhere -> silent skip, no row.
        $r = Invoke-Wired (New-Payload 'PowerShell' 'cat .env') @{}
        Check-Silent 'tier absent: no CLI, no checkout' $r
        Check 'tier absent: no shadow row' (-not (Test-Path -LiteralPath (Get-ShadowPath $r.La)))

        # Pre-screen miss never spawns even with a CLI on PATH.
        Set-FakeFindings $pathBin @(New-Finding 'TW-SEC-001@v1' 'fail' 'from-path-tier')
        $r = Invoke-Wired (New-Payload 'Bash' 'ls -la') @{ PATH = ($pathBin + ';' + $BasePath) }
        Check 'no-spawn: ls -la with a CLI on PATH -> silent, CLI never called, no row' (
            $r.Code -eq 0 -and -not $r.Out.Trim() -and (Get-FakeCalls $pathBin).Count -eq 0 -and
            -not (Test-Path -LiteralPath (Get-ShadowPath $r.La))) "out=$($r.Out)"

        # ===== CC-D12 note rule, both ways (fake findings, coding root) =============
        # 'git add -A' with cwd = a coding root makes the coding-root resolver true,
        # so only the finding shape decides whether a note is emitted.
        $noteBin = New-FakeBin @() 'note-bin'
        $NoteEnv = @{ PATH = ($noteBin + ';' + $BasePath) }
        Set-FakeFindings $noteBin @(New-Finding 'TW-GIT-001@v1' 'warn' 'broad staging')
        $r = Invoke-Wired (New-Payload 'PowerShell' 'git add -A' $markerRepo) $NoteEnv
        Check-NoteLine 'CC-D12: coding-root TW-GIT-001 warn' $r 'warn' 'TW-GIT-001' -Full
        $r = Invoke-Wired (New-Payload 'PowerShell' 'git add -A' $plainRepo) $NoteEnv
        Check-Silent 'CC-D12: TW-GIT-001 warn outside a coding root' $r
        Check 'CC-D12: TW-GIT-001 warn outside a coding root -> warn row still logged' (
            @(Get-ShadowRows $r.La | Where-Object { $_.severity -eq 'warn' }).Count -eq 1) "rows=$(Get-ShadowText $r.La)"

        Set-FakeFindings $noteBin @((New-Finding 'TW-GIT-001@v1' 'warn' 'broad one'), (New-Finding 'TW-GIT-001@v1' 'warn' 'broad two'))
        $r = Invoke-Wired (New-Payload 'PowerShell' 'git add -A' $markerRepo) $NoteEnv
        Check-NoteLine 'CC-D12: two coding-root TW-GIT-001 warns -> still one note' $r 'warn' 'TW-GIT-001'

        $otherWarns = @(
            @{ Rule = 'TW-SHL-001@v1'; Sev = 'warn' },
            @{ Rule = 'TW-GIT-002@v1'; Sev = 'warn' },
            @{ Rule = 'TW-WTR-002@v1'; Sev = 'warn' },
            @{ Rule = 'TW-SES-001@v1'; Sev = 'warn' },
            @{ Rule = 'TW-SES-002@v1'; Sev = 'warn' },
            @{ Rule = 'TW-GIT-0011@v1'; Sev = 'warn' },
            @{ Rule = 'TW-GIT-001@v1'; Sev = 'unknown' }
        )
        foreach ($ow in $otherWarns) {
            Set-FakeFindings $noteBin @(New-Finding $ow.Rule $ow.Sev 'other finding')
            $r = Invoke-Wired (New-Payload 'PowerShell' 'git add -A' $markerRepo) $NoteEnv
            $rows = @(Get-ShadowRows $r.La)
            Check ("CC-D12: {0} {1} at a coding root -> no note, row logged" -f $ow.Rule, $ow.Sev) (
                $r.Code -eq 0 -and -not $r.Out.Trim() -and $rows.Count -eq 1 -and $rows[0].severity -eq $ow.Sev
            ) "out=$($r.Out) rows=$(Get-ShadowText $r.La)"
        }

        foreach ($order in @('warn-first', 'fail-first')) {
            $w = New-Finding 'TW-GIT-001@v1' 'warn' 'broad staging'
            $f = New-Finding 'TW-SEC-001@v1' 'fail' 'secret read'
            if ($order -eq 'warn-first') { Set-FakeFindings $noteBin @($w, $f) } else { Set-FakeFindings $noteBin @($f, $w) }
            $r = Invoke-Wired (New-Payload 'PowerShell' 'git add -A' $markerRepo) $NoteEnv
            Check-NoteLine "CC-D12: fail + coding-root TW-GIT-001 warn ($order) -> only the fail note" $r 'fail' 'TW-SEC-001' -Full
            Check "CC-D12: fail + warn ($order) -> no warn text in output, both rows logged" (
                $r.Out -notmatch '\[warn\]' -and @(Get-ShadowRows $r.La).Count -eq 2) "out=$($r.Out)"
        }

        # One line, capped message, even when tripwire's message is long / multi-line.
        Set-FakeFindings $noteBin @(New-Finding 'TW-SEC-001@v1' 'fail' (('line one' + "`n" + 'line two ') + ('x' * 600)))
        $r = Invoke-Wired (New-Payload 'PowerShell' 'cat .env') $NoteEnv
        Check-FailLine 'long multi-line fail message -> one line, capped' $r 'TW-SEC-001' -Full
    }

    # ===== The open project is never run ============================================
    # A hostile project ships tripwire/pyproject.toml whose in-tree build backend
    # writes HOSTILE-CODE-RAN the moment uv imports it. With CLAUDE_PROJECT_DIR
    # (and the payload cwd) pointing at it, nothing on PATH or in the tool bin dir,
    # and DEV_UTILITIES_ROOT unset or empty, the hook must not start uv (a logging
    # fake uv.exe first on PATH stays uncalled), and the project must keep no
    # trace (no marker, no .venv, no uv.lock).
    $hostileA = New-HostileRoot
    $spyUv = New-TempDir 'spy-uv'
    if ($fakeOk) { [System.IO.File]::Copy($FakeExeMaster, (Join-Path $spyUv 'uv.exe')) }
    Check 'fixture: logging spy uv.exe built' (Test-Path -LiteralPath (Join-Path $spyUv 'uv.exe'))
    foreach ($case in @(
        @{ Name = 'DEV_UTILITIES_ROOT unset'; Env = @{ CLAUDE_PROJECT_DIR = $hostileA } },
        @{ Name = 'DEV_UTILITIES_ROOT empty'; Env = @{ CLAUDE_PROJECT_DIR = $hostileA; DEV_UTILITIES_ROOT = '' } }
    )) {
        foreach ($uvMode in @('spy', 'real')) {
            $envC = $case.Env.Clone()
            if ($uvMode -eq 'spy') { $envC['PATH'] = ($spyUv + ';' + $BasePath) }
            $r = Invoke-Wired (New-Payload 'PowerShell' 'cat .env' $hostileA) $envC
            $label = "hostile project ($($case.Name), $uvMode uv)"
            Check "$label -> exit 0, no stdout, no stderr" ($r.Code -eq 0 -and -not $r.Out.Trim() -and -not $r.Err.Trim()) `
                "exit=$($r.Code) out=$($r.Out) err=$($r.Err)"
            if ($uvMode -eq 'spy') {
                Check "$label -> no uv process started (spy uv.exe first on PATH never called)" (
                    (Get-FakeCalls $spyUv).Count -eq 0) "calls=$((Get-FakeCalls $spyUv) -join ' | ')"
            }
            Check "$label -> its code left no trace (no marker, no .venv, no uv.lock)" (
                -not (Test-HostileRan $hostileA) -and -not (Test-SpawnEvidence $hostileA))
            Check "$label -> no shadow row" (-not (Test-Path -LiteralPath (Get-ShadowPath $r.La)))
        }
    }
    # Red anchors for both instruments. (1) The spy sees a spawn: the trusted
    # DEV_UTILITIES_ROOT tier pointed at the same shape DOES call uv. (2) The
    # marker is reachable: real uv through that tier runs the hostile backend.
    $hostileB = New-HostileRoot
    $spyLog = Join-Path $spyUv 'calls.log'
    if (Test-Path -LiteralPath $spyLog) { [System.IO.File]::Delete($spyLog) }
    $r = Invoke-Wired (New-Payload 'PowerShell' 'cat .env') @{ DEV_UTILITIES_ROOT = $hostileB; PATH = ($spyUv + ';' + $BasePath) }
    $spyCalls = @(Get-FakeCalls $spyUv)
    Check 'red-anchor: spy uv.exe records a spawn via DEV_UTILITIES_ROOT (instrument can fail)' (
        $spyCalls.Count -eq 1 -and $spyCalls[0].StartsWith('run' + [char]0x1F + '--project' + [char]0x1F)) "calls=$($spyCalls -join ' | ')"
    Check 'red-anchor: spy call -> silent, one unavailable row' (
        $r.Code -eq 0 -and -not $r.Out.Trim() -and @(Get-ShadowRows $r.La).Count -eq 1) "out=$($r.Out) rows=$(Get-ShadowText $r.La)"
    $hostileC = New-HostileRoot
    $r = Invoke-Wired (New-Payload 'PowerShell' 'cat .env') @{ DEV_UTILITIES_ROOT = $hostileC }
    Check 'red-anchor: real uv via DEV_UTILITIES_ROOT runs the hostile backend (marker written; instrument can fail)' (
        Test-HostileRan $hostileC) "exit=$($r.Code) err=$($r.Err)"
    Check-Silent 'red-anchor: hostile backend run through the trusted tier still fails open' $r

    # Nothing resolvable at all (default child env: no tripwire on PATH, empty
    # tool bin dir, no DEV_UTILITIES_ROOT, no CLAUDE_PROJECT_DIR) -> silent, exit 0.
    foreach ($cmd in @('cat .env', 'git add -A', 'rm -rf build')) {
        $r = Invoke-Wired (New-Payload 'PowerShell' $cmd $markerRepo)
        Check "unresolvable: '$cmd' -> exit 0, no stdout, no stderr" ($r.Code -eq 0 -and -not $r.Out.Trim() -and -not $r.Err.Trim()) `
            "exit=$($r.Code) out=$($r.Out) err=$($r.Err)"
        Check "unresolvable: '$cmd' -> no shadow row" (-not (Test-Path -LiteralPath (Get-ShadowPath $r.La)))
    }

    # ===== Fail-open cases (no tripwire needed) =====================================
    $fake = New-FakeRoot
    $r = Invoke-Wired '{not json' @{ DEV_UTILITIES_ROOT = $fake }
    Check-Silent 'malformed stdin' $r
    $laMalformed = $r.La
    $r = Invoke-Wired '' @{ DEV_UTILITIES_ROOT = $fake; LOCALAPPDATA = $laMalformed }
    Check-Silent 'empty stdin' $r
    $r = Invoke-Wired '{"tool_name":"Bash","tool_input":{}}' @{ DEV_UTILITIES_ROOT = $fake; LOCALAPPDATA = $laMalformed }
    Check-Silent 'payload without command' $r
    Check 'malformed/empty/no-command -> no shadow row, no uv spawn' (
        -not (Test-Path -LiteralPath (Get-ShadowPath $laMalformed)) -and -not (Test-SpawnEvidence $fake))

    # Red anchor: bogus tripwire root -> exit 0, no output, no row.
    $bogus = New-TempDir 'bogus'
    $r = Invoke-Wired (New-Payload 'PowerShell' 'cat .env') @{ DEV_UTILITIES_ROOT = $bogus }
    Check-Silent 'red-anchor: bogus tripwire root + cat .env' $r
    Check 'red-anchor: bogus tripwire root -> no shadow row' (-not (Test-Path -LiteralPath (Get-ShadowPath $r.La)))

    $r = Invoke-Wired (New-Payload 'Bash' 'ls -la') @{ DEV_UTILITIES_ROOT = $fake }
    Check-Silent 'no-spawn: ls -la vs fake tripwire root' $r
    Check 'no-spawn: ls -la left NO uv spawn evidence (.venv/uv.lock) in the fake root' (-not (Test-SpawnEvidence $fake))
    Check 'no-spawn: ls -la wrote no shadow row' (-not (Test-Path -LiteralPath (Get-ShadowPath $r.La)))

    $r = Invoke-Wired (New-Payload 'PowerShell' 'cat .env') @{ DEV_UTILITIES_ROOT = $fake }
    Check 'red-anchor: cat .env vs fake root DOES leave spawn evidence (instrument can fail)' (Test-SpawnEvidence $fake)
    Check-Silent 'red-anchor: failed tripwire call' $r
    $rows = @(Get-ShadowRows $r.La)
    Check 'red-anchor: failed tripwire call -> one row severity unavailable' `
        ($rows.Count -eq 1 -and $rows[0].severity -eq 'unavailable') "rows=$(Get-ShadowText $r.La)"

    # Timing: ABSOLUTE median over 9 runs of the registered hook command with a
    # realistic pre-screen-miss payload, end to end (powershell.exe startup
    # included). The bare powershell.exe no-op baseline is printed for context.
    $baseArgs = '-NoProfile -NonInteractive -Command "exit 0"'
    $baseMs = @(); $hookMs = @()
    $laT = New-TempDir 'la-timing'
    $fakeT = New-FakeRoot
    for ($i = 0; $i -lt 9; $i++) {
        $baseMs += (Invoke-Wired '' @{ LOCALAPPDATA = $laT } 'powershell.exe' $baseArgs).Ms
        $hookMs += (Invoke-Wired (New-Payload 'Bash' 'ls -la') @{ DEV_UTILITIES_ROOT = $fakeT; LOCALAPPDATA = $laT }).Ms
    }
    $baseMed = ($baseMs | Sort-Object)[4]; $hookMed = ($hookMs | Sort-Object)[4]
    Write-Host ("#     timing: hook ls -la median {0} ms (runs {1}); baseline powershell.exe no-op median {2} ms (runs {3}); delta {4} ms" -f `
        $hookMed, (($hookMs | Sort-Object) -join '/'), $baseMed, (($baseMs | Sort-Object) -join '/'), ($hookMed - $baseMed))
    if ($null -ne $FailPathMs) { Write-Host "#     timing: fail path (cat .env, real tripwire on PATH) $FailPathMs ms" }
    # The budget is absolute ($HookBudgetMs). When powershell.exe startup alone
    # has a median above $SlowBaselineMs (a loaded machine), the absolute figure
    # measures the machine, not the hook; the check then requires the hook to add
    # less than $HookAddedBudgetMs over that baseline and says which rule applied.
    $HookBudgetMs = 300       # ported absolute budget for the pre-screen-miss path
    $SlowBaselineMs = 200     # bare powershell.exe startup above this = loaded machine
    $HookAddedBudgetMs = 100  # hook's own cost over startup (= 300 - 200)
    if ($baseMed -le $SlowBaselineMs) {
        Check "timing: ls -la hook absolute median wall time < $HookBudgetMs ms" ($hookMed -lt $HookBudgetMs) "median=$hookMed ms"
    } else {
        Write-Host "#     timing: baseline median $baseMed ms > $SlowBaselineMs ms -> applying the delta rule"
        Check "timing: ls -la hook median < $HookAddedBudgetMs ms over the powershell.exe baseline (loaded machine)" (($hookMed - $baseMed) -lt $HookAddedBudgetMs) "delta=$($hookMed - $baseMed) ms"
    }
    Check 'timing: the 9 timed ls -la runs left NO uv spawn evidence and wrote no shadow row' `
        ((-not (Test-SpawnEvidence $fakeT)) -and -not (Test-Path -LiteralPath (Get-ShadowPath $laT)))

    if ($hasFns) {
        # ===== Redaction unit section (Protect-TwObserved called directly) =====
        $u = Protect-TwObserved 'selector is (Bearer abc123)' 'curl -H "Authorization: Bearer abc123"'
        Check 'redact-unit: Bearer abc123 from a quoted header -> secret gone, wording kept' `
            ($u -notmatch 'abc123' -and $u.Contains('selector is')) "u=$u"
        $u = Protect-TwObserved 'normalized form api_key=zz9q not from the command' 'git push'
        Check 'redact-unit: layer 2 key=value (text not literally in the command) -> value redacted' `
            ($u -notmatch 'zz9q' -and $u.Contains('api_key=[REDACTED]')) "u=$u"
        $u = Protect-TwObserved ('blob ' + ('A1b2' * 10) + ' end') ''
        Check 'redact-unit: layer 2 32+ char run with no command -> redacted' ($u -notmatch 'A1b2A1b2' -and $u.Contains('[REDACTED]')) "u=$u"
        $u = Protect-TwObserved ('wording ' * 60) 'ls'
        Check 'redact-unit: observed capped at 200 chars' ($u.Length -le 200 -and $u.Length -gt 0) "len=$($u.Length)"
        Check 'redact-unit: null observed stays null' ($null -eq (Protect-TwObserved $null 'git push'))

        # ===== Coding-root resolver unit section =====
        Check 'resolver: git -C overrides cwd' (Test-TwCodingRoot ('git -C "' + $markerRepo + '" add -A') $plainRepo)
        Check 'resolver: relative -C is based on leading cd' (Test-TwCodingRoot ('cd "' + $subDir + '" && git -C .. add -A') $plainRepo)
        Check 'resolver: -C ordinary repo overrides leading coding-root cd' (-not (Test-TwCodingRoot ('cd "' + $markerRepo + '" && git -C "' + $plainRepo + '" add -A') $markerRepo))

        # ===== Tool bin dir unit section (default = OS user profile\.local\bin) =====
        $saved = @{}
        foreach ($k in @('UV_TOOL_BIN_DIR', 'XDG_BIN_HOME', 'XDG_DATA_HOME')) {
            $saved[$k] = [Environment]::GetEnvironmentVariable($k, 'Process')
            [Environment]::SetEnvironmentVariable($k, $null, 'Process')
        }
        try {
            $prof = [Environment]::GetFolderPath([Environment+SpecialFolder]::UserProfile)
            Check 'bin-dir unit: no overrides -> <user profile>\.local\bin' ((Get-TwToolBinDir) -eq (Join-Path $prof '.local\bin')) "got $(Get-TwToolBinDir)"
            [Environment]::SetEnvironmentVariable('UV_TOOL_BIN_DIR', 'relative\bin', 'Process')
            Check 'bin-dir unit: relative UV_TOOL_BIN_DIR is ignored' ($null -eq (Get-TwToolBinDir)) "got $(Get-TwToolBinDir)"
            [Environment]::SetEnvironmentVariable('UV_TOOL_BIN_DIR', '\\server\share\bin', 'Process')
            Check 'bin-dir unit: UNC UV_TOOL_BIN_DIR is ignored' ($null -eq (Get-TwToolBinDir)) "got $(Get-TwToolBinDir)"
        } finally {
            foreach ($k in $saved.Keys) { [Environment]::SetEnvironmentVariable($k, $saved[$k], 'Process') }
        }

        # ===== Timeout + process-TREE kill =====
        $pidFile = Join-Path (New-TempDir 'tree') 'grandchild.pid'
        $script = "`$g = Start-Process powershell.exe -ArgumentList '-NoProfile','-Command','Start-Sleep 60' -PassThru -WindowStyle Hidden; " +
                  "[System.IO.File]::WriteAllText('$pidFile', [string]`$g.Id); Start-Sleep 60"
        $sw = [System.Diagnostics.Stopwatch]::StartNew()
        $tr = Invoke-TwBounded 'powershell.exe' @('-NoProfile', '-NonInteractive', '-Command', $script) 3000
        $sw.Stop()
        Check 'timeout: bounded call reports TimedOut' ($tr.TimedOut -eq $true)
        Check 'timeout: bounded call returns within 3.5 s' ($sw.ElapsedMilliseconds -lt 3500) "$($sw.ElapsedMilliseconds) ms"
        Check 'timeout: partial output discarded' ($null -eq $tr.Stdout)
        $gpid = $null
        if (Test-Path -LiteralPath $pidFile) { $gpid = [int]([System.IO.File]::ReadAllText($pidFile).Trim()) }
        Check 'timeout: grandchild was started (pid file written)' ($null -ne $gpid)
        if ($null -ne $gpid) {
            $alive = $true
            for ($i = 0; $i -lt 20 -and $alive; $i++) {
                $alive = $null -ne (Get-Process -Id $gpid -ErrorAction SilentlyContinue)
                if ($alive) { Start-Sleep -Milliseconds 100 }
            }
            Check 'timeout: grandchild killed with the tree (taskkill /T)' (-not $alive) "pid $gpid still alive"
            if ($alive) { try { Stop-Process -Id $gpid -Force } catch { } }
        }

        # ===== Argv escaping unit =====
        $echoPs1 = Join-Path (New-TempDir 'argv') 'echo-argv.ps1'
        [System.IO.File]::WriteAllText($echoPs1,
            '[Environment]::GetCommandLineArgs() | Select-Object -Skip 5 | ForEach-Object { "B:" + [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($_)) }')
        $tricky = @('a b', 'say "hi"', 'C:\dir\', 'C:\x y\"q"\', '', 'plain')
        $echo = Invoke-TwBounded 'powershell.exe' (@('-NoProfile', '-NonInteractive', '-File', $echoPs1) + $tricky) 10000
        $got = @(([string]$echo.Stdout) -split "`r?`n" | Where-Object { $_ -like 'B:*' } |
            ForEach-Object { [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($_.Substring(2))) })
        Check 'argv: quoted/backslash/empty args round-trip intact through ConvertTo-TwWinArg' `
            ($got.Count -eq $tricky.Count -and ($got -join '|') -ceq ($tricky -join '|')) "got=$($got -join '|')"
    }

    # ===== Global invariants over EVERY hook invocation in this run ================
    $n = $script:AllOutputs.Count
    $pd = @($script:AllOutputs | Where-Object { $_ -match 'permissionDecision' }).Count
    Check "global: no hook output (stdout or stderr) ever contains permissionDecision ($n invocations)" ($n -gt 0 -and $pd -eq 0) "$pd of $n outputs contain it"
    $outside = @($script:AllLa | Where-Object { -not $_.StartsWith($script:TempRoot, [StringComparison]::OrdinalIgnoreCase) }).Count
    Check 'global: every hook invocation ran with a temp LOCALAPPDATA (the real one is never written)' ($outside -eq 0) "$outside outside the temp root"
    $oldDirs =@($script:AllLa | Sort-Object -Unique | Where-Object { Test-Path -LiteralPath (Join-Path $_ 'jev-gate') })
    Check 'global: nothing written under the old jev-gate folder in any LOCALAPPDATA' ($oldDirs.Count -eq 0) "$($oldDirs.Count) LOCALAPPDATA dirs gained a jev-gate folder"
    $newLogs = @($script:AllLa | Sort-Object -Unique | Where-Object { Test-Path -LiteralPath (Get-ShadowPath $_) }).Count
    Check 'global: the shadow log was written at %LOCALAPPDATA%\tripwire\hook-shadow.jsonl (positive control)' ($newLogs -gt 0) "$newLogs logs"
} finally {
    # Remove junctions FIRST (the link only, never the target), then the temp tree.
    $junctionsGone = $true
    foreach ($j in $script:Junctions) {
        try { if (Test-Path -LiteralPath $j) { [System.IO.Directory]::Delete($j, $false) } } catch { $junctionsGone = $false }
    }
    if ($junctionsGone) { Remove-Item -LiteralPath $TempRoot -Recurse -Force -ErrorAction SilentlyContinue }
    else { Write-Host "#     left temp dir in place (junction removal failed): $TempRoot" }
}

Write-Host ''
if ($fail -eq 0) { Write-Host "ALL PASS ($total/$total)"; exit 0 } else { Write-Host "$fail/$total FAILED"; exit 1 }
