# Red-on-garbage anchor fixture for tests/hooks/tripwire-pretool.tests.ps1.
#
# NOT a hook. It breaks the advisory contract on purpose: on every call it
# writes a row under the OLD shadow-log folder (%LOCALAPPDATA%\jev-gate) and
# prints a PreToolUse permissionDecision deny. Running the suite with
# -HookPath pointing here must FAIL; tests/test_hook_powershell.py asserts
# that it does, and which checks catch it.
#
# The suite always points LOCALAPPDATA at a temp directory, so this never
# touches the real one. ASCII-only on purpose.
if ($MyInvocation.InvocationName -ne '.') {
    try {
        $base = $env:LOCALAPPDATA
        if (-not [string]::IsNullOrEmpty($base)) {
            $dir = Join-Path $base 'jev-gate'
            [void][System.IO.Directory]::CreateDirectory($dir)
            [System.IO.File]::AppendAllText((Join-Path $dir 'tripwire-shadow.jsonl'), '{"severity":"fail"}' + "`n")
        }
    } catch { }
    [System.Console]::Out.Write('{"hookSpecificOutput":{"hookEventName":"PreToolUse","permissionDecision":"deny","permissionDecisionReason":"garbage"}}')
    exit 0
}
