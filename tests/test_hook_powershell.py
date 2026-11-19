"""Run the PowerShell behavioural suite for the packaged hook from pytest.

The suite (``tests/hooks/tripwire-pretool.tests.ps1``) drives the hook through
the exact command line an installer registers::

    powershell.exe -NoProfile -NonInteractive -File "<absolute hook path>"

These tests run it twice: against the real packaged hook (must pass), and against
the red-on-garbage anchor fixture ``tests/hooks/fixtures/garbage-hook.ps1`` (must
fail, and on the named contract checks). The real tripwire CLI under test is the
console script next to this interpreter. Windows PowerShell 5.1 only.
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parent.parent
SUITE = REPO_ROOT / "tests" / "hooks" / "tripwire-pretool.tests.ps1"
GARBAGE = REPO_ROOT / "tests" / "hooks" / "fixtures" / "garbage-hook.ps1"

pytestmark = pytest.mark.skipif(
    sys.platform != "win32" or shutil.which("powershell") is None,
    reason="the hook targets Windows PowerShell 5.1",
)


def _run_suite(*extra: str) -> subprocess.CompletedProcess[str]:
    powershell = shutil.which("powershell")
    assert powershell is not None
    return subprocess.run(
        [
            powershell,
            "-NoProfile",
            "-ExecutionPolicy",
            "Bypass",
            "-File",
            str(SUITE),
            "-TripwireBin",
            str(Path(sys.executable).parent),
            *extra,
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=900,
        check=False,
    )


def _fail_lines(stdout: str) -> list[str]:
    return [line for line in stdout.splitlines() if line.startswith("FAIL")]


def test_powershell_suite_passes_on_packaged_hook() -> None:
    proc = _run_suite()
    assert proc.returncode == 0, "\n".join(_fail_lines(proc.stdout)) or proc.stdout[-4000:]
    assert "ALL PASS" in proc.stdout
    assert _fail_lines(proc.stdout) == []
    # The open-project security cases and their red anchors actually ran.
    for name in (
        "hostile project (DEV_UTILITIES_ROOT unset, spy uv) -> no uv process started",
        "red-anchor: spy uv.exe records a spawn via DEV_UTILITIES_ROOT",
        "hostile project (DEV_UTILITIES_ROOT empty, real uv) -> its code left no trace",
        "red-anchor: real uv via DEV_UTILITIES_ROOT runs the hostile backend",
        "unresolvable: 'cat .env' -> exit 0, no stdout, no stderr",
    ):
        assert any(line.startswith("PASS  " + name) for line in proc.stdout.splitlines()), name


def test_powershell_suite_fails_on_garbage_anchor() -> None:
    proc = _run_suite("-HookPath", str(GARBAGE))
    fails = "\n".join(_fail_lines(proc.stdout))
    assert proc.returncode == 1, proc.stdout[-4000:]
    assert "FAILED" in proc.stdout
    # The contract checks themselves must catch it, not a harness crash.
    assert "global: no hook output (stdout or stderr) ever contains permissionDecision" in fails
    assert "global: nothing written under the old jev-gate folder" in fails
    assert "global: the shadow log was written at" in fails
