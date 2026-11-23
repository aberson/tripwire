"""Tests for the packaged host hook: ``--version``, ``hook path`` and packaging.

``tripwire --version`` is the install health check and ``tripwire hook path --host
claude`` is what an installer runs to find the hook file it copies and registers.
The installer validates that output (one line, an absolute existing ``.ps1`` path
without a double quote), so these tests pin exactly that shape, through both the
in-process ``main`` and the installed console script (the production entry point).
"""

from __future__ import annotations

import io
import shutil
import subprocess
import sys
import tomllib
import zipfile
from pathlib import Path

import pytest

import tripwire
from tripwire import hook_assets
from tripwire.cli import main

REPO_ROOT = Path(__file__).resolve().parent.parent
SOURCE_HOOK = REPO_ROOT / "hooks" / "claude" / "tripwire-pretool.ps1"
WHEEL_HOOK = "tripwire/hooks/claude/tripwire-pretool.ps1"


def _console_script() -> str:
    """The ``tripwire`` console script installed next to this interpreter."""
    found = shutil.which("tripwire", path=str(Path(sys.executable).parent))
    assert found is not None, "tripwire console script is not installed in this environment"
    return found


def _run(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [_console_script(), *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=60,
        check=False,
    )


# --- --version ---------------------------------------------------------------------


def test_version_matches_pyproject() -> None:
    data = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    assert tripwire.__version__ == data["project"]["version"]


def test_version_flag_in_process(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        main(["--version"])
    assert exc.value.code == 0
    assert capsys.readouterr().out.strip() == f"tripwire {tripwire.__version__}"


def test_version_flag_console_script() -> None:
    proc = _run("--version")
    assert proc.returncode == 0
    assert proc.stdout.strip() == f"tripwire {tripwire.__version__}"


# --- hook path ---------------------------------------------------------------------


def _assert_installer_shape(stdout: str) -> Path:
    lines = stdout.splitlines()
    assert len(lines) == 1, f"expected exactly one line, got {lines!r}"
    line = lines[0]
    assert '"' not in line
    assert line.endswith(".ps1")
    path = Path(line)
    assert path.is_absolute()
    assert path.is_file()
    return path


def test_hook_path_in_process(capsys: pytest.CaptureFixture[str]) -> None:
    code = main(["hook", "path", "--host", "claude"])
    assert code == 0
    path = _assert_installer_shape(capsys.readouterr().out)
    assert path.read_bytes() == SOURCE_HOOK.read_bytes()


def test_hook_path_console_script() -> None:
    proc = _run("hook", "path", "--host", "claude")
    assert proc.returncode == 0, proc.stderr
    path = _assert_installer_shape(proc.stdout)
    assert path.read_bytes() == SOURCE_HOOK.read_bytes()


def test_hook_path_requires_host(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        main(["hook", "path"])
    assert exc.value.code == 2
    assert capsys.readouterr().out == ""


def test_hook_path_rejects_unknown_host(capsys: pytest.CaptureFixture[str]) -> None:
    with pytest.raises(SystemExit) as exc:
        main(["hook", "path", "--host", "copilot"])
    assert exc.value.code == 2
    assert capsys.readouterr().out == ""


def test_hook_path_prefers_packaged_copy(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    packaged = tmp_path / "packaged.ps1"
    source = tmp_path / "source.ps1"
    packaged.write_text("packaged", encoding="ascii")
    source.write_text("source", encoding="ascii")
    monkeypatch.setattr(hook_assets, "hook_candidates", lambda host: [packaged, source])
    assert hook_assets.hook_path("claude") == packaged
    packaged.unlink()
    assert hook_assets.hook_path("claude") == source


def test_hook_path_non_ansi_path_through_an_ansi_pipe(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    # A piped stdout on Windows uses the ANSI code page; a profile path outside it
    # must still print (as UTF-8), not raise UnicodeEncodeError.
    hook = tmp_path / "中文 profile" / "tripwire-pretool.ps1"
    hook.parent.mkdir()
    hook.write_text("hook", encoding="ascii")
    with pytest.raises(UnicodeEncodeError):
        str(hook).encode("cp1252")  # the instrument: cp1252 really cannot hold it
    monkeypatch.setattr(hook_assets, "hook_candidates", lambda host: [hook])
    raw = io.BytesIO()
    monkeypatch.setattr(sys, "stdout", io.TextIOWrapper(raw, encoding="cp1252"))
    code = main(["hook", "path", "--host", "claude"])
    assert code == 0
    assert raw.getvalue().decode("utf-8") == str(hook) + "\n"


def test_hook_path_missing_file_is_exit_2(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(hook_assets, "hook_candidates", lambda host: [tmp_path / "absent.ps1"])
    code = main(["hook", "path", "--host", "claude"])
    captured = capsys.readouterr()
    assert code == 2
    assert captured.out == ""
    assert "no claude hook file found" in captured.err


def test_cli_host_choices_come_from_hook_files() -> None:
    # One source of truth: the CLI's --host choices are HOOK_FILES' keys.
    assert sorted(hook_assets.HOOK_FILES) == ["claude", "codex"]
    for host, relative in hook_assets.HOOK_FILES.items():
        packaged = hook_assets.hook_candidates(host)[0]
        assert packaged.as_posix().endswith("tripwire/hooks/" + relative)


@pytest.mark.parametrize("host", ["claude", "codex"])
def test_hook_path_each_host_console_script(host: str) -> None:
    # The production entry point an installer runs, per host.
    proc = _run("hook", "path", "--host", host)
    assert proc.returncode == 0, proc.stderr
    path = _assert_installer_shape(proc.stdout)
    assert path.read_bytes() == SOURCE_HOOK.read_bytes()


def test_codex_and_claude_share_one_hook_script() -> None:
    # One script serves both hosts: no second copy that could drift.
    assert hook_assets.HOOK_FILES["codex"] == hook_assets.HOOK_FILES["claude"]
    assert hook_assets.hook_path("codex") == hook_assets.hook_path("claude")
    assert sorted(p.name for p in (REPO_ROOT / "hooks").iterdir()) == ["claude"]


def test_pyproject_force_include_ships_every_host_hook() -> None:
    # Every HOOK_FILES value must be force-included at tripwire/hooks/<value>.
    data = tomllib.loads((REPO_ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    force = data["tool"]["hatch"]["build"]["targets"]["wheel"]["force-include"]
    for relative in set(hook_assets.HOOK_FILES.values()):
        assert force.get("hooks/" + relative) == "tripwire/hooks/" + relative


# --- hook file static checks -------------------------------------------------------


@pytest.mark.parametrize(
    "path",
    [
        SOURCE_HOOK,
        REPO_ROOT / "tests" / "hooks" / "tripwire-pretool.tests.ps1",
        REPO_ROOT / "tests" / "hooks" / "fixtures" / "garbage-hook.ps1",
    ],
    ids=["hook", "suite", "garbage-fixture"],
)
def test_powershell_files_are_ascii(path: Path) -> None:
    data = path.read_bytes()
    offenders = [i for i, b in enumerate(data) if b > 0x7F]
    assert offenders == [], f"{path.name}: non-ASCII bytes at offsets {offenders[:10]}"


def test_hook_never_spells_a_permission_decision_key() -> None:
    # Advisory mode: no code line of the hook builds a permissionDecision field
    # (comments may name it). The behavioural suite checks every real output.
    code_lines = [
        line
        for line in SOURCE_HOOK.read_text(encoding="ascii").splitlines()
        if not line.lstrip().startswith("#")
    ]
    assert [line for line in code_lines if "permissionDecision" in line] == []


def test_hook_never_resolves_tripwire_from_the_open_project() -> None:
    # A packaged hook must not run code the open project ships: no code line reads
    # CLAUDE_PROJECT_DIR (comments may name it). The behavioural suite proves a
    # hostile project's tripwire/pyproject.toml is never run.
    code_lines = [
        line
        for line in SOURCE_HOOK.read_text(encoding="ascii").splitlines()
        if not line.lstrip().startswith("#")
    ]
    assert [line for line in code_lines if "CLAUDE_PROJECT_DIR" in line] == []


def test_hook_logs_to_tripwire_folder_not_old_location() -> None:
    text = SOURCE_HOOK.read_text(encoding="ascii")
    assert "Join-Path $base 'tripwire'" in text
    assert "'hook-shadow.jsonl'" in text
    assert "jev-gate" not in text


# --- packaging ---------------------------------------------------------------------


@pytest.mark.skipif(shutil.which("uv") is None, reason="uv is required to build the wheel")
def test_wheel_ships_the_hook(tmp_path: Path) -> None:
    uv = shutil.which("uv")
    assert uv is not None
    proc = subprocess.run(
        [uv, "build", "--wheel", "--out-dir", str(tmp_path), str(REPO_ROOT)],
        capture_output=True,
        text=True,
        encoding="utf-8",
        timeout=300,
        check=False,
    )
    assert proc.returncode == 0, proc.stderr
    wheels = list(tmp_path.glob("tripwire-*.whl"))
    assert len(wheels) == 1
    with zipfile.ZipFile(wheels[0]) as zf:
        assert WHEEL_HOOK in zf.namelist()
        assert zf.read(WHEEL_HOOK) == SOURCE_HOOK.read_bytes()
        assert "tripwire/hook_assets.py" in zf.namelist()
        # Every host's packaged path (codex included) is inside the wheel.
        for host, relative in hook_assets.HOOK_FILES.items():
            member = "tripwire/hooks/" + relative
            assert member in zf.namelist(), host
            assert zf.read(member) == SOURCE_HOOK.read_bytes(), host
