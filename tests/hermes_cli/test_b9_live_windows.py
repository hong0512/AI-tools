"""Batch-9 live pass — Windows family, real windows-latest runner.

Every test here drives REAL Windows surfaces (schtasks.exe, the Startup folder, powershell.exe,
real child processes) against a scratch HERMES_HOME. Red on origin/main, green on the b9 composite.

Scenarios (see /tmp/batch9/live/windows/SCENARIOS.md):
  #114945  gateway status reports a stale Scheduled Task + `start` reconciles it
  #114863  non-interactive `gateway start` never installs login persistence
  #114838  a failed Startup-folder swap leaves no Hermes_Gateway.tmp; uninstall/install sweep debris
  #114880  a Scheduled-Task gateway (HERMES_SUPERVISED_CHILD only) blocks interpreter-image kills
  #114857  Windows kanban workers' exit codes reach the dispatcher (75 -> rate_limited)
  #114758  the desktop's Windows SSH probe scripts parse in real powershell.exe
  #114782  profile clone keeps a real NTFS junction as a junction
"""
from __future__ import annotations

import io
import json
import os
import re
import shutil
import subprocess
import sys
import textwrap
import time
from contextlib import redirect_stdout
from pathlib import Path

import pytest

pytestmark = pytest.mark.windows_only

REPO = Path(__file__).resolve().parents[2]


def _schtasks(*args: str) -> tuple[int, str]:
    proc = subprocess.run(["schtasks", *args], capture_output=True, text=True, errors="replace", timeout=60)
    return proc.returncode, (proc.stdout or "") + (proc.stderr or "")


@pytest.fixture
def scratch(tmp_path, monkeypatch):
    """Scratch HERMES_HOME + scratch APPDATA (Startup folder) + a unique per-profile task name."""
    home = tmp_path / "hermes_home"
    home.mkdir()
    appdata = tmp_path / "appdata"
    appdata.mkdir()
    monkeypatch.setenv("HERMES_HOME", str(home))
    monkeypatch.setenv("APPDATA", str(appdata))
    monkeypatch.delenv("HERMES_PROFILE", raising=False)
    monkeypatch.delenv("HERMES_GATEWAY_INSTALL_START_ON_LOGIN", raising=False)
    monkeypatch.delenv("HERMES_GATEWAY_INSTALL_START_NOW", raising=False)
    monkeypatch.delenv("HERMES_NONINTERACTIVE", raising=False)
    from hermes_cli import gateway_windows as gw

    task_name = gw.get_task_name()
    assert task_name != "Hermes_Gateway", "scratch home must not alias the bare task name"
    _schtasks("/Delete", "/F", "/TN", task_name)
    yield gw, home, appdata, task_name
    _schtasks("/Delete", "/F", "/TN", task_name)


def _pre_hardening_xml(gw, task_name: str, launcher: Path) -> str:
    """The reporter's pre-hardening registration (#113670): v1.3, no RestartOnFailure, no logon Delay,
    old cmd.exe launcher arguments."""
    user = gw._resolve_task_user()
    user_principal = f"<UserId>{user}</UserId>" if user else ""
    return f"""<?xml version="1.0" encoding="UTF-16"?>
<Task version="1.3" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo><Description>{gw._TASK_DESCRIPTION}</Description></RegistrationInfo>
  <Triggers><LogonTrigger><Enabled>true</Enabled></LogonTrigger></Triggers>
  <Principals><Principal id="Author">{user_principal}<LogonType>InteractiveToken</LogonType><RunLevel>LeastPrivilege</RunLevel></Principal></Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <DisallowStartIfOnBatteries>false</DisallowStartIfOnBatteries>
    <StopIfGoingOnBatteries>false</StopIfGoingOnBatteries>
    <AllowHardTerminate>true</AllowHardTerminate>
    <StartWhenAvailable>true</StartWhenAvailable>
    <AllowStartOnDemand>true</AllowStartOnDemand>
    <Enabled>true</Enabled>
    <Hidden>false</Hidden>
    <ExecutionTimeLimit>PT0S</ExecutionTimeLimit>
    <Priority>7</Priority>
  </Settings>
  <Actions Context="Author"><Exec><Command>cmd.exe</Command><Arguments>/c "{launcher.with_suffix('.cmd')}"</Arguments></Exec></Actions>
</Task>
"""


def _register_stale_task(gw, task_name: str) -> None:
    script_path = gw._write_task_script()
    xml_path = script_path.with_suffix(".stale.xml")
    xml_path.write_text(_pre_hardening_xml(gw, task_name, script_path.with_suffix(".vbs")), encoding="utf-16", newline="")
    code, out = _schtasks("/Create", "/F", "/TN", task_name, "/XML", str(xml_path))
    assert code == 0, f"schtasks /Create of the stale fixture failed: {out}"
    assert gw.is_task_registered()


def _query_xml(task_name: str) -> str:
    proc = subprocess.run(["schtasks", "/Query", "/TN", task_name, "/XML"], capture_output=True, text=True,
                          encoding="utf-8", errors="replace", timeout=60)
    assert proc.returncode == 0, proc.stderr
    return proc.stdout


# ── #114945 ──────────────────────────────────────────────────────────────────────────────────────

def test_114945_status_reports_stale_scheduled_task_registration(scratch):
    gw, home, appdata, task_name = scratch
    _register_stale_task(gw, task_name)

    buf = io.StringIO()
    with redirect_stdout(buf):
        gw.status()
    out = buf.getvalue()
    print(out)
    assert "Scheduled Task registered" in out
    assert "⚠ Scheduled Task registration predates the current template" in out, out
    assert "RestartOnFailure" in out and "LogonTrigger Delay" in out and "version 1.3 vs 1.4" in out, out
    assert "Repair:" in out and "hermes gateway install" in out, out


def test_114945_start_reconciles_stale_scheduled_task(scratch, monkeypatch):
    gw, home, appdata, task_name = scratch
    _register_stale_task(gw, task_name)
    before = _query_xml(task_name)
    assert "RestartOnFailure" not in before and 'version="1.3"' in before

    spawns: list[int] = []
    monkeypatch.setattr(gw, "_spawn_detached", lambda *a, **k: spawns.append(4242) or 4242)
    monkeypatch.setattr(gw, "_report_gateway_start", lambda via: print(f"[stub] gateway start via {via}"))
    buf = io.StringIO()
    with redirect_stdout(buf):
        gw.start()
    out = buf.getvalue()
    print(out)
    after = _query_xml(task_name)
    assert spawns == [4242], out
    assert "Repairing outdated Scheduled Task registration" in out, out
    assert "RestartOnFailure" in after and 'version="1.4"' in after and "<Delay>PT30S</Delay>" in after, after
    assert "wscript.exe" in after, after


# ── #114863 ──────────────────────────────────────────────────────────────────────────────────────

def _run_start_in_child(home: Path, appdata: Path, extra_env: dict[str, str]) -> subprocess.CompletedProcess:
    """`hermes gateway start` semantics in a real child with a redirected (non-TTY) stdin. Only the
    detached gateway spawn is stubbed (recorded on stdout); schtasks / Startup writes are real."""
    code = textwrap.dedent(
        """
        import sys
        from hermes_cli import gateway_windows as gw
        gw._spawn_detached = lambda *a, **k: (print("[stub] _spawn_detached called") or 4242)
        gw._report_gateway_start = lambda via: print(f"[stub] _report_gateway_start {via}")
        gw.start()
        print("task_registered=%s startup_installed=%s" % (gw.is_task_registered(), gw.is_startup_entry_installed()))
        """
    )
    env = {**os.environ, "HERMES_HOME": str(home), "APPDATA": str(appdata), "PYTHONIOENCODING": "utf-8", **extra_env}
    env.pop("HERMES_GATEWAY_INSTALL_START_ON_LOGIN", None)
    env.update(extra_env)
    return subprocess.run([sys.executable, "-c", code], cwd=str(REPO), env=env, stdin=subprocess.DEVNULL,
                          capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=240)


def test_114863_noninteractive_start_does_not_install_login_autostart(scratch):
    gw, home, appdata, task_name = scratch
    startup_dir = gw._startup_dir()
    proc = _run_start_in_child(home, appdata, {})
    print(proc.stdout, proc.stderr)
    assert proc.returncode == 0, proc.stderr
    listing = sorted(p.name for p in startup_dir.iterdir()) if startup_dir.exists() else []
    print("startup listing:", listing)
    assert proc.stdout.count("[stub] _spawn_detached called") == 1, proc.stdout
    assert "Login auto-start not installed; add it later with: hermes gateway install" in proc.stdout, proc.stdout
    assert "Install it now so the gateway starts on login?" not in proc.stdout, proc.stdout
    assert "Gateway install did not complete" not in proc.stdout, proc.stdout
    assert "task_registered=False startup_installed=False" in proc.stdout, proc.stdout
    assert listing == [], listing
    code, _ = _schtasks("/Query", "/TN", task_name)
    assert code != 0, "a bare non-interactive start registered a real Scheduled Task"


def test_114863_start_on_login_override_still_installs(scratch):
    gw, home, appdata, task_name = scratch
    proc = _run_start_in_child(home, appdata, {"HERMES_GATEWAY_INSTALL_START_ON_LOGIN": "1"})
    print(proc.stdout, proc.stderr)
    assert proc.returncode == 0, proc.stderr
    assert "Install it now so the gateway starts on login?" not in proc.stdout, proc.stdout
    assert proc.stdout.count("[stub] _spawn_detached called") == 1, proc.stdout
    assert gw.is_task_registered() or gw.is_startup_entry_installed(), proc.stdout


# ── #114838 ──────────────────────────────────────────────────────────────────────────────────────

def test_114838_failed_startup_swap_leaves_no_tmp_debris(scratch):
    gw, home, appdata, task_name = scratch
    entry = gw.get_startup_entry_path()
    entry.parent.mkdir(parents=True, exist_ok=True)
    entry.write_text("rem locked\r\n", encoding="utf-8")
    script_path = gw._write_task_script()
    # A real Windows sharing violation: the existing login item is held open (no FILE_SHARE_DELETE),
    # so MoveFileEx over it fails with PermissionError — the reporter's failed swap (#114093).
    with open(entry, "r", encoding="utf-8"):
        with pytest.raises(OSError) as excinfo:
            gw._install_startup_entry(script_path)
    print("swap failure:", repr(excinfo.value))
    listing = sorted(p.name for p in entry.parent.iterdir())
    print("Startup listing after failed swap:", listing)
    assert not any(name.lower().endswith(".tmp") for name in listing), listing


def test_114838_uninstall_and_install_sweep_pre_fix_tmp_debris(scratch, monkeypatch):
    gw, home, appdata, task_name = scratch
    entry = gw.get_startup_entry_path()
    entry.parent.mkdir(parents=True, exist_ok=True)
    debris = entry.with_suffix(".tmp")
    debris.write_text("' leftover from a pre-fix failed swap\r\n", encoding="utf-8")

    buf = io.StringIO()
    with redirect_stdout(buf):
        gw.uninstall()
    print(buf.getvalue())
    assert not debris.exists(), sorted(p.name for p in entry.parent.iterdir())

    debris.write_text("' leftover again\r\n", encoding="utf-8")
    monkeypatch.setattr(gw, "_spawn_detached", lambda *a, **k: 4242)
    monkeypatch.setattr(gw, "_report_gateway_start", lambda via: None)
    buf = io.StringIO()
    with redirect_stdout(buf):
        gw.install(force=False, start_now=False, start_on_login=True)   # real schtasks path
    print(buf.getvalue())
    assert gw.is_task_registered(), buf.getvalue()
    assert not debris.exists(), sorted(p.name for p in entry.parent.iterdir())


# ── #114880 ──────────────────────────────────────────────────────────────────────────────────────

_GUARD_CHILD = textwrap.dedent(
    """
    import json, os, sys
    from gateway.status import acquire_gateway_runtime_lock, write_pid_file, get_running_pid
    assert acquire_gateway_runtime_lock(), "lock"
    write_pid_file()
    assert get_running_pid(cleanup_stale=False) == os.getpid(), "pid identity"
    from tools.process_registry import _is_supervised_gateway_process
    from tools.terminal_tool_guards import gateway_lifecycle_block
    class _Env:
        cwd = os.getcwd()
    results = {"supervised": _is_supervised_gateway_process()}
    for cmd in json.loads(sys.argv[3]):
        blocked = gateway_lifecycle_block(command=cmd, env=_Env(), env_type="local", cwd=os.getcwd(),
                                          workdir=None, session_key="b9-live")
        results[cmd] = blocked
    print("RESULT:" + json.dumps(results))
    """
)

_SELF_KILLS = [
    "taskkill /F /IM python.exe",
    'taskkill /F /FI "IMAGENAME eq python.exe"',
    "Stop-Process -Name python -Force",
    "pkill -9 python3",
    "hermes.exe gateway stop",
]
_CONTROLS = [
    "taskkill /F /IM agent-browser.exe /T",
    "taskkill /F /PID 46544",
    "dir",
]


def test_114880_scheduled_task_gateway_blocks_interpreter_image_kills(scratch):
    gw, home, appdata, task_name = scratch
    env = {**os.environ, "HERMES_HOME": str(home), "_HERMES_GATEWAY": "1", "PYTHONIOENCODING": "utf-8"}
    for key, value in gw._GATEWAY_ENV:     # exactly what the Scheduled-Task launcher exports
        env[key] = value
    env.pop("INVOCATION_ID", None)
    env.pop("XPC_SERVICE_NAME", None)
    env["PYTHONPATH"] = str(REPO)
    # The gateway identity check reads the LIVE command line, so the child must look like the real
    # runtime (`python .../hermes_cli/main.py gateway run`) — the same shape the Scheduled Task launches.
    child_main = home / "launcher" / "hermes_cli" / "main.py"
    child_main.parent.mkdir(parents=True)
    child_main.write_text(_GUARD_CHILD, encoding="utf-8")
    proc = subprocess.run([sys.executable, str(child_main), "gateway", "run", json.dumps(_SELF_KILLS + _CONTROLS)],
                          cwd=str(REPO), env=env, capture_output=True, text=True, encoding="utf-8", errors="replace",
                          timeout=240)
    print(proc.stdout, proc.stderr)
    assert proc.returncode == 0, proc.stderr
    results = json.loads(proc.stdout.split("RESULT:", 1)[1].strip().splitlines()[0])
    assert results["supervised"] is True, results
    for cmd in _SELF_KILLS:
        assert results[cmd], f"not blocked inside a Scheduled-Task gateway: {cmd!r}"
    for cmd in _CONTROLS:
        assert results[cmd] is None, f"control wrongly blocked: {cmd!r} -> {results[cmd]}"
    assert "Blocked" in results["taskkill /F /IM python.exe"]
    assert "interpreter" in results["taskkill /F /IM python.exe"].lower()


# ── #114857 ──────────────────────────────────────────────────────────────────────────────────────

def _task(task_id: str, workspace: Path):
    from hermes_cli.kanban_db import Task

    return Task(id=task_id, title="b9 live", body=None, assignee="default", status="running", priority=1,
                created_by=None, created_at=int(time.time()), started_at=None, completed_at=None,
                workspace_kind="dir", workspace_path=str(workspace), claim_lock=None, claim_expires=None, tenant=None)


def test_114857_windows_worker_exit_codes_reach_the_dispatcher(scratch, monkeypatch, tmp_path):
    gw, home, appdata, task_name = scratch
    from hermes_cli import kanban_db as kb
    from hermes_cli import kanban_db_dispatch as kd

    assert kb._IS_WINDOWS
    workspace = tmp_path / "ws"
    workspace.mkdir()
    exits = {"rate": 75, "fail": 3}

    def fake_worker_argv(task, profile_arg, hermes_home):
        if task.id == "live":
            return [sys.executable, "-c", "import time; time.sleep(120)"]
        return [sys.executable, "-c", f"import sys; sys.exit({exits[task.id]})"]

    monkeypatch.setattr(kd, "_worker_argv", fake_worker_argv)
    pids = {tid: kd._default_spawn(_task(tid, workspace), str(workspace)) for tid in ("rate", "fail", "live")}
    print("spawned:", pids)
    assert all(pids.values())
    deadline = time.monotonic() + 30
    reaped: set[int] = set()
    while time.monotonic() < deadline and not {pids["rate"], pids["fail"]} <= reaped:
        reaped |= set(kd.reap_worker_zombies())
        time.sleep(0.2)
    try:
        print("reaped:", sorted(reaped))
        assert {pids["rate"], pids["fail"]} <= reaped, f"reap_worker_zombies never reaped the exited workers: {reaped}"
        assert pids["live"] not in reaped
        assert kd._classify_worker_exit(pids["rate"]) == ("rate_limited", 75)
        assert kd._classify_worker_exit(pids["fail"]) == ("nonzero_exit", 3)
        assert kd._pid_alive(pids["live"])
    finally:
        subprocess.run(["taskkill", "/F", "/PID", str(pids["live"])], capture_output=True)


# ── #114758 ──────────────────────────────────────────────────────────────────────────────────────

def _emitted_powershell_scripts(hermes_home: Path) -> dict[str, str]:
    """Render the two `const script = [...]`.join(';') arrays of windows-remote-lifecycle.ts exactly as
    the desktop does (node evaluates the literal array; psLiteral/explicit/hermesHome as in the file)."""
    source = (REPO / "apps" / "desktop" / "electron" / "windows-remote-lifecycle.ts").read_text(encoding="utf-8")
    blocks = re.findall(r"const script = (\[.*?\])\.join\(';'\)", source, flags=re.S)
    assert len(blocks) >= 2, len(blocks)   # the first two are probeWindowsRemote / windowsUpdateMarkerProbeCommand
    node = shutil.which("node")
    assert node, "node is required on the runner"
    scripts = {}
    for label, block in zip(("probeWindowsRemote", "windowsUpdateMarkerProbeCommand"), blocks[:2]):
        js = (
            "function psLiteral(v){return `'${String(v).replace(/'/g, \"''\")}'`}\n"
            "const hermesHome = process.argv[1]; const explicit = psLiteral('');\n"
            f"const script = {block}.join(';');\n"
            "process.stdout.write(script);"
        )
        proc = subprocess.run([node, "-e", js, str(hermes_home)], capture_output=True, text=True, encoding="utf-8", timeout=60)
        assert proc.returncode == 0, proc.stderr
        scripts[label] = proc.stdout
    return scripts


def _run_encoded_powershell(script: str, env: dict[str, str]) -> subprocess.CompletedProcess:
    import base64

    encoded = base64.b64encode(script.encode("utf-16-le")).decode("ascii")
    return subprocess.run(
        ["powershell.exe", "-NoProfile", "-NonInteractive", "-ExecutionPolicy", "Bypass", "-EncodedCommand", encoded],
        capture_output=True, text=True, encoding="utf-8", errors="replace", env=env, timeout=180,
    )


def test_114758_desktop_windows_probe_scripts_parse_in_real_powershell(scratch, tmp_path):
    gw, home, appdata, task_name = scratch
    scripts = _emitted_powershell_scripts(home)
    env = {**os.environ, "HERMES_HOME": str(home)}
    results = {}
    for label, script in scripts.items():
        proc = _run_encoded_powershell(script, env)
        results[label] = proc
        print(f"--- {label}: rc={proc.returncode}\nSTDOUT:\n{proc.stdout}\nSTDERR:\n{proc.stderr}")
    for label, proc in results.items():
        combined = proc.stdout + proc.stderr
        assert "ParserError" not in combined and "Unexpected token" not in combined, f"{label} did not parse: {combined}"
    probe = results["probeWindowsRemote"]
    # Either outcome proves the script parsed and RAN: a found hermes.exe yields the JSON probe result,
    # none yields the script's own "not installed" error.
    if probe.returncode == 0:
        assert json.loads(probe.stdout.strip())["os"] == "Windows", probe.stdout
    else:
        assert "Hermes is not installed on the remote Windows host." in probe.stderr, probe.stderr
    marker = results["windowsUpdateMarkerProbeCommand"]
    # Pre-existing behaviour of the marker script itself (e.g. `$home=` assignment) is not this PR's
    # observable; the PR's claim is that both scripts PARSE (asserted above). Record the run outcome.
    print("marker probe:", marker.returncode, marker.stdout.strip())
    if marker.returncode == 0:
        assert marker.stdout.strip() == "CLEAR", marker.stdout


# ── #114782 ──────────────────────────────────────────────────────────────────────────────────────

def test_114782_profile_clone_keeps_real_ntfs_junction(tmp_path, monkeypatch):
    import _winapi
    import stat

    from hermes_cli.profiles import create_profile

    monkeypatch.setattr(Path, "home", lambda: tmp_path)
    default_home = tmp_path / ".hermes"
    default_home.mkdir()
    monkeypatch.setenv("HERMES_HOME", str(default_home))
    external = tmp_path / "agents-skills"
    (external / "foo").mkdir(parents=True)
    (external / "foo" / "SKILL.md").write_text("# external foo\n", encoding="utf-8")
    (default_home / "skills" / "local").mkdir(parents=True)
    (default_home / "skills" / "local" / "SKILL.md").write_text("# local\n", encoding="utf-8")
    (default_home / "config.yaml").write_text(f"model: test\nskills:\n  external_dirs:\n    - {external}\n")
    _winapi.CreateJunction(str(external / "foo"), str(default_home / "skills" / "foo"))

    clone = create_profile("clone", clone_config=True, no_alias=True)
    foo = clone / "skills" / "foo"
    st = os.lstat(foo)
    print("clone skills/foo reparse tag:", hex(getattr(st, "st_reparse_tag", 0)))
    assert st.st_reparse_tag == stat.IO_REPARSE_TAG_MOUNT_POINT, "clone holds a physical copy, not a junction"
    assert foo.resolve() == (external / "foo").resolve()
    assert (clone / "skills" / "local" / "SKILL.md").is_file()
    from tools.skills_tool import _collect_skill_candidates

    assert len(_collect_skill_candidates("foo", None, [clone / "skills", external])) == 1
