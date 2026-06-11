"""Windows installer (v0.14) — pure builders, exact.

The path/command/registry builders are deterministic and security/uninstall-
relevant, so they're pinned exactly here (always run, every platform). The
full install->uninstall round trip is a separate env-gated live test
(test_installer_live, Windows only) so unit runs never touch the real venv,
Start Menu, or registry.
"""

import os

from sentinel_slice import installer
from sentinel_slice.installer import (
    DISPLAY_NAME,
    default_target,
    self_delete_command,
    shortcut_path,
    shortcut_powershell,
    uninstall_key_values,
    venv_python,
)

ENV = {
    "LOCALAPPDATA": r"C:\Users\u\AppData\Local",
    "APPDATA": r"C:\Users\u\AppData\Roaming",
}


def test_default_target_under_localappdata():
    assert default_target(ENV) == os.path.join(
        r"C:\Users\u\AppData\Local", "Programs", "SentinelLoop")


def test_venv_python_console_vs_windowed():
    t = r"C:\app"
    assert venv_python(t) == os.path.join(t, "venv", "Scripts", "python.exe")
    assert venv_python(t, windowed=True) == os.path.join(
        t, "venv", "Scripts", "pythonw.exe")


def test_shortcut_path_in_start_menu():
    assert shortcut_path(ENV) == os.path.join(
        r"C:\Users\u\AppData\Roaming", "Microsoft", "Windows", "Start Menu",
        "Programs", DISPLAY_NAME + ".lnk")


def test_shortcut_powershell_targets_launcher():
    t = r"C:\app"
    link = r"C:\link.lnk"
    ps = shortcut_powershell(t, link)
    assert link in ps
    assert os.path.join(t, "venv", "Scripts", "sentinel-loop.exe") in ps
    # Fallback uses the windowed interpreter + the module form.
    assert os.path.join(t, "venv", "Scripts", "pythonw.exe") in ps
    assert "-m sentinel_slice.app.shell" in ps
    assert "CreateShortcut" in ps and "Save()" in ps


def test_uninstall_key_values_exact():
    vals = uninstall_key_values(r"C:\app", "0.14.0")
    assert vals == {
        "DisplayName": "Sentinel Loop",
        "DisplayVersion": "0.14.0",
        "Publisher": "Sentinel Loop (unsigned)",
        "InstallLocation": r"C:\app",
        "UninstallString": os.path.join(
            r"C:\app", "venv", "Scripts", "python.exe")
        + " -m sentinel_slice.installer uninstall",
        "NoModify": 1,
        "NoRepair": 1,
        "EstimatedSize": 0,
    }


def test_self_delete_command_removes_target():
    cmd = self_delete_command(r"C:\app")
    assert "rmdir /s /q" in cmd
    assert r"C:\app" in cmd
    assert "ping" in cmd  # the wait so the running exe's dir is free


def test_install_and_uninstall_use_injected_registry(tmp_path, monkeypatch):
    """The flows write/delete through the injected registry hooks and report
    the actions — proven without a real venv or HKCU (skip_venv + fakes)."""
    if os.name != "nt":
        # default_target/shortcut still resolve; we just drive the injected
        # registry + skip the windows-only guard by monkeypatching platform.
        monkeypatch.setattr(installer.sys, "platform", "win32")

    target = str(tmp_path / "app")
    written = {}
    deleted = []

    def fake_write(key, values):
        written[key] = values

    def fake_delete(key):
        deleted.append(key)
        return True

    # skip_venv + no wheel + no shortcut: only init (subprocess) + registry.
    # Stub the init subprocess so no real process spawns.
    monkeypatch.setattr(installer, "_run",
                        lambda *a, **k: type("R", (), {"returncode": 0, "stderr": ""})())
    report = installer.install(
        target=target, version="0.14.0", skip_venv=True, make_shortcut=False,
        enable_sandbox=False, registry=fake_write, uninstall_key="TESTKEY")
    assert "registry" in report["actions"] and "init" in report["actions"]
    assert written["TESTKEY"]["DisplayName"] == "Sentinel Loop"

    out = installer.uninstall(
        target=target, uninstall_key="TESTKEY", registry_delete=fake_delete,
        remove_shortcut=False, teardown_sandbox=False,
        schedule_self_delete=False)
    assert deleted == ["TESTKEY"]
    assert "registry" in out["actions"]
