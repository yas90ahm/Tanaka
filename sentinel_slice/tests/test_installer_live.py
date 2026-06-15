# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Yasir Qureshi
"""Installer live round trip (v0.14) — real registry, shortcut, app home.

Env-gated (SENTINEL_TEST_INSTALLER=1, Windows): drives the REAL install() and
uninstall() against a TEMP target, a TEMP Start Menu / APPDATA, a TEMP app
home, and a SCRATCH HKCU subkey — so it writes nothing the user would see.
Asserts the install produced the shortcut, the exact Add/Remove Programs
values (read back from the registry), and an initialized app home; and that
uninstall removed all three and the install dir. Uses the current interpreter
(skip_venv) and no sandbox so it stays fast — venv/pip and the AppContainer
each have their own proofs.
"""

import os
import sys

import pytest

_GATED = os.environ.get("SENTINEL_TEST_INSTALLER") == "1"
_WIN = sys.platform == "win32"

pytestmark = pytest.mark.skipif(
    not (_GATED and _WIN),
    reason="real install round trip; set SENTINEL_TEST_INSTALLER=1 on Windows")

# A scratch HKCU key — NOT the real Add/Remove Programs location.
TEST_KEY = r"Software\SentinelLoopTest\Uninstall\SentinelLoop"


def _read_key(key_path):
    import winreg
    out = {}
    key = winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path)
    try:
        i = 0
        while True:
            try:
                name, value, _ = winreg.EnumValue(key, i)
            except OSError:
                break
            out[name] = value
            i += 1
    finally:
        winreg.CloseKey(key)
    return out


def _key_exists(key_path):
    import winreg
    try:
        winreg.CloseKey(winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path))
        return True
    except FileNotFoundError:
        return False


def test_install_then_uninstall_round_trip(tmp_path):
    from sentinel_slice import apphome, installer

    target = str(tmp_path / "Programs" / "SentinelLoop")
    home = str(tmp_path / "home")
    env = {
        "APPDATA": str(tmp_path / "Roaming"),
        "LOCALAPPDATA": str(tmp_path / "Local"),
        "SENTINEL_HOME": home,
    }

    report = installer.install(
        target=target, version="0.14.0", environ=env, skip_venv=True,
        pip_python=sys.executable, make_shortcut=True, enable_sandbox=False,
        uninstall_key=TEST_KEY)

    try:
        assert "init" in report["actions"]
        assert "registry" in report["actions"]
        # The app home was set up (keypair present).
        assert apphome.is_initialized(home)
        # Start Menu shortcut landed in the temp APPDATA.
        link = installer.shortcut_path(env)
        assert os.path.isfile(link), report
        # Add/Remove Programs values are exactly what the builder specified.
        vals = _read_key(TEST_KEY)
        assert vals["DisplayName"] == "Sentinel Loop"
        assert vals["DisplayVersion"] == "0.14.0"
        assert vals["InstallLocation"] == target
        assert vals["NoModify"] == 1
    finally:
        out = installer.uninstall(
            target=target, environ=env, uninstall_key=TEST_KEY,
            teardown_sandbox=False, schedule_self_delete=False)

    # Everything is gone.
    assert not os.path.isfile(installer.shortcut_path(env))
    assert not _key_exists(TEST_KEY)
    assert not os.path.isdir(target)
    assert "registry" in out["actions"] and "deleted" in out["actions"]
