# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Yasir Qureshi
"""The door's tkinter shell (v0.13).

The shell is thin, so most coverage lives in test_app_model. Here: the window
actually builds (all three screens, refreshers present) and a refresh after a
model change doesn't raise — under an env-gated real display, like the
on-device dialog test. Off-display it skips.
"""

import os

import pytest

from sentinel_slice import apphome
from sentinel_slice.app.model import AppModel

_GUI = os.environ.get("SENTINEL_TEST_GUI") == "1"


@pytest.mark.skipif(not _GUI, reason="real tkinter window; set SENTINEL_TEST_GUI=1")
def test_shell_builds_three_screens(tmp_path):
    import tkinter as tk

    from sentinel_slice.app.shell import build_app

    home = str(tmp_path / "home")
    apphome.ensure_app_home(home)
    root = tk.Tk()
    try:
        refreshers = build_app(root, AppModel(home))
        assert set(refreshers) == {"connect", "perms", "activity"}
        # Re-rendering each screen must not raise (covers the model calls the
        # buttons trigger).
        for fn in refreshers.values():
            fn()
    finally:
        root.destroy()


@pytest.mark.skipif(not _GUI, reason="real tkinter window; set SENTINEL_TEST_GUI=1")
def test_run_opens_and_autocloses(tmp_path, monkeypatch):
    from sentinel_slice.app.shell import run

    # Force sandbox-unavailable so first-run readiness does NOT grant ACLs
    # (icacls) during a GUI test; we're exercising init + window, not the
    # AppContainer (that has its own gated test).
    monkeypatch.setattr(
        "sentinel_slice.chef.appcontainer.is_available", lambda: False)
    home = str(tmp_path / "home")
    rc = run(home=home, _test_autoclose_ms=200)
    assert rc == 0
    assert apphome.is_initialized(home)
