"""Installed-app behavior (v0.10) — the app home steers every entry point.

The real claim under test: after `sentinel-init`, running `sentinel-mcp` from
ANY working directory uses the app home's key and ledger (writing nothing to
the cwd and nothing near the package), and the chain it produces verifies
standalone against the app home's public key. Plus: the permissions editor's
default file moves into the app home, and a dev checkout with NO initialized
home keeps the historical defaults.
"""

import json
import os
import subprocess
import sys
from pathlib import Path

from sentinel_slice import apphome
from sentinel_slice.init_app import main as init_main

SENTINEL_DIR = Path(__file__).resolve().parents[1]
REPO_ROOT = Path(__file__).resolve().parents[2]
VERIFIER = SENTINEL_DIR / "verify_ledger.py"

DRAFT_TOOL = "cap_email_draft_reply_v1"


def test_gateway_uses_app_home_from_any_cwd(tmp_path):
    home = str(tmp_path / "home")
    assert init_main(["--home", home], print_fn=lambda *_: None) == 0
    cwd = tmp_path / "somewhere-else"
    cwd.mkdir()

    env = dict(os.environ)
    env["SENTINEL_HOME"] = home
    env["PYTHONPATH"] = str(REPO_ROOT)
    lines = (
        json.dumps({"jsonrpc": "2.0", "id": 1, "method": "initialize",
                    "params": {}}) + "\n"
        + json.dumps({"jsonrpc": "2.0", "id": 2, "method": "tools/call",
                      "params": {"name": DRAFT_TOOL,
                                 "arguments": {"thread_id": "user.kenji/t-001"}}})
        + "\n")
    proc = subprocess.run(
        [sys.executable, "-m", "sentinel_slice.mcp_gateway"],
        input=lines, capture_output=True, text=True, cwd=str(cwd), env=env,
        timeout=120)

    assert proc.returncode == 0, proc.stderr
    assert "using app home " + home in proc.stderr
    responses = [json.loads(ln) for ln in proc.stdout.splitlines() if ln.strip()]
    assert len(responses) == 2
    call = responses[1]["result"]
    assert call["isError"] is False
    assert call["content"][0]["text"].startswith("Re: Acme Corp Q3 onboarding")

    # State landed in the app home — and ONLY there.
    assert os.path.isfile(apphome.ledger_path(home))
    assert os.listdir(cwd) == []  # nothing written to the cwd
    # The draft went to the home's window dir.
    assert len(os.listdir(apphome.window_root(home))) == 1

    # The chain verifies standalone against the app home's public key.
    verify = subprocess.run(
        [sys.executable, str(VERIFIER), apphome.ledger_path(home),
         apphome.public_key_path(home)],
        capture_output=True, text=True, timeout=60)
    assert verify.returncode == 0, (verify.stdout, verify.stderr)
    assert verify.stdout.strip() == "OK verified=1"


def test_explicit_ledger_arg_beats_app_home(tmp_path):
    home = str(tmp_path / "home")
    assert init_main(["--home", home], print_fn=lambda *_: None) == 0
    explicit = tmp_path / "explicit.db"

    env = dict(os.environ)
    env["SENTINEL_HOME"] = home
    env["PYTHONPATH"] = str(REPO_ROOT)
    line = json.dumps({"jsonrpc": "2.0", "id": 1, "method": "tools/call",
                       "params": {"name": DRAFT_TOOL,
                                  "arguments": {"thread_id": "user.kenji/t-001"}}})
    proc = subprocess.run(
        [sys.executable, "-m", "sentinel_slice.mcp_gateway",
         "--ledger", str(explicit)],
        input=line + "\n", capture_output=True, text=True,
        cwd=str(tmp_path), env=env, timeout=120)

    assert proc.returncode == 0, proc.stderr
    assert explicit.is_file()
    assert not os.path.isfile(apphome.ledger_path(home))


def test_permissions_default_path_follows_initialized_home(tmp_path, monkeypatch):
    from sentinel_slice.consumer.permissions import (
        DEFAULT_PREFS_PATH,
        default_prefs_path,
    )

    home = str(tmp_path / "home")
    monkeypatch.setenv("SENTINEL_HOME", home)
    # Uninitialized home -> the historical cwd default, unchanged.
    assert default_prefs_path() == DEFAULT_PREFS_PATH

    assert init_main(["--home", home], print_fn=lambda *_: None) == 0
    assert default_prefs_path() == os.path.join(home, "permissions.json")
