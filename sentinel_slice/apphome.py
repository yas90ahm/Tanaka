# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Yasir Qureshi
"""App home — where an INSTALLED Sentinel keeps its state.

The dev checkout keeps state inside the repo (sentinel_slice/keys, a cwd
ledger.db). That is wrong for `pip install sentinel-slice`: site-packages may
be read-only, is wiped on upgrade, and is no place for a private key. An
installed app keeps its state in a per-user directory:

    Windows  %APPDATA%\\SentinelLoop
    macOS    ~/Library/Application Support/SentinelLoop
    Linux    $XDG_DATA_HOME/sentinel-loop  (default ~/.local/share/sentinel-loop)

`SENTINEL_HOME` overrides all of those (tests, portable installs, several
profiles side by side).

Resolution precedence is explicit and boring on purpose:

    1. an explicit CLI argument always wins;
    2. else, if the app home is INITIALIZED (sentinel-init put a private key
       there), the app home provides the default;
    3. else fall back to the dev-checkout behavior unchanged (package keys,
       cwd ledger) — so a git clone keeps working exactly as before.

"Initialized" is defined by one fact only: the cashier private key exists in
the home's keys dir. No marker files, no config format.

stdlib only. This module computes paths; it loads no keys and opens no ledger.
"""

import os
import sys
from dataclasses import dataclass

ENV_HOME = "SENTINEL_HOME"

PRIVATE_KEY_FILENAME = "cashier_ed25519_private.pem"
PUBLIC_KEY_FILENAME = "cashier_ed25519_public.pem"


def default_app_home(environ=None, platform=None) -> str:
    """The per-user Sentinel home for this platform (absolute path).
    `environ` / `platform` are injectable for tests; defaults are the real
    process environment and sys.platform."""
    env = os.environ if environ is None else environ
    plat = sys.platform if platform is None else platform

    override = env.get(ENV_HOME)
    if override:
        return os.path.abspath(override)

    if plat == "win32":
        roaming = env.get("APPDATA") or os.path.join(
            os.path.expanduser("~"), "AppData", "Roaming")
        return os.path.join(roaming, "SentinelLoop")
    if plat == "darwin":
        return os.path.join(
            os.path.expanduser("~"), "Library", "Application Support",
            "SentinelLoop")
    data_home = env.get("XDG_DATA_HOME") or os.path.join(
        os.path.expanduser("~"), ".local", "share")
    return os.path.join(data_home, "sentinel-loop")


# ---- the fixed layout inside a home ----

def keys_dir(home: str) -> str:
    return os.path.join(home, "keys")


def private_key_path(home: str) -> str:
    return os.path.join(keys_dir(home), PRIVATE_KEY_FILENAME)


def public_key_path(home: str) -> str:
    return os.path.join(keys_dir(home), PUBLIC_KEY_FILENAME)


def ledger_path(home: str) -> str:
    return os.path.join(home, "ledger.db")


def window_root(home: str) -> str:
    return os.path.join(home, "window")


def custom_capabilities_dir(home: str) -> str:
    return os.path.join(home, "capabilities_custom")


def preferences_path(home: str) -> str:
    return os.path.join(home, "permissions.json")


def sandbox_marker_path(home: str) -> str:
    return os.path.join(home, "sandbox.json")


def read_sandbox_backend(home: str) -> str | None:
    """The containment backend the user opted into (e.g. "appcontainer"), or
    None if none was set up. A small JSON marker written by the sandbox
    setup; absent/garbage -> None (fall back to the subprocess contract)."""
    import json
    try:
        with open(sandbox_marker_path(home), "r", encoding="utf-8-sig") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return None
    backend = data.get("backend") if isinstance(data, dict) else None
    return backend if isinstance(backend, str) and backend else None


def write_sandbox_backend(home: str, backend: str) -> str:
    """Record the chosen containment backend in the app home. Returns the
    marker path."""
    import json
    path = sandbox_marker_path(home)
    with open(path, "w", encoding="utf-8") as fh:
        json.dump({"backend": backend}, fh, indent=2, sort_keys=True)
        fh.write("\n")
    return path


def is_initialized(home: str) -> bool:
    """True iff sentinel-init has produced a credential in this home."""
    return os.path.isfile(private_key_path(home))


def ensure_app_home(home: str) -> str:
    """Create the home directory layout (idempotent). Returns the home path.
    Writes no keys and no files — only directories."""
    for d in (home, keys_dir(home), window_root(home),
              custom_capabilities_dir(home)):
        os.makedirs(d, exist_ok=True)
    return home


@dataclass(frozen=True)
class RuntimePaths:
    """Where one process run should keep/find its state.

    Fields that are None mean "use the dev-checkout default" (the package
    keys dir, the package window dir, the package custom-capabilities dir,
    the cwd preferences file) — callers keep their pre-app-home behavior for
    a plain git clone with no initialized home."""
    home: str
    initialized: bool
    ledger: str
    keys_dir: str | None
    window_root: str | None
    custom_capabilities_dir: str | None
    preferences_path: str | None


def resolve_runtime_paths(
    *,
    ledger: str | None = None,
    keys: str | None = None,
    window: str | None = None,
    home: str | None = None,
    environ=None,
    platform=None,
) -> RuntimePaths:
    """Apply the precedence (explicit arg > initialized app home > dev
    fallback) and return the concrete paths for this run."""
    resolved_home = home if home is not None else default_app_home(
        environ=environ, platform=platform)
    initialized = is_initialized(resolved_home)

    if initialized:
        return RuntimePaths(
            home=resolved_home,
            initialized=True,
            ledger=ledger if ledger is not None else ledger_path(resolved_home),
            keys_dir=keys if keys is not None else keys_dir(resolved_home),
            window_root=window if window is not None else window_root(resolved_home),
            custom_capabilities_dir=custom_capabilities_dir(resolved_home),
            preferences_path=preferences_path(resolved_home),
        )
    return RuntimePaths(
        home=resolved_home,
        initialized=False,
        ledger=ledger if ledger is not None else "ledger.db",
        keys_dir=keys,
        window_root=window,
        custom_capabilities_dir=None,
        preferences_path=None,
    )
