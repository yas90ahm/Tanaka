"""App home (v0.10) — per-user state for an installed Sentinel.

Pins exact paths for every platform branch, the SENTINEL_HOME override, the
"initialized = private key exists" definition, the directory layout
ensure_app_home creates, and the full resolution precedence:
explicit CLI arg > initialized app home > dev-checkout fallback (None /
cwd ledger.db — i.e. behavior identical to pre-v0.10).
"""

import os

from sentinel_slice.apphome import (
    RuntimePaths,
    custom_capabilities_dir,
    default_app_home,
    ensure_app_home,
    is_initialized,
    keys_dir,
    ledger_path,
    preferences_path,
    private_key_path,
    public_key_path,
    resolve_runtime_paths,
    window_root,
)


# ---- default_app_home: every branch, exact ----

def test_sentinel_home_env_overrides_everything():
    home = default_app_home(
        environ={"SENTINEL_HOME": r"X:\sl-home", "APPDATA": r"C:\ignored"},
        platform="win32")
    assert home == os.path.abspath(r"X:\sl-home")


def test_windows_uses_appdata_roaming():
    home = default_app_home(
        environ={"APPDATA": r"C:\Users\u\AppData\Roaming"}, platform="win32")
    assert home == r"C:\Users\u\AppData\Roaming" + os.sep + "SentinelLoop"


def test_windows_without_appdata_falls_back_to_profile():
    home = default_app_home(environ={}, platform="win32")
    assert home == os.path.join(
        os.path.expanduser("~"), "AppData", "Roaming", "SentinelLoop")


def test_macos_application_support():
    home = default_app_home(environ={}, platform="darwin")
    assert home == os.path.join(
        os.path.expanduser("~"), "Library", "Application Support",
        "SentinelLoop")


def test_linux_xdg_data_home():
    home = default_app_home(
        environ={"XDG_DATA_HOME": "/x/data"}, platform="linux")
    assert home == os.path.join("/x/data", "sentinel-loop")


def test_linux_default_local_share():
    home = default_app_home(environ={}, platform="linux")
    assert home == os.path.join(
        os.path.expanduser("~"), ".local", "share", "sentinel-loop")


# ---- the fixed layout ----

def test_layout_paths_are_exact_joins():
    home = os.path.join("h", "ome")
    assert keys_dir(home) == os.path.join(home, "keys")
    assert private_key_path(home) == os.path.join(
        home, "keys", "cashier_ed25519_private.pem")
    assert public_key_path(home) == os.path.join(
        home, "keys", "cashier_ed25519_public.pem")
    assert ledger_path(home) == os.path.join(home, "ledger.db")
    assert window_root(home) == os.path.join(home, "window")
    assert custom_capabilities_dir(home) == os.path.join(
        home, "capabilities_custom")
    assert preferences_path(home) == os.path.join(home, "permissions.json")


def test_ensure_app_home_creates_exactly_the_layout_dirs(tmp_path):
    home = str(tmp_path / "home")
    returned = ensure_app_home(home)
    assert returned == home
    assert sorted(os.listdir(home)) == [
        "capabilities_custom", "keys", "window"]
    # Idempotent: a second call neither fails nor adds anything.
    ensure_app_home(home)
    assert sorted(os.listdir(home)) == [
        "capabilities_custom", "keys", "window"]


def test_initialized_means_private_key_exists(tmp_path):
    home = str(tmp_path / "home")
    ensure_app_home(home)
    assert is_initialized(home) is False
    with open(private_key_path(home), "wb") as fh:
        fh.write(b"PEM")
    assert is_initialized(home) is True


# ---- resolution precedence ----

def _initialized_home(tmp_path) -> str:
    home = str(tmp_path / "home")
    ensure_app_home(home)
    with open(private_key_path(home), "wb") as fh:
        fh.write(b"PEM")
    return home


def test_uninitialized_home_resolves_to_dev_fallbacks(tmp_path):
    home = str(tmp_path / "nothing-here")
    paths = resolve_runtime_paths(home=home)
    assert paths == RuntimePaths(
        home=home, initialized=False, ledger="ledger.db", keys_dir=None,
        window_root=None, custom_capabilities_dir=None, preferences_path=None)


def test_initialized_home_provides_every_default(tmp_path):
    home = _initialized_home(tmp_path)
    paths = resolve_runtime_paths(home=home)
    assert paths == RuntimePaths(
        home=home, initialized=True,
        ledger=os.path.join(home, "ledger.db"),
        keys_dir=os.path.join(home, "keys"),
        window_root=os.path.join(home, "window"),
        custom_capabilities_dir=os.path.join(home, "capabilities_custom"),
        preferences_path=os.path.join(home, "permissions.json"))


def test_explicit_args_beat_an_initialized_home(tmp_path):
    home = _initialized_home(tmp_path)
    paths = resolve_runtime_paths(
        ledger="elsewhere.db", keys=r"k\dir", window=r"w\dir", home=home)
    assert paths.ledger == "elsewhere.db"
    assert paths.keys_dir == r"k\dir"
    assert paths.window_root == r"w\dir"
    # Home still supplies what was not explicitly given.
    assert paths.custom_capabilities_dir == os.path.join(
        home, "capabilities_custom")
    assert paths.preferences_path == os.path.join(home, "permissions.json")
    assert paths.initialized is True


def test_explicit_args_pass_through_when_uninitialized(tmp_path):
    home = str(tmp_path / "nothing-here")
    paths = resolve_runtime_paths(ledger="my.db", keys="kk", home=home)
    assert paths.ledger == "my.db"
    assert paths.keys_dir == "kk"
    assert paths.window_root is None


def test_home_argument_defaults_to_env_override(tmp_path):
    home = _initialized_home(tmp_path)
    paths = resolve_runtime_paths(environ={"SENTINEL_HOME": home})
    assert paths.home == os.path.abspath(home)
    assert paths.initialized is True
