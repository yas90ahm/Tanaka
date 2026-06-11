"""Windows per-user installer — what turns a download into an installed app.

This is the real install/uninstall flow a non-technical user gets: a private
Python environment under %LOCALAPPDATA%, the package installed into it, the
app set up (home + keypair + AppContainer), a Start Menu shortcut, and a
genuine **Add/Remove Programs** entry so it uninstalls like any other app.
No admin (per-user / HKCU only), no terminal once it's running.

The path/command/registry builders are PURE and exactly tested; install() and
uninstall() perform the side effects. The registry hive and target are
injectable so tests run against a scratch key and temp dir, never the real
install.

HONEST SCOPE — read this. This produces a per-user install and a working
uninstaller, but the bundle is **UNSIGNED**: with no code-signing certificate,
Windows SmartScreen will warn ("unknown publisher") on first run, and there is
no auto-update. A shipping product needs an Authenticode cert (and ideally an
MSI/MSIX); that is identity + money, not code. Everything here is the
mechanism a signed installer would wrap.
"""

import os
import subprocess
import sys

APP_NAME = "SentinelLoop"
DISPLAY_NAME = "Sentinel Loop"
# HKCU uninstall key the real Add/Remove Programs reads. Tests pass a scratch
# subkey instead of writing the user's real hive.
UNINSTALL_KEY = r"Software\Microsoft\Windows\CurrentVersion\Uninstall\SentinelLoop"


def default_target(environ=None) -> str:
    """Where the app installs for this user (no admin): under LOCALAPPDATA."""
    env = os.environ if environ is None else environ
    local = env.get("LOCALAPPDATA") or os.path.join(
        os.path.expanduser("~"), "AppData", "Local")
    return os.path.join(local, "Programs", APP_NAME)


def venv_python(target: str, *, windowed=False) -> str:
    """The launcher inside the installed venv. `windowed` -> pythonw.exe (no
    console window), used by the Start Menu shortcut."""
    exe = "pythonw.exe" if windowed else "python.exe"
    return os.path.join(target, "venv", "Scripts", exe)


def start_menu_dir(environ=None) -> str:
    env = os.environ if environ is None else environ
    appdata = env.get("APPDATA") or os.path.join(
        os.path.expanduser("~"), "AppData", "Roaming")
    return os.path.join(
        appdata, "Microsoft", "Windows", "Start Menu", "Programs")


def shortcut_path(environ=None) -> str:
    return os.path.join(start_menu_dir(environ), DISPLAY_NAME + ".lnk")


def shortcut_powershell(target: str, link_path: str) -> str:
    """A PowerShell one-liner that creates the Start Menu .lnk pointing at the
    windowed launcher. Returned (not run) so it's testable; install() runs it."""
    launcher = venv_python(target, windowed=True)
    app_script = os.path.join(target, "venv", "Scripts", "sentinel-loop.exe")
    # Prefer the gui-script exe if present; fall back to pythonw -m.
    return (
        "$ws = New-Object -ComObject WScript.Shell; "
        "$s = $ws.CreateShortcut('{link}'); "
        "if (Test-Path '{app}') {{ $s.TargetPath = '{app}' }} "
        "else {{ $s.TargetPath = '{pyw}'; "
        "$s.Arguments = '-m sentinel_slice.app.shell' }}; "
        "$s.WorkingDirectory = '{target}'; "
        "$s.Description = 'Sentinel Loop'; $s.Save()"
    ).format(link=link_path, app=app_script, pyw=launcher, target=target)


def uninstall_key_values(target: str, version: str) -> dict:
    """The exact value set written under the HKCU Uninstall key so the app
    shows in Add/Remove Programs and uninstalls cleanly."""
    uninstaller = "{} -m sentinel_slice.installer uninstall".format(
        venv_python(target))
    return {
        "DisplayName": DISPLAY_NAME,
        "DisplayVersion": version,
        "Publisher": "Sentinel Loop (unsigned)",
        "InstallLocation": target,
        "UninstallString": uninstaller,
        "NoModify": 1,
        "NoRepair": 1,
        "EstimatedSize": 0,
    }


def self_delete_command(target: str) -> str:
    """A detached cmd that waits, then removes the install dir — so the
    uninstaller can delete the very venv it is running from (Windows locks a
    running exe's dir). Returned for testing; uninstall() spawns it."""
    return ('cmd /c "ping 127.0.0.1 -n 4 >nul & '
            'rmdir /s /q "{}""').format(target)


# ---- side-effecting flows ----

def _run(cmd, **kw):
    return subprocess.run(cmd, capture_output=True, text=True, **kw)


def install(*, target=None, wheel=None, version="0.0.0", environ=None,
            uninstall_key=UNINSTALL_KEY, registry=None, make_shortcut=True,
            enable_sandbox=True, skip_venv=False, pip_python=None) -> dict:
    """Install for the current user. Returns a report.

    target     where to install (default: LOCALAPPDATA\\Programs\\SentinelLoop)
    wheel      path to the sentinel-slice wheel to install (None -> assume the
               package is already importable, e.g. skip_venv dev runs)
    registry   a registry writer (injected in tests); default writes HKCU
    """
    if sys.platform != "win32":
        raise RuntimeError("the Windows installer runs on Windows only")
    target = target or default_target(environ)
    os.makedirs(target, exist_ok=True)
    actions = []

    py = pip_python or venv_python(target)
    if not skip_venv:
        venv_dir = os.path.join(target, "venv")
        r = _run([sys.executable, "-m", "venv", venv_dir])
        if r.returncode != 0:
            raise RuntimeError("venv creation failed: " + r.stderr)
        actions.append("venv")
        if wheel:
            r = _run([py, "-m", "pip", "install", "--quiet", wheel])
            if r.returncode != 0:
                raise RuntimeError("pip install failed: " + r.stderr)
            actions.append("pip")

    # First-run setup: app home + keypair + (Windows) AppContainer.
    init_args = [py, "-m", "sentinel_slice.init_app"]
    if enable_sandbox:
        init_args.append("--sandbox")
    r = _run(init_args, env={**os.environ, **(environ or {})})
    if r.returncode not in (0, 1):  # 1 = already initialized, fine
        raise RuntimeError("init failed: " + r.stderr)
    actions.append("init")

    if make_shortcut:
        link = shortcut_path(environ)
        os.makedirs(os.path.dirname(link), exist_ok=True)
        ps = shortcut_powershell(target, link)
        r = _run(["powershell", "-NoProfile", "-NonInteractive", "-Command", ps])
        if r.returncode == 0:
            actions.append("shortcut")

    writer = registry or _write_registry
    writer(uninstall_key, uninstall_key_values(target, version))
    actions.append("registry")

    return {"target": target, "actions": actions}


def uninstall(*, target=None, environ=None, uninstall_key=UNINSTALL_KEY,
              registry_delete=None, remove_shortcut=True, teardown_sandbox=True,
              schedule_self_delete=True) -> dict:
    """Reverse install(): tear down the AppContainer grants, remove the
    shortcut and the Add/Remove Programs entry, and delete the install dir
    (scheduled, since the running uninstaller lives inside it)."""
    target = target or default_target(environ)
    actions = []

    if teardown_sandbox:
        try:
            from sentinel_slice.chef.appcontainer import AppContainerSandbox, is_available
            if is_available():
                AppContainerSandbox.teardown()
                actions.append("sandbox_teardown")
        except Exception:
            pass  # never block uninstall on cleanup

    if remove_shortcut:
        link = shortcut_path(environ)
        if os.path.isfile(link):
            os.remove(link)
            actions.append("shortcut")

    deleter = registry_delete or _delete_registry
    if deleter(uninstall_key):
        actions.append("registry")

    if schedule_self_delete and os.path.isdir(target):
        subprocess.Popen(self_delete_command(target), shell=True)
        actions.append("scheduled_delete")
    elif os.path.isdir(target):
        import shutil
        shutil.rmtree(target, ignore_errors=True)
        actions.append("deleted")

    return {"target": target, "actions": actions}


# ---- real HKCU registry writers (only imported/used on Windows) ----

def _write_registry(key_path: str, values: dict) -> None:
    import winreg

    key = winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, key_path, 0,
                             winreg.KEY_WRITE)
    try:
        for name, value in values.items():
            if isinstance(value, int):
                winreg.SetValueEx(key, name, 0, winreg.REG_DWORD, value)
            else:
                winreg.SetValueEx(key, name, 0, winreg.REG_SZ, str(value))
    finally:
        winreg.CloseKey(key)


def _delete_registry(key_path: str) -> bool:
    import winreg

    try:
        winreg.DeleteKey(winreg.HKEY_CURRENT_USER, key_path)
        return True
    except FileNotFoundError:
        return False


def main(argv=None) -> int:
    import argparse

    parser = argparse.ArgumentParser(
        prog="sentinel-installer",
        description="Install or uninstall Sentinel Loop for the current user.")
    sub = parser.add_subparsers(dest="action", required=True)
    pi = sub.add_parser("install")
    pi.add_argument("--wheel", default=None)
    pi.add_argument("--version", default="0.0.0")
    pi.add_argument("--target", default=None)
    pi.add_argument("--skip-venv", action="store_true",
                    help="package already installed in the active env")
    pi.add_argument("--no-sandbox", action="store_true")
    sub.add_parser("uninstall").add_argument(
        "--target", default=None)
    args = parser.parse_args(argv)

    if args.action == "install":
        report = install(target=args.target, wheel=args.wheel,
                         version=args.version, skip_venv=args.skip_venv,
                         enable_sandbox=not args.no_sandbox)
        print("installed to {} ({})".format(
            report["target"], ", ".join(report["actions"])))
        return 0
    report = uninstall(target=args.target)
    print("uninstalled {} ({})".format(
        report["target"], ", ".join(report["actions"])))
    return 0


def cli() -> None:
    sys.exit(main())


if __name__ == "__main__":
    sys.exit(main())
