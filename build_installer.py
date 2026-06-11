"""Build the thing dad downloads: dist/SentinelLoop-Setup-<ver>.zip.

The zip contains the wheel plus a tiny bootstrap (install.ps1 / INSTALL.bat)
that finds a Python, creates the private venv, pip-installs the wheel into it,
and hands off to `python -m sentinel_slice.installer install --skip-venv`
(which does the app setup + Start Menu shortcut + Add/Remove Programs entry).

Run from the repo root:  python build_installer.py
Requires the wheel to be built first (or pass --wheel).

HONEST: the bundle is UNSIGNED. SmartScreen will warn on a downloaded .ps1 /
the app's first run ("unknown publisher"). A real release wraps this in a
signed installer (Authenticode + MSI/MSIX). This builds the payload that
installer would carry.
"""

import argparse
import glob
import os
import sys
import zipfile

REPO = os.path.dirname(os.path.abspath(__file__))

INSTALL_PS1 = r"""# Sentinel Loop installer (per-user, no admin).
# UNSIGNED: you may need  Set-ExecutionPolicy -Scope Process Bypass  to run it.
$ErrorActionPreference = "Stop"
$here = Split-Path -Parent $MyInvocation.MyCommand.Path
$wheel = Get-ChildItem (Join-Path $here "*.whl") | Select-Object -First 1
if (-not $wheel) { Write-Error "no wheel found next to install.ps1"; exit 1 }

# Find a Python 3.11+ launcher.
$py = $null
foreach ($cand in @("py","python","python3")) {
  $c = Get-Command $cand -ErrorAction SilentlyContinue
  if ($c) { $py = $c.Source; break }
}
if (-not $py) {
  Write-Host "Python not found. Install it from https://python.org or the Store, then re-run."
  exit 1
}

$target = Join-Path $env:LOCALAPPDATA "Programs\SentinelLoop"
$venv = Join-Path $target "venv"
Write-Host "Installing Sentinel Loop to $target ..."
New-Item -ItemType Directory -Force -Path $target | Out-Null
& $py -m venv $venv
$vpy = Join-Path $venv "Scripts\python.exe"
& $vpy -m pip install --quiet --upgrade pip
& $vpy -m pip install --quiet $wheel.FullName
# Hand off to the package's own installer for setup + shortcut + registry.
& $vpy -m sentinel_slice.installer install --skip-venv --target $target --version "{VERSION}"
Write-Host ""
Write-Host "Done. Open 'Sentinel Loop' from the Start Menu, then Connect your AI."
"""

INSTALL_BAT = r"""@echo off
REM One-click wrapper: runs install.ps1 with a per-process bypass so an
REM unsigned script can run without changing system policy.
powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0install.ps1"
pause
"""

README_TXT = """Sentinel Loop — install

1. Unzip this folder anywhere.
2. Double-click INSTALL.bat  (or right-click install.ps1 -> Run with PowerShell).
3. Open "Sentinel Loop" from the Start Menu. Go to Connect and turn it on for
   your AI (Claude Desktop, etc.).

To remove it: Settings -> Apps -> Sentinel Loop -> Uninstall
(or run the UninstallString shown there).

NOTE: this build is UNSIGNED. Windows SmartScreen may warn ("unknown
publisher") — that is expected for an unsigned app, not a sign of malware.
A signed release removes the warning.
"""


def build(wheel: str, version: str, out_dir: str) -> str:
    os.makedirs(out_dir, exist_ok=True)
    bundle = os.path.join(out_dir, "SentinelLoop-Setup-{}.zip".format(version))
    with zipfile.ZipFile(bundle, "w", zipfile.ZIP_DEFLATED) as z:
        z.write(wheel, os.path.basename(wheel))
        z.writestr("install.ps1", INSTALL_PS1.replace("{VERSION}", version))
        z.writestr("INSTALL.bat", INSTALL_BAT)
        z.writestr("README.txt", README_TXT)
    return bundle


def _find_wheel(version):
    matches = glob.glob(os.path.join(
        REPO, "dist", "sentinel_slice-{}-*.whl".format(version)))
    return matches[0] if matches else None


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="build_installer")
    parser.add_argument("--version", default=None,
                        help="package version (default: read from pyproject)")
    parser.add_argument("--wheel", default=None)
    parser.add_argument("--out", default=os.path.join(REPO, "dist"))
    args = parser.parse_args(argv)

    version = args.version
    if version is None:
        import tomllib
        with open(os.path.join(REPO, "pyproject.toml"), "rb") as fh:
            version = tomllib.load(fh)["project"]["version"]

    wheel = args.wheel or _find_wheel(version)
    if not wheel or not os.path.isfile(wheel):
        print("wheel not found for version {} — build it first:\n"
              "  python -m pip wheel . --no-deps -w dist".format(version),
              file=sys.stderr)
        return 1

    bundle = build(wheel, version, args.out)
    print("built " + bundle)
    return 0


if __name__ == "__main__":
    sys.exit(main())
