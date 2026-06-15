"""macOS microsandbox via the built-in `sandbox-exec` launcher.

No third-party install — `sandbox-exec` ships with macOS (/usr/bin). It applies
a Seatbelt (SBPL) profile and then execs the command, so the chef runs under a
KERNEL-ENFORCED sandbox that denies network AND confines the filesystem.

Mechanism note (honest): the Windows/Linux peers raise the boundary IN-process
via ctypes (AppContainer / seccomp+Landlock); macOS raises it through the OS's
built-in launcher instead. The containment is still OS-enforced by the Seatbelt
kernel extension — only the way it is RAISED differs. (Apple deprecated the
public `sandbox_init` C symbol but still ships and uses `sandbox-exec`; we use
the launcher rather than a deprecated private symbol. Flagged, not papered.)

The profile is built PER-RUN (like ContainerSandbox's argv) and is pure +
unit-tested; `run()` shells out to `sandbox-exec` and refuses off-macOS.

CONTAINMENT (rides on the receipt as containment="macsandbox"):
  - Network: DENIED (`(deny network*)`).
  - Writes: DENIED except the serving window, the ephemeral workspace, and the
    system temp dirs — the chef cannot modify anything else.
  - File CONTENT reads: DENIED except the Python runtime + system libraries, the
    kitchen fixtures, the cashier public key, and the chef module. Metadata
    (stat) stays allowed so path resolution works; only DATA is confined — so
    the chef cannot read another tenant's or user's file contents. Mirrors the
    Linux Landlock allow-list; DEFENSE-IN-DEPTH with the chef's owner-dir guard.
  - Shares the host kernel; an OS sandbox, not a VM/TEE.
"""

import os
import shutil
import subprocess
import sys

from sentinel_slice.chef.sandbox import SandboxResult, SandboxSpec

# System locations the chef's Python needs to READ content from to run.
_SYSTEM_READ = [
    "/usr", "/System", "/Library", "/bin", "/sbin", "/opt",
    "/private/var/db", "/private/etc", "/private/var/folders", "/dev",
]


def _existing_realpaths(paths):
    out, seen = [], set()
    for p in paths:
        if not p:
            continue
        rp = os.path.realpath(p)
        if rp not in seen:
            seen.add(rp)
            out.append(rp)
    return out


def _read_roots(spec):
    """Directories the chef may read CONTENT from: the Python runtime + system
    libs, plus the kitchen fixtures, the cashier public key, and the chef
    module. Everything else is content-read-denied."""
    roots = list(_SYSTEM_READ)
    roots += [sys.base_prefix, sys.prefix, sys.base_exec_prefix, sys.exec_prefix,
              os.path.dirname(os.path.realpath(sys.executable))]
    roots += [p for p in sys.path if p]
    roots += [spec.fixtures_root, os.path.dirname(spec.pubkey_path),
              os.path.dirname(spec.chef_main)]
    return _existing_realpaths(roots)


def _write_roots(spec):
    """The only places the chef may write: its serving window, the ephemeral
    workspace, and the system temp dirs Python may touch."""
    return _existing_realpaths(
        [spec.out_dir, spec.workspace, "/private/var/folders", "/private/tmp"])


def _subpaths(paths):
    return " ".join('(subpath "{}")'.format(p) for p in paths)


def build_profile(spec: SandboxSpec) -> str:
    """The Seatbelt profile: allow the operation classes Python needs, then deny
    network, deny writes outside the window/workspace/temp, and deny file
    CONTENT reads outside the runtime + kitchen + keys."""
    return (
        "(version 1)"
        "(allow default)"
        "(deny network*)"
        "(deny file-write*)"
        '(allow file-write* {w} (literal "/dev/null") (literal "/dev/dtracehelper"))'
        "(deny file-read-data)"
        "(allow file-read-data {r})"
    ).format(w=_subpaths(_write_roots(spec)), r=_subpaths(_read_roots(spec)))


class MacSandbox:
    """macOS Seatbelt backend via `sandbox-exec`: OS-enforced no-network +
    filesystem confinement."""

    containment_class = "macsandbox"

    def __init__(self, *, binary: str = "sandbox-exec") -> None:
        self._binary = binary

    def is_available(self) -> bool:
        """True only on macOS with the built-in `sandbox-exec` present."""
        return sys.platform == "darwin" and shutil.which(self._binary) is not None

    def build_command(self, spec: SandboxSpec) -> list[str]:
        """The exact `sandbox-exec` argv (pure — asserted by a test)."""
        return [
            self._binary, "-p", build_profile(spec),
            sys.executable, spec.chef_main,
            spec.pubkey_path, spec.fixtures_root, spec.out_dir,
        ]

    def run(self, spec: SandboxSpec) -> SandboxResult:
        if not self.is_available():
            raise RuntimeError(
                "MacSandbox needs macOS with the built-in `sandbox-exec`; not "
                "available here ({}).".format(sys.platform))
        # Pre-create the serving-window dir so it can be granted write and the
        # chef (which skips makedirs when out_dir exists) writes into it.
        os.makedirs(spec.out_dir, exist_ok=True)
        proc = subprocess.run(
            self.build_command(spec),
            input=spec.stdin,
            capture_output=True,
            text=True,
            cwd=spec.workspace,
            env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1"),
        )
        return SandboxResult(proc.returncode, proc.stdout, proc.stderr)
