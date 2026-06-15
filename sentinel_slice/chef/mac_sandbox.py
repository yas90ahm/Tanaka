# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Yasir Qureshi
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
    system temp dirs — the chef cannot modify or create anything else.
  - Reads: handled by the chef's own owner-dir guard (which confines reads to
    the tenant within the kitchen). HONEST ASYMMETRY vs. Linux: Landlock there
    also OS-confines reads to an allow-list; on macOS a content-read allow-list
    (file-read-data) proved too fragile across runner/OS versions (the dyld
    shared cache + framework content reads broke Python startup), so this
    backend OS-confines NETWORK + WRITES and leaves read-confinement to the
    chef's guard. Flagged, not papered. Tightening reads is a future increment.
  - Shares the host kernel; an OS sandbox, not a VM/TEE.
"""

import os
import shutil
import subprocess
import sys

from sentinel_slice.chef.sandbox import SandboxResult, SandboxSpec


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


def _write_roots(spec):
    """The only places the chef may write: its serving window, the ephemeral
    workspace, and the system temp dirs Python may touch."""
    return _existing_realpaths(
        [spec.out_dir, spec.workspace, "/private/var/folders", "/private/tmp"])


def _subpaths(paths):
    return " ".join('(subpath "{}")'.format(p) for p in paths)


def build_profile(spec: SandboxSpec) -> str:
    """The Seatbelt profile: allow the operation classes Python needs, then deny
    network and deny writes outside the window/workspace/temp."""
    return (
        "(version 1)"
        "(allow default)"
        "(deny network*)"
        "(deny file-write*)"
        '(allow file-write* {w} (literal "/dev/null") (literal "/dev/dtracehelper"))'
    ).format(w=_subpaths(_write_roots(spec)))


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
