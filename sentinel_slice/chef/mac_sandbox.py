"""macOS microsandbox via the built-in `sandbox-exec` launcher.

No third-party install — `sandbox-exec` ships with macOS (/usr/bin). It applies
a Seatbelt (SBPL) profile and then execs the command, so the chef runs under a
KERNEL-ENFORCED sandbox that denies all network operations.

Mechanism note (honest): the Windows/Linux peers raise the boundary IN-process
via ctypes (AppContainer / seccomp); macOS raises it through the OS's built-in
launcher instead. The containment is still OS-enforced by the Seatbelt kernel
extension — only the way it is RAISED differs. (Apple deprecated the public
`sandbox_init` C API but still ships and uses `sandbox-exec`; we use the
launcher rather than a deprecated private symbol. Flagged, not papered over.)

Like `ContainerSandbox`, the command CONSTRUCTION is pure and unit-tested
exactly; `run()` shells out to `sandbox-exec` and refuses off-macOS.

HONEST SCOPE (rides on the receipt as containment="macsandbox"):
  - Network: DENIED by the profile (`(deny network*)` — outbound, inbound, bind).
  - Filesystem: NOT confined by THIS profile (it `(allow default)` everything
    else); the chef's own owner-dir path guard remains the FS mechanism. A
    tighter file-read/file-write profile is the next increment.
  - Shares the host kernel; an OS sandbox, not a VM/TEE.
"""

import shutil
import subprocess
import sys

from sentinel_slice.chef.sandbox import SandboxResult, SandboxSpec

# Seatbelt profile: allow everything the chef needs to run, then deny all
# network operations. `network*` matches network-outbound/inbound/bind.
_PROFILE = "(version 1)(allow default)(deny network*)"


class MacSandbox:
    """macOS Seatbelt backend via `sandbox-exec`. OS-enforced no-network."""

    containment_class = "macsandbox"

    def __init__(self, *, binary: str = "sandbox-exec") -> None:
        self._binary = binary

    def is_available(self) -> bool:
        """True only on macOS with the built-in `sandbox-exec` present."""
        return sys.platform == "darwin" and shutil.which(self._binary) is not None

    def build_command(self, spec: SandboxSpec) -> list[str]:
        """The exact `sandbox-exec` argv. PURE — asserted by a test — so the
        network-deny profile is verified regardless of the host."""
        return [
            self._binary, "-p", _PROFILE,
            sys.executable, spec.chef_main,
            spec.pubkey_path, spec.fixtures_root, spec.out_dir,
        ]

    def run(self, spec: SandboxSpec) -> SandboxResult:
        if not self.is_available():
            raise RuntimeError(
                "MacSandbox needs macOS with the built-in `sandbox-exec`; not "
                "available here ({}).".format(sys.platform))
        proc = subprocess.run(
            self.build_command(spec),
            input=spec.stdin,
            capture_output=True,
            text=True,
            cwd=spec.workspace,
        )
        return SandboxResult(proc.returncode, proc.stdout, proc.stderr)
