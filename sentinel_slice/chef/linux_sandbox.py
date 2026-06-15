"""Linux in-process microsandbox: seccomp network denial.

No Docker, no daemon, no external runtime — the slice asks the Linux kernel
directly. Before the chef execs, a `preexec_fn` (run in the forked child)
installs PR_SET_NO_NEW_PRIVS plus a seccomp BPF filter that makes the
network-creating syscalls (socket/connect/bind) return EACCES. So the chef
subprocess cannot open a network connection even if its code were hostile —
the Linux peer of AppContainerSandbox (Windows): an OS-ENFORCED no-network
boundary raised by in-process syscalls, zero third-party install, no new Python
dependency (ctypes only).

Why seccomp on `socket` (not a network namespace): blocking the `socket(2)`
syscall needs no privilege and no user namespace (only PR_SET_NO_NEW_PRIVS +
a filter), so it works on hardened/unprivileged hosts and CI runners where
unprivileged `CLONE_NEWUSER` is restricted. With `socket` denied, every higher
egress path (urllib.request, http.client, requests, ssl) — all of which build
on a socket — is denied too.

HONEST SCOPE (rides on the receipt as containment="seccomp"):
  - Network egress: BLOCKED by the kernel (socket/connect/bind -> EACCES).
  - Filesystem: NOT confined by THIS backend yet — the chef's own owner-dir
    commonpath path guard remains the FS mechanism. A landlock ruleset is the
    next increment and slots in behind this same backend/`preexec_fn`.
  - Shares the host kernel; this is an OS sandbox, not a VM/TEE boundary (that
    is ContainerSandbox+gVisor, or a microVM).
"""

import ctypes
import platform
import subprocess
import sys

from sentinel_slice.chef.sandbox import SandboxResult, SandboxSpec

# --- seccomp / BPF constants ---
_BPF_LD = 0x00
_BPF_W = 0x00
_BPF_ABS = 0x20
_BPF_JMP = 0x05
_BPF_JEQ = 0x10
_BPF_K = 0x00
_BPF_RET = 0x06

# offsets into struct seccomp_data
_OFF_NR = 0      # int  nr        (the syscall number)
_OFF_ARCH = 4    # __u32 arch     (AUDIT_ARCH_*)

_SECCOMP_RET_ALLOW = 0x7FFF0000
_SECCOMP_RET_ERRNO = 0x00050000
_SECCOMP_RET_KILL_PROCESS = 0x80000000
_EACCES = 13

_PR_SET_NO_NEW_PRIVS = 38
_PR_SET_SECCOMP = 22
_SECCOMP_MODE_FILTER = 2

# Per-arch: (AUDIT_ARCH value, (socket, connect, bind) syscall numbers).
_ARCH = {
    "x86_64": (0xC000003E, (41, 42, 49)),
    "aarch64": (0xC00000B7, (198, 203, 200)),
    "arm64": (0xC00000B7, (198, 203, 200)),
}


class _SockFilter(ctypes.Structure):
    _fields_ = [
        ("code", ctypes.c_uint16),
        ("jt", ctypes.c_uint8),
        ("jf", ctypes.c_uint8),
        ("k", ctypes.c_uint32),
    ]


class _SockFprog(ctypes.Structure):
    _fields_ = [
        ("len", ctypes.c_ushort),
        ("filter", ctypes.POINTER(_SockFilter)),
    ]


def _stmt(code, k):
    return _SockFilter(code, 0, 0, k & 0xFFFFFFFF)


def _jump(code, k, jt, jf):
    return _SockFilter(code, jt, jf, k & 0xFFFFFFFF)


def _build_program(audit_arch, block_nrs):
    """Assemble the BPF filter:

        validate arch (else KILL); for each blocked syscall -> ERRNO(EACCES);
        otherwise ALLOW.

    Returns (fprog, backing_array). The caller must keep BOTH alive until the
    prctl() that installs the filter returns (the kernel copies it in then)."""
    n = len(block_nrs)
    instrs = [
        _stmt(_BPF_LD | _BPF_W | _BPF_ABS, _OFF_ARCH),         # A = arch
        # if A != expected -> jump to KILL (jf); else fall through
        _jump(_BPF_JMP | _BPF_JEQ | _BPF_K, audit_arch, 0, n + 3),
        _stmt(_BPF_LD | _BPF_W | _BPF_ABS, _OFF_NR),           # A = syscall nr
    ]
    for i, nr in enumerate(block_nrs):
        # if A == nr -> jump to ERRNO; else fall through to the next check
        instrs.append(_jump(_BPF_JMP | _BPF_JEQ | _BPF_K, nr, n - i, 0))
    instrs.append(_stmt(_BPF_RET | _BPF_K, _SECCOMP_RET_ALLOW))
    instrs.append(_stmt(_BPF_RET | _BPF_K, _SECCOMP_RET_ERRNO | _EACCES))
    instrs.append(_stmt(_BPF_RET | _BPF_K, _SECCOMP_RET_KILL_PROCESS))

    arr = (_SockFilter * len(instrs))(*instrs)
    prog = _SockFprog(len(instrs), ctypes.cast(arr, ctypes.POINTER(_SockFilter)))
    return prog, arr


def install_network_seccomp():
    """A `preexec_fn`: in the forked child, before exec, deny the
    network-creating syscalls via seccomp. Raises on any failure so the spawn
    fails CLOSED (the child never execs unconfined)."""
    audit_arch, nrs = _ARCH[platform.machine()]
    prog, _arr = _build_program(audit_arch, nrs)  # _arr kept alive below

    libc = ctypes.CDLL(None, use_errno=True)
    libc.prctl.restype = ctypes.c_int
    libc.prctl.argtypes = (ctypes.c_int, ctypes.c_ulong,
                           ctypes.c_void_p, ctypes.c_ulong, ctypes.c_ulong)

    if libc.prctl(_PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "PR_SET_NO_NEW_PRIVS failed")
    addr = ctypes.cast(ctypes.byref(prog), ctypes.c_void_p)
    if libc.prctl(_PR_SET_SECCOMP, _SECCOMP_MODE_FILTER, addr, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "PR_SET_SECCOMP failed")
    # _arr is referenced here so it outlives both prctl calls.
    del _arr


def is_available() -> bool:
    """True only on Linux with a supported arch (x86_64 / aarch64). seccomp
    itself is universal on Linux >=3.5; the arch table gates syscall numbers."""
    return sys.platform.startswith("linux") and platform.machine() in _ARCH


class LinuxSeccompSandbox:
    """In-process Linux microsandbox: the chef runs under a seccomp filter that
    the kernel enforces, denying all network syscalls. No external runtime."""

    containment_class = "seccomp"

    def is_available(self) -> bool:
        return is_available()

    def run(self, spec: SandboxSpec) -> SandboxResult:
        if not self.is_available():
            raise RuntimeError(
                "LinuxSeccompSandbox needs Linux (x86_64/aarch64); not "
                "available here ({} {}).".format(sys.platform, platform.machine()))
        try:
            proc = subprocess.run(
                [sys.executable, spec.chef_main, spec.pubkey_path,
                 spec.fixtures_root, spec.out_dir],
                input=spec.stdin,
                capture_output=True,
                text=True,
                cwd=spec.workspace,
                preexec_fn=install_network_seccomp,
            )
        except Exception as exc:
            # Confinement could not be applied -> fail CLOSED with an auditable
            # nonzero result instead of running the chef unconfined.
            return SandboxResult(
                126, "", "seccomp confinement failed: {}".format(exc))
        return SandboxResult(proc.returncode, proc.stdout, proc.stderr)
