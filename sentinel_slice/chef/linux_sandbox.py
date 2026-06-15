"""Linux in-process microsandbox: seccomp (network) + Landlock (filesystem).

No Docker, no daemon, no external runtime — the slice asks the Linux kernel
directly. Before the chef execs, a `preexec_fn` (run in the forked child)
installs, with only PR_SET_NO_NEW_PRIVS (no privilege, no user namespace):

  1. a seccomp BPF filter making the network syscalls (socket/connect/bind)
     return EACCES — the chef cannot open a network connection; and
  2. a Landlock ruleset confining the filesystem to an allow-list: READ+EXEC on
     the Python runtime + system libraries it needs to run and the kitchen
     fixtures (read-only), READ+WRITE only on the serving window + ephemeral
     workspace. Everything else — /home, /root, /var, other tenants' data,
     arbitrary writes — is DENIED by the kernel.

This is the Linux peer of AppContainerSandbox (Windows): an OS-ENFORCED no-
network + filesystem-confined boundary raised by in-process syscalls, zero
third-party install, no new Python dependency (ctypes only). Privilege-free, so
it works on hardened/unprivileged hosts and CI where `CLONE_NEWUSER` is denied.

HONEST SCOPE (rides on the receipt as containment="seccomp+landlock"):
  - Network egress: BLOCKED (socket/connect/bind -> EACCES).
  - Filesystem: confined to an allow-list (no reads outside runtime+kitchen,
    no writes outside the window+workspace). DEFENSE-IN-DEPTH with the chef's
    own owner-dir guard, which still narrows reads to the tenant WITHIN the
    kitchen — Landlock denies everything OUTSIDE it.
  - Requires Landlock (kernel 5.13+); if absent, the backend reports itself
    unavailable and the selector falls back to the subprocess contract.
  - Shares the host kernel; an OS sandbox, not a VM/TEE.
"""

import ctypes
import os
import platform
import subprocess
import sys

from sentinel_slice.chef.sandbox import SandboxResult, SandboxSpec

# ---------------- seccomp / BPF (network denial) ----------------
_BPF_LD = 0x00
_BPF_W = 0x00
_BPF_ABS = 0x20
_BPF_JMP = 0x05
_BPF_JEQ = 0x10
_BPF_K = 0x00
_BPF_RET = 0x06

_OFF_NR = 0      # struct seccomp_data: int nr
_OFF_ARCH = 4    # struct seccomp_data: __u32 arch

_SECCOMP_RET_ALLOW = 0x7FFF0000
_SECCOMP_RET_ERRNO = 0x00050000
_SECCOMP_RET_KILL_PROCESS = 0x80000000
_EACCES = 13

_PR_SET_NO_NEW_PRIVS = 38
_PR_SET_SECCOMP = 22
_SECCOMP_MODE_FILTER = 2

# Per-arch: (AUDIT_ARCH, (socket, connect, bind)).
_ARCH = {
    "x86_64": (0xC000003E, (41, 42, 49)),
    "aarch64": (0xC00000B7, (198, 203, 200)),
    "arm64": (0xC00000B7, (198, 203, 200)),
}

# ---------------- Landlock (filesystem confinement) ----------------
# Syscall numbers are identical on x86_64 and the asm-generic table (aarch64).
_SYS_landlock_create_ruleset = 444
_SYS_landlock_add_rule = 445
_SYS_landlock_restrict_self = 446
_LANDLOCK_CREATE_RULESET_VERSION = 1
_RULE_PATH_BENEATH = 1

_FS_EXECUTE = 1 << 0
_FS_WRITE_FILE = 1 << 1
_FS_READ_FILE = 1 << 2
_FS_READ_DIR = 1 << 3
_FS_REMOVE_DIR = 1 << 4
_FS_REMOVE_FILE = 1 << 5
_FS_MAKE_CHAR = 1 << 6
_FS_MAKE_DIR = 1 << 7
_FS_MAKE_REG = 1 << 8
_FS_MAKE_SOCK = 1 << 9
_FS_MAKE_FIFO = 1 << 10
_FS_MAKE_BLOCK = 1 << 11
_FS_MAKE_SYM = 1 << 12
_FS_REFER = 1 << 13      # ABI v2
_FS_TRUNCATE = 1 << 14   # ABI v3
_FS_IOCTL_DEV = 1 << 15  # ABI v5


class _SockFilter(ctypes.Structure):
    _fields_ = [("code", ctypes.c_uint16), ("jt", ctypes.c_uint8),
                ("jf", ctypes.c_uint8), ("k", ctypes.c_uint32)]


class _SockFprog(ctypes.Structure):
    _fields_ = [("len", ctypes.c_ushort), ("filter", ctypes.POINTER(_SockFilter))]


class _RulesetAttr(ctypes.Structure):
    _fields_ = [("handled_access_fs", ctypes.c_uint64)]


class _PathBeneath(ctypes.Structure):
    _pack_ = 1
    _fields_ = [("allowed_access", ctypes.c_uint64), ("parent_fd", ctypes.c_int32)]


def _stmt(code, k):
    return _SockFilter(code, 0, 0, k & 0xFFFFFFFF)


def _jump(code, k, jt, jf):
    return _SockFilter(code, jt, jf, k & 0xFFFFFFFF)


def _build_program(audit_arch, block_nrs):
    """Assemble the BPF: validate arch (else KILL); blocked syscall -> ERRNO;
    otherwise ALLOW. Returns (fprog, backing_array) — keep both alive until the
    installing prctl() returns."""
    n = len(block_nrs)
    instrs = [
        _stmt(_BPF_LD | _BPF_W | _BPF_ABS, _OFF_ARCH),
        _jump(_BPF_JMP | _BPF_JEQ | _BPF_K, audit_arch, 0, n + 3),
        _stmt(_BPF_LD | _BPF_W | _BPF_ABS, _OFF_NR),
    ]
    for i, nr in enumerate(block_nrs):
        instrs.append(_jump(_BPF_JMP | _BPF_JEQ | _BPF_K, nr, n - i, 0))
    instrs.append(_stmt(_BPF_RET | _BPF_K, _SECCOMP_RET_ALLOW))
    instrs.append(_stmt(_BPF_RET | _BPF_K, _SECCOMP_RET_ERRNO | _EACCES))
    instrs.append(_stmt(_BPF_RET | _BPF_K, _SECCOMP_RET_KILL_PROCESS))
    arr = (_SockFilter * len(instrs))(*instrs)
    prog = _SockFprog(len(instrs), ctypes.cast(arr, ctypes.POINTER(_SockFilter)))
    return prog, arr


def install_network_seccomp():
    """`preexec_fn` fragment: deny network-creating syscalls via seccomp."""
    audit_arch, nrs = _ARCH[platform.machine()]
    prog, _arr = _build_program(audit_arch, nrs)
    libc = ctypes.CDLL(None, use_errno=True)
    libc.prctl.restype = ctypes.c_int
    libc.prctl.argtypes = (ctypes.c_int, ctypes.c_ulong,
                           ctypes.c_void_p, ctypes.c_ulong, ctypes.c_ulong)
    if libc.prctl(_PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "PR_SET_NO_NEW_PRIVS failed")
    addr = ctypes.cast(ctypes.byref(prog), ctypes.c_void_p)
    if libc.prctl(_PR_SET_SECCOMP, _SECCOMP_MODE_FILTER, addr, 0, 0) != 0:
        raise OSError(ctypes.get_errno(), "PR_SET_SECCOMP failed")
    del _arr


def landlock_abi() -> int:
    """The kernel's Landlock ABI version (0 if Landlock is unavailable)."""
    if not sys.platform.startswith("linux"):
        return 0
    try:
        libc = ctypes.CDLL(None, use_errno=True)
        libc.syscall.restype = ctypes.c_long
        v = libc.syscall(ctypes.c_long(_SYS_landlock_create_ruleset),
                         ctypes.c_void_p(0), ctypes.c_size_t(0),
                         ctypes.c_uint(_LANDLOCK_CREATE_RULESET_VERSION))
        return int(v) if v and v > 0 else 0
    except Exception:
        return 0


def _handled_access(abi):
    h = (_FS_EXECUTE | _FS_WRITE_FILE | _FS_READ_FILE | _FS_READ_DIR
         | _FS_REMOVE_DIR | _FS_REMOVE_FILE | _FS_MAKE_CHAR | _FS_MAKE_DIR
         | _FS_MAKE_REG | _FS_MAKE_SOCK | _FS_MAKE_FIFO | _FS_MAKE_BLOCK
         | _FS_MAKE_SYM)
    if abi >= 2:
        h |= _FS_REFER
    if abi >= 3:
        h |= _FS_TRUNCATE
    if abi >= 5:
        h |= _FS_IOCTL_DEV
    return h


def python_read_roots():
    """Directories the chef's Python needs READ+EXEC on to start and run:
    the interpreter, shared libraries, and every importable location. Granting
    these (and nothing else for read) lets Python run while DENYING reads of
    user data outside them (/home, /root, /var, other tenants)."""
    roots = [
        "/usr", "/lib", "/lib64", "/lib32", "/libx32", "/bin", "/sbin",
        "/etc", "/opt", "/proc", "/dev", "/sys",
        sys.base_prefix, sys.prefix, sys.base_exec_prefix, sys.exec_prefix,
        os.path.dirname(os.path.realpath(sys.executable)),
    ]
    roots += [p for p in sys.path if p]
    out, seen = [], set()
    for p in roots:
        ap = os.path.abspath(p)
        if ap not in seen and os.path.isdir(ap):
            seen.add(ap)
            out.append(ap)
    return out


def apply_landlock(*, read_exec_roots, read_roots, write_roots):
    """Confine the calling thread's filesystem to an allow-list and restrict
    self. Raises on any failure (so callers fail CLOSED)."""
    abi = landlock_abi()
    if abi < 1:
        raise OSError("Landlock unavailable (ABI {})".format(abi))
    handled = _handled_access(abi)
    libc = ctypes.CDLL(None, use_errno=True)
    libc.syscall.restype = ctypes.c_long

    attr = _RulesetAttr(handled)
    rfd = libc.syscall(ctypes.c_long(_SYS_landlock_create_ruleset),
                       ctypes.byref(attr), ctypes.c_size_t(ctypes.sizeof(attr)),
                       ctypes.c_uint(0))
    if rfd < 0:
        raise OSError(ctypes.get_errno(), "landlock_create_ruleset failed")
    rfd = int(rfd)

    read_exec = (_FS_READ_FILE | _FS_READ_DIR | _FS_EXECUTE) & handled
    read_only = (_FS_READ_FILE | _FS_READ_DIR) & handled
    write_all = (_FS_READ_FILE | _FS_WRITE_FILE | _FS_READ_DIR
                 | _FS_REMOVE_FILE | _FS_REMOVE_DIR | _FS_MAKE_REG
                 | _FS_MAKE_DIR | _FS_MAKE_SYM | _FS_TRUNCATE) & handled
    o_path = getattr(os, "O_PATH", 0)

    def add(path, access):
        if not path or not os.path.exists(path):
            return
        fd = os.open(path, o_path)
        try:
            pb = _PathBeneath(access, fd)
            r = libc.syscall(ctypes.c_long(_SYS_landlock_add_rule),
                             ctypes.c_int(rfd), ctypes.c_int(_RULE_PATH_BENEATH),
                             ctypes.byref(pb), ctypes.c_uint(0))
            if r != 0:
                raise OSError(ctypes.get_errno(),
                              "landlock_add_rule({})".format(path))
        finally:
            os.close(fd)

    try:
        seen = set()
        for p in read_exec_roots:
            ap = os.path.abspath(p)
            if ap not in seen:
                seen.add(ap)
                add(ap, read_exec)
        for p in read_roots:
            ap = os.path.abspath(p)
            if ap not in seen:
                seen.add(ap)
                add(ap, read_only)
        for p in write_roots:
            add(os.path.abspath(p), write_all)
        libc.prctl(_PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)
        r = libc.syscall(ctypes.c_long(_SYS_landlock_restrict_self),
                         ctypes.c_int(rfd), ctypes.c_uint(0))
        if r != 0:
            raise OSError(ctypes.get_errno(), "landlock_restrict_self failed")
    finally:
        os.close(rfd)


def is_available() -> bool:
    """True only on Linux with a supported arch AND Landlock (kernel 5.13+).
    seccomp is universal; Landlock is the gate, so the backend always delivers
    BOTH network and filesystem confinement (its honest label)."""
    return (sys.platform.startswith("linux")
            and platform.machine() in _ARCH
            and landlock_abi() >= 1)


class LinuxSeccompSandbox:
    """In-process Linux microsandbox: the chef runs under a seccomp filter (no
    network) AND a Landlock ruleset (filesystem allow-list), both kernel-
    enforced. No external runtime."""

    containment_class = "seccomp+landlock"

    def is_available(self) -> bool:
        return is_available()

    def run(self, spec: SandboxSpec) -> SandboxResult:
        if not self.is_available():
            raise RuntimeError(
                "LinuxSeccompSandbox needs Linux (x86_64/aarch64) with Landlock "
                "(kernel 5.13+); not available here ({} {}).".format(
                    sys.platform, platform.machine()))
        # Pre-create the serving-window dir so it can be granted write and the
        # chef (which skips makedirs when out_dir exists) writes into it.
        os.makedirs(spec.out_dir, exist_ok=True)
        read_exec = python_read_roots() + [spec.fixtures_root]
        write = [spec.out_dir, spec.workspace]

        def _confine():
            apply_landlock(read_exec_roots=read_exec, read_roots=[],
                           write_roots=write)
            install_network_seccomp()

        try:
            proc = subprocess.run(
                [sys.executable, spec.chef_main, spec.pubkey_path,
                 spec.fixtures_root, spec.out_dir],
                input=spec.stdin,
                capture_output=True,
                text=True,
                cwd=spec.workspace,
                env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1"),
                preexec_fn=_confine,
            )
        except Exception as exc:
            return SandboxResult(
                126, "", "seccomp+landlock confinement failed: {}".format(exc))
        return SandboxResult(proc.returncode, proc.stdout, proc.stderr)
