"""AppContainer sandbox backend — OS-enforced containment for the chef on
Windows, with ZERO install (no Docker, no VM, no admin).

This is the consumer-Windows answer to "the sandbox is a contract, not a
guarantee." An AppContainer is the same OS isolation primitive the browser
uses to contain a web page on a billion machines: a low-integrity, capability-
gated security context. Run the chef inside one with NO capabilities and the
key property is structural, not promised:

  - NO NETWORK by construction. An AppContainer reaches the network only if it
    holds a network capability (internetClient / internetClientServer /
    privateNetwork). We grant ZERO capabilities, so Windows Firewall blocks
    every outbound connection — network is a DENIED capability, not a dropped
    one. (Compare SubprocessSandbox, where "no network" is only the chef's
    own import closure behaving.)
  - LEAST-PRIVILEGE FILES. An AppContainer process can touch only paths whose
    ACL grants its package SID. We grant exactly: read+execute on the Python
    runtime (setup-once) and the per-order workspace + kitchen scope, and
    modify on the one serving-window dir. Everything else on disk is denied by
    the OS — the chef cannot read your documents because it was never granted
    them.
  - A JOB OBJECT caps it: kill-on-close (no orphaned survivors), one active
    process (no fork bomb / no spawning a helper), and a memory ceiling.

HONEST LIMITS (and they go on the receipt as `containment="appcontainer"`,
never as something stronger):
  - This is an OS sandbox, NOT a hypervisor boundary. It shares the host
    kernel. A kernel-level exploit escapes it; a microVM (Firecracker /
    Virtualization.framework) or gVisor is the next rung and a different
    receipt label.
  - It is NOT a TEE. No attestation of the environment beyond the existing
    MOCK quote.
  - The file ACLs are real grants on the real filesystem (reversible: see
    `teardown`). The setup-once Python grants add read+execute for the
    package SID; they remove nothing.

stdlib only (ctypes + subprocess for icacls) — the cryptography+pytest deps
non-negotiable holds. Windows-only; `is_available()` is False everywhere else,
so the seam degrades to SubprocessSandbox cleanly off-Windows.
"""

import ctypes
import os
import subprocess
import sys
import threading
from ctypes import wintypes

from sentinel_slice.chef.sandbox import SandboxResult, SandboxSpec

# The package SID is derived from this name; stable so setup/run/teardown
# agree and a re-run reuses the same profile.
PROFILE_NAME = "SentinelLoopChef"

# Capability SID string for "ALL APPLICATION PACKAGES" is S-1-15-2-1; the
# per-profile AppContainer SID we derive is S-1-15-2-<hash...>. We grant the
# derived SID, not the broad one.

_IS_WIN = sys.platform == "win32"

# ---- Win32 constants ----
_CREATE_SUSPENDED = 0x00000004
_CREATE_UNICODE_ENVIRONMENT = 0x00000400
_EXTENDED_STARTUPINFO_PRESENT = 0x00080000
_PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES = 0x00020009
_STARTF_USESTDHANDLES = 0x00000100
_HANDLE_FLAG_INHERIT = 0x00000001
_WAIT_TIMEOUT = 0x00000102
_WAIT_OBJECT_0 = 0x00000000
_INFINITE = 0xFFFFFFFF
_GENERIC_READ = 0x80000000
_GENERIC_WRITE = 0x40000000
_OPEN_EXISTING = 3
_CREATE_ALWAYS = 2
_FILE_ATTRIBUTE_NORMAL = 0x80
_FILE_SHARE_READ = 0x00000001
_FILE_SHARE_WRITE = 0x00000002

# Job-object limit flags.
_JOB_OBJECT_LIMIT_ACTIVE_PROCESS = 0x00000008
_JOB_OBJECT_LIMIT_PROCESS_MEMORY = 0x00000100
_JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
_JobObjectExtendedLimitInformation = 9

# Profile-create returns this when the profile already exists.
_HRESULT_ALREADY_EXISTS = -2147024713  # 0x800700B7 (ERROR_ALREADY_EXISTS as HRESULT)


def is_available() -> bool:
    """True only on Windows with the AppContainer APIs present and a package
    SID derivable. Cheap and side-effect-free (it derives a SID and frees it)."""
    if not _IS_WIN:
        return False
    try:
        sid_str, sid_ptr = _derive_sid(PROFILE_NAME)
        ctypes.windll.kernel32.LocalFree(sid_ptr)
        return bool(sid_str)
    except OSError:
        return False


# ---- ctypes structures ----
if _IS_WIN:
    class _STARTUPINFOW(ctypes.Structure):
        _fields_ = [
            ("cb", wintypes.DWORD),
            ("lpReserved", wintypes.LPWSTR),
            ("lpDesktop", wintypes.LPWSTR),
            ("lpTitle", wintypes.LPWSTR),
            ("dwX", wintypes.DWORD),
            ("dwY", wintypes.DWORD),
            ("dwXSize", wintypes.DWORD),
            ("dwYSize", wintypes.DWORD),
            ("dwXCountChars", wintypes.DWORD),
            ("dwYCountChars", wintypes.DWORD),
            ("dwFillAttribute", wintypes.DWORD),
            ("dwFlags", wintypes.DWORD),
            ("wShowWindow", wintypes.WORD),
            ("cbReserved2", wintypes.WORD),
            ("lpReserved2", ctypes.POINTER(ctypes.c_byte)),
            ("hStdInput", wintypes.HANDLE),
            ("hStdOutput", wintypes.HANDLE),
            ("hStdError", wintypes.HANDLE),
        ]

    class _STARTUPINFOEXW(ctypes.Structure):
        _fields_ = [
            ("StartupInfo", _STARTUPINFOW),
            ("lpAttributeList", ctypes.c_void_p),
        ]

    class _PROCESS_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("hProcess", wintypes.HANDLE),
            ("hThread", wintypes.HANDLE),
            ("dwProcessId", wintypes.DWORD),
            ("dwThreadId", wintypes.DWORD),
        ]

    class _SECURITY_CAPABILITIES(ctypes.Structure):
        _fields_ = [
            ("AppContainerSid", ctypes.c_void_p),
            ("Capabilities", ctypes.c_void_p),
            ("CapabilityCount", wintypes.DWORD),
            ("Reserved", wintypes.DWORD),
        ]

    class _SECURITY_ATTRIBUTES(ctypes.Structure):
        _fields_ = [
            ("nLength", wintypes.DWORD),
            ("lpSecurityDescriptor", ctypes.c_void_p),
            ("bInheritHandle", wintypes.BOOL),
        ]

    class _JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("PerProcessUserTimeLimit", ctypes.c_int64),
            ("PerJobUserTimeLimit", ctypes.c_int64),
            ("LimitFlags", wintypes.DWORD),
            ("MinimumWorkingSetSize", ctypes.c_size_t),
            ("MaximumWorkingSetSize", ctypes.c_size_t),
            ("ActiveProcessLimit", wintypes.DWORD),
            ("Affinity", ctypes.c_size_t),
            ("PriorityClass", wintypes.DWORD),
            ("SchedulingClass", wintypes.DWORD),
        ]

    class _IO_COUNTERS(ctypes.Structure):
        _fields_ = [
            ("ReadOperationCount", ctypes.c_uint64),
            ("WriteOperationCount", ctypes.c_uint64),
            ("OtherOperationCount", ctypes.c_uint64),
            ("ReadTransferCount", ctypes.c_uint64),
            ("WriteTransferCount", ctypes.c_uint64),
            ("OtherTransferCount", ctypes.c_uint64),
        ]

    class _JOBOBJECT_EXTENDED_LIMIT_INFORMATION(ctypes.Structure):
        _fields_ = [
            ("BasicLimitInformation", _JOBOBJECT_BASIC_LIMIT_INFORMATION),
            ("IoInfo", _IO_COUNTERS),
            ("ProcessMemoryLimit", ctypes.c_size_t),
            ("JobMemoryLimit", ctypes.c_size_t),
            ("PeakProcessMemoryUsed", ctypes.c_size_t),
            ("PeakJobMemoryUsed", ctypes.c_size_t),
        ]


_CONFIGURED = False


def _configure():
    """Declare argtypes/restypes for every Win32 call we make. REQUIRED on
    64-bit: without it ctypes assumes 32-bit ints and truncates pointers and
    HANDLEs, corrupting SIDs and handles. Idempotent."""
    global _CONFIGURED
    if _CONFIGURED or not _IS_WIN:
        return
    k32 = ctypes.windll.kernel32
    advapi = ctypes.windll.advapi32
    userenv = ctypes.windll.userenv
    H = wintypes.HANDLE
    DW = wintypes.DWORD
    VP = ctypes.c_void_p

    userenv.CreateAppContainerProfile.restype = ctypes.c_long  # HRESULT
    userenv.CreateAppContainerProfile.argtypes = [
        wintypes.LPCWSTR, wintypes.LPCWSTR, wintypes.LPCWSTR,
        VP, DW, ctypes.POINTER(VP)]
    userenv.DeriveAppContainerSidFromAppContainerName.restype = ctypes.c_long
    userenv.DeriveAppContainerSidFromAppContainerName.argtypes = [
        wintypes.LPCWSTR, ctypes.POINTER(VP)]

    advapi.ConvertSidToStringSidW.restype = wintypes.BOOL
    advapi.ConvertSidToStringSidW.argtypes = [VP, ctypes.POINTER(wintypes.LPWSTR)]

    k32.LocalFree.restype = VP
    k32.LocalFree.argtypes = [VP]
    k32.CreateFileW.restype = H
    k32.CreateFileW.argtypes = [
        wintypes.LPCWSTR, DW, DW, VP, DW, DW, H]
    k32.CreateJobObjectW.restype = H
    k32.CreateJobObjectW.argtypes = [VP, wintypes.LPCWSTR]
    k32.SetInformationJobObject.restype = wintypes.BOOL
    k32.SetInformationJobObject.argtypes = [H, ctypes.c_int, VP, DW]
    k32.AssignProcessToJobObject.restype = wintypes.BOOL
    k32.AssignProcessToJobObject.argtypes = [H, H]
    k32.TerminateJobObject.restype = wintypes.BOOL
    k32.TerminateJobObject.argtypes = [H, wintypes.UINT]
    k32.ResumeThread.restype = DW
    k32.ResumeThread.argtypes = [H]
    k32.WaitForSingleObject.restype = DW
    k32.WaitForSingleObject.argtypes = [H, DW]
    k32.GetExitCodeProcess.restype = wintypes.BOOL
    k32.GetExitCodeProcess.argtypes = [H, ctypes.POINTER(DW)]
    k32.CloseHandle.restype = wintypes.BOOL
    k32.CloseHandle.argtypes = [H]
    k32.InitializeProcThreadAttributeList.restype = wintypes.BOOL
    k32.InitializeProcThreadAttributeList.argtypes = [
        VP, DW, DW, ctypes.POINTER(ctypes.c_size_t)]
    k32.UpdateProcThreadAttribute.restype = wintypes.BOOL
    k32.UpdateProcThreadAttribute.argtypes = [
        VP, DW, ctypes.c_void_p, VP, ctypes.c_size_t, VP, VP]
    k32.DeleteProcThreadAttributeList.restype = None
    k32.DeleteProcThreadAttributeList.argtypes = [VP]
    k32.CreateProcessW.restype = wintypes.BOOL
    k32.CreateProcessW.argtypes = [
        wintypes.LPCWSTR, wintypes.LPWSTR, VP, VP, wintypes.BOOL,
        DW, VP, wintypes.LPCWSTR, VP, VP]
    _CONFIGURED = True


def _check(ok, what):
    if not ok:
        raise OSError("{} failed: WinError {}".format(
            what, ctypes.get_last_error()))


def _derive_sid(name):
    """Derive the AppContainer package SID for `name`. Returns
    (sid_string, sid_ptr). The caller frees sid_ptr with LocalFree. Creating
    the profile is idempotent; we derive even if it already exists."""
    _configure()
    userenv = ctypes.windll.userenv
    advapi = ctypes.windll.advapi32

    psid = ctypes.c_void_p()
    # Try to create the profile (display name + description are cosmetic).
    hr = userenv.CreateAppContainerProfile(
        ctypes.c_wchar_p(name), ctypes.c_wchar_p(name),
        ctypes.c_wchar_p("Sentinel Loop ephemeral chef sandbox"),
        None, 0, ctypes.byref(psid))
    if hr == 0:
        sid_ptr = psid.value
    else:
        # Already exists (or create failed) -> derive the SID directly.
        psid2 = ctypes.c_void_p()
        hr2 = userenv.DeriveAppContainerSidFromAppContainerName(
            ctypes.c_wchar_p(name), ctypes.byref(psid2))
        if hr2 != 0:
            raise OSError("DeriveAppContainerSid failed: HRESULT {}".format(hr2))
        sid_ptr = psid2.value

    str_ptr = wintypes.LPWSTR()
    ok = advapi.ConvertSidToStringSidW(sid_ptr, ctypes.byref(str_ptr))
    _check(ok, "ConvertSidToStringSidW")
    sid_string = str_ptr.value
    ctypes.windll.kernel32.LocalFree(str_ptr)
    return sid_string, sid_ptr


def _icacls(path, args):
    """Run icacls on path with args; raise on failure. Quiet."""
    proc = subprocess.run(
        ["icacls", path] + args + ["/Q"],
        capture_output=True, text=True)
    if proc.returncode != 0:
        raise OSError("icacls {} {} failed: {}".format(
            path, args, proc.stderr.strip() or proc.stdout.strip()))


def _grant(path, sid_string, perm):
    """Grant the package SID `perm` (e.g. '(OI)(CI)(RX)') on path, recursive."""
    _icacls(path, ["/grant", "*{}:{}".format(sid_string, perm), "/T"])


def _revoke(path, sid_string):
    """Remove the package SID's grant from path, recursive. Tolerant: a path
    that's already gone or never granted is not an error here (teardown)."""
    proc = subprocess.run(
        ["icacls", path, "/remove", "*" + sid_string, "/T", "/Q"],
        capture_output=True, text=True)
    # icacls returns nonzero only on real failure; a no-op remove is rc 0.
    if proc.returncode != 0 and os.path.exists(path):
        raise OSError("icacls revoke {} failed: {}".format(
            path, proc.stderr.strip() or proc.stdout.strip()))


class AppContainerSandbox:
    """Run the chef in a Windows AppContainer with no capabilities, confined
    by file ACLs and a job object. `containment_class = "appcontainer"`.

    Setup-once: grant the package SID read+execute on the Python runtime
    (see `setup`/`teardown`, or the CLI). Per run: copy chef_main + pubkey
    into the ephemeral workspace, grant the workspace + kitchen scope, run,
    then revoke."""

    containment_class = "appcontainer"

    def __init__(self, *, timeout_sec=60, memory_mb=256,
                 python_exe=None) -> None:
        self._timeout_ms = int(timeout_sec * 1000)
        self._memory_bytes = int(memory_mb) * 1024 * 1024
        # Default to the BASE interpreter, not a venv launcher stub: a venv's
        # python.exe re-execs the real interpreter, which is a second process
        # the job's ActiveProcessLimit=1 (correctly) forbids. A packaged app
        # ships one interpreter and hits this path naturally.
        self._python = python_exe or getattr(
            sys, "_base_executable", None) or sys.executable
        # The import roots the standalone chef needs (cryptography lives in
        # site-packages); passed to the child via PYTHONPATH so a single base
        # interpreter finds them. Only real dirs (which must also be ACL-
        # granted; site-packages sits under the granted runtime prefix).
        self._pythonpath = [
            p for p in sys.path
            if p and "site-packages" in p and os.path.isdir(p)]

    def is_available(self) -> bool:
        return is_available()

    # ---- setup-once Python grants ----
    @staticmethod
    def runtime_paths(python_exe=None):
        """The Python trees the sandboxed chef must read+execute: the venv/
        install prefix (cryptography, the launcher) and the base prefix
        (stdlib, python core). De-duplicated, existing dirs only."""
        seen, out = set(), []
        for p in (sys.prefix, sys.base_prefix):
            ap = os.path.abspath(p)
            if ap not in seen and os.path.isdir(ap):
                seen.add(ap)
                out.append(ap)
        return out

    @classmethod
    def setup(cls):
        """Create the profile and grant the package SID read+execute on the
        Python runtime. Returns (sid_string, granted_paths). Idempotent."""
        sid_string, sid_ptr = _derive_sid(PROFILE_NAME)
        ctypes.windll.kernel32.LocalFree(sid_ptr)
        granted = cls.runtime_paths()
        for path in granted:
            _grant(path, sid_string, "(OI)(CI)(RX)")
        return sid_string, granted

    @classmethod
    def teardown(cls):
        """Reverse `setup`: remove the package SID's grant from the Python
        runtime trees. The profile itself is left (harmless, reusable);
        pass-through to delete it could be added but isn't necessary."""
        sid_string, sid_ptr = _derive_sid(PROFILE_NAME)
        ctypes.windll.kernel32.LocalFree(sid_ptr)
        removed = cls.runtime_paths()
        for path in removed:
            _revoke(path, sid_string)
        return sid_string, removed

    # ---- per-order run ----
    def run(self, spec: SandboxSpec) -> SandboxResult:
        if not _IS_WIN:
            raise RuntimeError("AppContainerSandbox is Windows-only")
        sid_string, sid_ptr = _derive_sid(PROFILE_NAME)
        granted = []
        try:
            # Copy the chef + pubkey into the workspace so the AppContainer
            # needs read access to ONLY the ephemeral workspace, never the
            # package source tree.
            import shutil
            local_chef = os.path.join(spec.workspace, "chef_main.py")
            local_pubkey = os.path.join(spec.workspace, "pubkey.pem")
            shutil.copy2(spec.chef_main, local_chef)
            shutil.copy2(spec.pubkey_path, local_pubkey)

            # The serving window must EXIST before we grant it: the chef calls
            # os.makedirs(out_dir, exist_ok=True), which — if the dir is absent
            # — walks up creating parents and hits C:\ (which the AppContainer
            # cannot stat, so it can't short-circuit). Create it here so the
            # grant lands on a real dir and the chef's makedirs is a no-op.
            os.makedirs(spec.out_dir, exist_ok=True)

            # Grants: workspace RX (run the chef copy, read its cwd), kitchen
            # scope RX (read the one fixture), serving window M (write output).
            _grant(spec.workspace, sid_string, "(OI)(CI)(RX)")
            granted.append(spec.workspace)
            _grant(spec.fixtures_root, sid_string, "(OI)(CI)(RX)")
            granted.append(spec.fixtures_root)
            _grant(spec.out_dir, sid_string, "(OI)(CI)(M)")
            granted.append(spec.out_dir)

            argv = [
                self._python, "-B", local_chef, local_pubkey,
                spec.fixtures_root, spec.out_dir,
            ]
            return self._launch(argv, spec, sid_ptr)
        finally:
            for path in granted:
                _revoke(path, sid_string)
            ctypes.windll.kernel32.LocalFree(sid_ptr)

    def _launch(self, argv, spec, sid_ptr) -> SandboxResult:
        k32 = ctypes.windll.kernel32

        # --- std handles via files (no pipe-deadlock dance): stdin from a
        # file, stdout/stderr to files. The handles are opened by US (parent),
        # so the child writes through inherited handles regardless of its ACL.
        stdin_path = os.path.join(spec.workspace, "_stdin")
        stdout_path = os.path.join(spec.workspace, "_stdout")
        stderr_path = os.path.join(spec.workspace, "_stderr")
        with open(stdin_path, "w", encoding="utf-8") as fh:
            fh.write(spec.stdin)

        sa = _SECURITY_ATTRIBUTES()
        sa.nLength = ctypes.sizeof(sa)
        sa.lpSecurityDescriptor = None
        sa.bInheritHandle = True

        h_in = k32.CreateFileW(
            ctypes.c_wchar_p(stdin_path), _GENERIC_READ,
            _FILE_SHARE_READ | _FILE_SHARE_WRITE, ctypes.byref(sa),
            _OPEN_EXISTING, _FILE_ATTRIBUTE_NORMAL, None)
        h_out = k32.CreateFileW(
            ctypes.c_wchar_p(stdout_path), _GENERIC_WRITE,
            _FILE_SHARE_READ, ctypes.byref(sa),
            _CREATE_ALWAYS, _FILE_ATTRIBUTE_NORMAL, None)
        h_err = k32.CreateFileW(
            ctypes.c_wchar_p(stderr_path), _GENERIC_WRITE,
            _FILE_SHARE_READ, ctypes.byref(sa),
            _CREATE_ALWAYS, _FILE_ATTRIBUTE_NORMAL, None)
        for h, what in ((h_in, "stdin"), (h_out, "stdout"), (h_err, "stderr")):
            if h == wintypes.HANDLE(-1).value or h is None:
                raise OSError("CreateFileW for {} failed: WinError {}".format(
                    what, ctypes.get_last_error()))

        # --- attribute list carrying the zero-capability SECURITY_CAPABILITIES.
        caps = _SECURITY_CAPABILITIES()
        caps.AppContainerSid = sid_ptr
        caps.Capabilities = None        # NO capabilities -> no network
        caps.CapabilityCount = 0
        caps.Reserved = 0

        size = ctypes.c_size_t(0)
        k32.InitializeProcThreadAttributeList(None, 1, 0, ctypes.byref(size))
        buf = (ctypes.c_byte * size.value)()
        attr_list = ctypes.cast(buf, ctypes.c_void_p)
        _check(k32.InitializeProcThreadAttributeList(
            attr_list, 1, 0, ctypes.byref(size)),
            "InitializeProcThreadAttributeList")
        _check(k32.UpdateProcThreadAttribute(
            attr_list, 0, _PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES,
            ctypes.byref(caps), ctypes.sizeof(caps), None, None),
            "UpdateProcThreadAttribute")

        # Environment block: inherit the parent's, but force PYTHONPATH to the
        # chef's import roots (so the base interpreter finds cryptography) and
        # PYTHONDONTWRITEBYTECODE (the chef's tree is read-only to it anyway).
        env = {k: v for k, v in os.environ.items()}
        if self._pythonpath:
            env["PYTHONPATH"] = os.pathsep.join(self._pythonpath)
        env["PYTHONDONTWRITEBYTECODE"] = "1"
        env_block = "".join("{}={}\0".format(k, v) for k, v in env.items()) + "\0"
        env_buf = ctypes.create_unicode_buffer(env_block)

        si = _STARTUPINFOEXW()
        si.StartupInfo.cb = ctypes.sizeof(_STARTUPINFOEXW)
        si.StartupInfo.dwFlags = _STARTF_USESTDHANDLES
        si.StartupInfo.hStdInput = h_in
        si.StartupInfo.hStdOutput = h_out
        si.StartupInfo.hStdError = h_err
        si.lpAttributeList = attr_list

        pi = _PROCESS_INFORMATION()
        cmdline = subprocess.list2cmdline(argv)

        # Job object: kill-on-close, single active process, memory cap. Create
        # the process SUSPENDED, assign to the job, THEN resume — so it cannot
        # spawn or run before the limits bind.
        h_job = k32.CreateJobObjectW(None, None)
        _check(h_job, "CreateJobObjectW")
        info = _JOBOBJECT_EXTENDED_LIMIT_INFORMATION()
        info.BasicLimitInformation.LimitFlags = (
            _JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            | _JOB_OBJECT_LIMIT_ACTIVE_PROCESS
            | _JOB_OBJECT_LIMIT_PROCESS_MEMORY)
        info.BasicLimitInformation.ActiveProcessLimit = 1
        info.ProcessMemoryLimit = self._memory_bytes
        _check(k32.SetInformationJobObject(
            h_job, _JobObjectExtendedLimitInformation,
            ctypes.byref(info), ctypes.sizeof(info)),
            "SetInformationJobObject")

        try:
            created = k32.CreateProcessW(
                ctypes.c_wchar_p(self._python),
                ctypes.c_wchar_p(cmdline),
                None, None, True,
                _CREATE_SUSPENDED | _EXTENDED_STARTUPINFO_PRESENT
                | _CREATE_UNICODE_ENVIRONMENT,
                ctypes.cast(env_buf, ctypes.c_void_p),
                ctypes.c_wchar_p(spec.workspace),
                ctypes.byref(si), ctypes.byref(pi))
            _check(created, "CreateProcessW")
            try:
                _check(k32.AssignProcessToJobObject(h_job, pi.hProcess),
                       "AssignProcessToJobObject")
                k32.ResumeThread(pi.hThread)

                wait = k32.WaitForSingleObject(pi.hProcess, self._timeout_ms)
                if wait == _WAIT_TIMEOUT:
                    k32.TerminateJobObject(h_job, 1)
                    k32.WaitForSingleObject(pi.hProcess, 5000)
                    returncode = 1
                else:
                    code = wintypes.DWORD()
                    k32.GetExitCodeProcess(pi.hProcess, ctypes.byref(code))
                    returncode = int(code.value)
            finally:
                k32.CloseHandle(pi.hThread)
                k32.CloseHandle(pi.hProcess)
        finally:
            # Closing the job kills any survivor (kill-on-close); close std
            # handles so the output files are flushed and readable.
            k32.CloseHandle(h_job)
            k32.DeleteProcThreadAttributeList(attr_list)
            for h in (h_in, h_out, h_err):
                k32.CloseHandle(h)

        def _read(path):
            try:
                with open(path, "r", encoding="utf-8", errors="replace") as fh:
                    return fh.read()
            except FileNotFoundError:
                return ""

        return SandboxResult(returncode, _read(stdout_path), _read(stderr_path))


# ---- CLI: one-time setup / teardown of the Python runtime grants ----
def main(argv=None) -> int:
    import argparse

    parser = argparse.ArgumentParser(
        prog="sentinel-sandbox-setup",
        description="Set up (or tear down) the Windows AppContainer chef "
        "sandbox: a profile + read/execute grants on the Python runtime.")
    parser.add_argument("action", choices=["setup", "teardown", "status"])
    args = parser.parse_args(argv)

    if not _IS_WIN:
        print("AppContainer sandbox is Windows-only; nothing to do here.")
        return 1
    if args.action == "status":
        print("available: {}".format(is_available()))
        for p in AppContainerSandbox.runtime_paths():
            print("  runtime path: " + p)
        return 0
    if args.action == "setup":
        sid, granted = AppContainerSandbox.setup()
        print("AppContainer profile ready; package SID " + sid)
        for p in granted:
            print("  granted read+execute: " + p)
        return 0
    sid, removed = AppContainerSandbox.teardown()
    print("removed package SID grants (" + sid + ")")
    for p in removed:
        print("  revoked: " + p)
    return 0


def cli() -> None:
    sys.exit(main())


if __name__ == "__main__":
    sys.exit(main())
