# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Yasir Qureshi
"""Sandbox backends — the containment seam behind the chef.

ARCHITECTURE promised that the chef's execution environment is a swap behind a
contract whose replacement changes no type signature. This module makes that
literal: `run_chef` talks to a `Sandbox`, and the backend is interchangeable.

Backends, weakest to strongest:

- `SubprocessSandbox` (default) — a fresh OS subprocess. Combined with the
  chef's network-free import closure and workspace deletion, this proves the
  CONTRACT the real system must honor. It is NOT an isolation GUARANTEE: it
  does not contain a hostile chef. (Same honesty as SPEC's "sandbox" flag.)

- `ContainerSandbox` — runs the chef inside a hardened OCI container
  (no network, all capabilities dropped, read-only rootfs, non-root,
  pid-limited, no-new-privileges), optionally under gVisor (`runtime="runsc"`)
  for a real user-space-kernel isolation boundary — the "Agent Sandbox / gVisor"
  layer the essays name. This is genuine isolation WHEN RUN on Linux with a
  container runtime (+ gVisor). It is NOT exercised on non-Linux / no-runtime
  hosts: its command CONSTRUCTION is unit-tested exactly, and the integration
  path runs only where `is_available()` is true. A Firecracker microVM backend
  would slot in here behind the same `run()` signature.

No backend here imports anything heavy at module load; `ContainerSandbox`
shells out to the runtime binary only when actually run.
"""

import shutil
import subprocess
import sys
from dataclasses import dataclass


@dataclass(frozen=True)
class SandboxResult:
    """The minimal result `run_chef` needs from any backend: the chef's exit
    code and captured streams. The draft itself is read back from the serving
    window by the runner, not returned here."""
    returncode: int
    stdout: str
    stderr: str


@dataclass(frozen=True)
class SandboxSpec:
    """Everything a backend needs to run one chef invocation. Paths are host
    paths; a container backend maps them into the guest. `argv_after_program`
    are the chef's CLI args (pubkey, fixtures_root, out_dir) — note a container
    backend rewrites these to the IN-CONTAINER paths it mounts them at."""
    chef_main: str          # path to chef_main.py on the host
    pubkey_path: str        # cashier public key PEM (read-only input)
    fixtures_root: str      # kitchen fixtures root (read-only input)
    out_dir: str            # serving-window dir for this order (read-write)
    workspace: str          # ephemeral cwd (destroyed by the runner)
    stdin: str              # the signed ticket JSON on stdin


class SubprocessSandbox:
    """Default backend: a fresh subprocess. Contract, not guarantee."""

    # v0.12: every backend names its containment class honestly; the runner
    # records it on the receipt, so the chain never claims a guarantee the
    # execution didn't have.
    containment_class = "subprocess-contract"

    def run(self, spec: SandboxSpec) -> SandboxResult:
        proc = subprocess.run(
            [sys.executable, spec.chef_main, spec.pubkey_path,
             spec.fixtures_root, spec.out_dir],
            input=spec.stdin,
            capture_output=True,
            text=True,
            cwd=spec.workspace,
        )
        return SandboxResult(proc.returncode, proc.stdout, proc.stderr)


# In-container mount points for ContainerSandbox (fixed, read-only vs rw).
_GUEST_CHEF = "/chef/chef_main.py"
_GUEST_PUBKEY = "/chef/pubkey.pem"
_GUEST_FIXTURES = "/kitchen"
_GUEST_OUT = "/window"


class ContainerSandbox:
    """Hardened container backend, optionally gVisor.

    REAL isolation when run on Linux with a container runtime (+ gVisor). Not
    run on hosts where `is_available()` is False (e.g. Windows without Docker);
    `build_command` is pure and unit-tested so the security-relevant flags are
    verified regardless of whether a runtime is present here.

    The image must contain Python + cryptography to run the standalone chef.
    """

    def __init__(self, *, runtime=None, image="python:3.12-slim",
                 docker="docker", pids_limit=64, memory="256m",
                 user="65534:65534") -> None:
        self._runtime = runtime          # e.g. "runsc" for gVisor; None = host default
        self._image = image
        self._docker = docker
        self._pids_limit = pids_limit
        self._memory = memory
        # Run as a non-root uid:gid. Default nobody:nogroup for max restriction;
        # override to a uid that owns the bind-mounted window dir when the host
        # must read the output back (e.g. CI passes the runner's own uid).
        self._user = user

    @property
    def containment_class(self) -> str:
        """Honest label for receipts: a plain hardened container, or one under
        an alternate runtime (e.g. "container+runsc" = gVisor)."""
        return "container" if not self._runtime else "container+" + self._runtime

    def is_available(self) -> bool:
        """True only if the container runtime binary is on PATH. The actual
        run still needs the daemon up and the image pulled."""
        return shutil.which(self._docker) is not None

    def build_command(self, spec: SandboxSpec) -> list[str]:
        """Construct the hardened run argv. PURE — no side effects — so the
        isolation flags can be asserted exactly in a test."""
        cmd = [self._docker, "run", "--rm", "-i"]
        # Isolation hardening:
        cmd += ["--network", "none"]            # no network reachability
        cmd += ["--cap-drop", "ALL"]            # drop all Linux capabilities
        cmd += ["--security-opt", "no-new-privileges"]
        cmd += ["--read-only"]                  # read-only root filesystem
        cmd += ["--pids-limit", str(self._pids_limit)]
        cmd += ["--memory", self._memory]
        cmd += ["--user", self._user]           # non-root
        cmd += ["-e", "PYTHONDONTWRITEBYTECODE=1"]  # ro rootfs: don't try .pyc
        if self._runtime:
            cmd += ["--runtime", self._runtime]  # gVisor (runsc) etc.
        # Mounts: code + inputs read-only, the serving window read-write, and a
        # writable tmpfs for the ephemeral cwd (rootfs is read-only).
        cmd += ["-v", "{}:{}:ro".format(spec.chef_main, _GUEST_CHEF)]
        cmd += ["-v", "{}:{}:ro".format(spec.pubkey_path, _GUEST_PUBKEY)]
        cmd += ["-v", "{}:{}:ro".format(spec.fixtures_root, _GUEST_FIXTURES)]
        cmd += ["-v", "{}:{}".format(spec.out_dir, _GUEST_OUT)]
        cmd += ["--tmpfs", "/work"]
        cmd += ["-w", "/work"]
        cmd += [self._image]
        # The chef, with IN-CONTAINER paths.
        cmd += ["python", _GUEST_CHEF, _GUEST_PUBKEY, _GUEST_FIXTURES, _GUEST_OUT]
        return cmd

    def run(self, spec: SandboxSpec) -> SandboxResult:
        if not self.is_available():
            raise RuntimeError(
                "container runtime {!r} not found on PATH; ContainerSandbox "
                "needs Linux + a container runtime (+ gVisor for runsc).".format(
                    self._docker)
            )
        proc = subprocess.run(
            self.build_command(spec),
            input=spec.stdin,
            capture_output=True,
            text=True,
        )
        return SandboxResult(proc.returncode, proc.stdout, proc.stderr)


# In-VM mount points for AppleVmSandbox (mirror the container layout).
_VM_WORK = "/work"


class AppleVmSandbox:
    """macOS microVM backend via Apple's `container` tool (WWDC 2025).

    Apple's `container` runs each Linux container in its OWN lightweight
    virtual machine on Virtualization.framework — a per-order HARDWARE
    isolation boundary, built into macOS, needing no Docker. That makes it a
    genuinely stronger rung than `AppContainerSandbox` (which is an OS sandbox
    sharing the host kernel): a true microVM, the boundary the essays name,
    shipped to a consumer Mac with zero third-party install.

    Like `ContainerSandbox`, this is exercised only where it CAN be: command
    CONSTRUCTION is pure and unit-tested exactly; `run()` shells out to
    `container` and refuses off-macOS / when the binary is absent. It is NOT
    run on this Windows dev box (no Apple silicon, no `container`) — so, per
    the project's honesty rule, it is asserted by construction, never claimed
    to have executed here.

    HONEST CONTAINMENT NOTES (these ride on the receipt as
    `containment="applevm"`, never as something it isn't):
      - The isolation guarantee is the VM boundary + ephemerality (`--rm`
        destroys the VM per order).
      - NO-NETWORK IS NOT ASSERTED AT THE VM LEVEL. Apple's `container run`
        exposes no documented "disable all networking" flag (unlike Docker's
        `--network none`), so — unlike `ContainerSandbox` — this backend does
        NOT claim a VM-enforced network block. The chef's network-free import
        closure remains the no-network mechanism here until the tool grows a
        deny flag. Flagged, not papered over.

    The image must contain Python + cryptography to run the standalone chef.
    """

    def __init__(self, *, image="sentinel-chef", binary="container",
                 cpus=2, memory="1G", uid=None, gid=None) -> None:
        self._image = image
        self._binary = binary
        self._cpus = cpus
        self._memory = memory
        self._uid = uid
        self._gid = gid

    containment_class = "applevm"

    def is_available(self) -> bool:
        """True only on macOS with the `container` binary present. The actual
        run still needs the `container` system service started and the image
        built."""
        return sys.platform == "darwin" and shutil.which(self._binary) is not None

    def build_command(self, spec: SandboxSpec) -> list[str]:
        """The exact `container run` argv. PURE — asserted by test. Flags are
        the documented Apple `container` ones (-v host:guest[:ro], -w, -e,
        --rm, -i, -m, -c, --uid/--gid). No --network: see the class note (the
        tool exposes no disable-all-networking flag, so we don't fake one)."""
        cmd = [self._binary, "run", "--rm", "-i"]
        cmd += ["-m", self._memory]
        cmd += ["-c", str(self._cpus)]
        if self._uid is not None:
            cmd += ["--uid", str(self._uid)]
        if self._gid is not None:
            cmd += ["--gid", str(self._gid)]
        cmd += ["-e", "PYTHONDONTWRITEBYTECODE=1"]
        # Code + inputs read-only; serving window + ephemeral cwd read-write.
        cmd += ["-v", "{}:{}:ro".format(spec.chef_main, _GUEST_CHEF)]
        cmd += ["-v", "{}:{}:ro".format(spec.pubkey_path, _GUEST_PUBKEY)]
        cmd += ["-v", "{}:{}:ro".format(spec.fixtures_root, _GUEST_FIXTURES)]
        cmd += ["-v", "{}:{}".format(spec.out_dir, _GUEST_OUT)]
        cmd += ["-v", "{}:{}".format(spec.workspace, _VM_WORK)]
        cmd += ["-w", _VM_WORK]
        cmd += [self._image]
        # The chef, with IN-VM paths.
        cmd += ["python", _GUEST_CHEF, _GUEST_PUBKEY, _GUEST_FIXTURES, _GUEST_OUT]
        return cmd

    def run(self, spec: SandboxSpec) -> SandboxResult:
        if not self.is_available():
            raise RuntimeError(
                "AppleVmSandbox needs macOS (Apple silicon) and the "
                "`container` tool on PATH; not available here.")
        proc = subprocess.run(
            self.build_command(spec),
            input=spec.stdin,
            capture_output=True,
            text=True,
        )
        return SandboxResult(proc.returncode, proc.stdout, proc.stderr)
