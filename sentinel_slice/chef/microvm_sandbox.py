# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Yasir Qureshi
"""Linux microVM sandbox — the chef runs inside a real KVM virtual machine.

This is the rung ABOVE the OS sandboxes (seccomp/Landlock/AppContainer/Seatbelt):
the chef gets its OWN kernel inside a hardware-accelerated VM (QEMU/KVM), so a
kernel exploit in a hostile chef hits the throwaway guest kernel, not the host.

How it runs one order:
  - a prebuilt rootfs (Python + cryptography + the Sentinel package + a tiny
    busybox init, built by microvm/Dockerfile.rootfs) boots under QEMU/KVM,
    copy-on-write (`snapshot=on`) so the VM is ephemeral and the image is shared;
  - the signed ticket, the cashier PUBLIC key, and the fixtures ride in on a
    small ext4 I/O disk; the guest init runs the real chef_main.py, which
    verifies the signature INSIDE the VM before doing anything, then writes the
    draft to the I/O disk;
  - the host extracts the draft with `debugfs` (no mount, no root) and hands it
    back through the serving window, exactly like every other backend.

Proven in CI (`microvm-isolation`): the in-VM chef's draft is byte-identical to
the same chef run outside the VM, and it's the chef's own signature gate that
runs in the guest.

Honest availability: needs Linux + /dev/kvm + qemu + e2fsprogs (mkfs.ext4 +
debugfs) + a prebuilt rootfs and kernel. `is_available()` reflects all of it;
`run()` raises where it cannot run, like the container / Apple-VM backends.
"""

import os
import shutil
import subprocess
import sys
import tempfile

from sentinel_slice.chef.sandbox import SandboxResult, SandboxSpec

# Where the rootfs image bakes the Sentinel package (see Dockerfile.rootfs).
_GUEST_CHEF = "/opt/sentinel/sentinel_slice/chef/chef_main.py"
_BOOT_ARGS = "console=ttyS0 root=/dev/vda rw init=/sbin/microvm-init panic=-1 reboot=t"


class MicroVmSandbox:
    """Run the chef in a per-order KVM virtual machine via QEMU."""

    containment_class = "microvm-kvm"

    def __init__(self, *, rootfs, kernel, initrd=None,
                 qemu="qemu-system-x86_64", memory_mb=1024, timeout=180) -> None:
        self._rootfs = rootfs
        self._kernel = kernel
        self._initrd = initrd
        self._qemu = qemu
        self._memory_mb = memory_mb
        self._timeout = timeout

    def is_available(self) -> bool:
        return (
            sys.platform.startswith("linux")
            and os.path.exists("/dev/kvm")
            and shutil.which(self._qemu) is not None
            and shutil.which("mkfs.ext4") is not None
            and shutil.which("debugfs") is not None
            and bool(self._rootfs) and os.path.isfile(self._rootfs)
            and bool(self._kernel) and os.path.isfile(self._kernel)
        )

    def build_command(self, io_image: str) -> list:
        """The exact QEMU argv. PURE — asserted by a test. `snapshot=on` on the
        rootfs makes the VM ephemeral (writes go to a discarded overlay) and the
        image shareable/read-only."""
        cmd = [
            self._qemu, "-accel", "kvm", "-m", str(self._memory_mb),
            "-smp", "1", "-nographic", "-no-reboot",
            "-kernel", self._kernel,
        ]
        if self._initrd:
            cmd += ["-initrd", self._initrd]
        cmd += [
            "-append", _BOOT_ARGS,
            "-drive", "file={},format=raw,if=virtio,snapshot=on".format(self._rootfs),
            "-drive", "file={},format=raw,if=virtio".format(io_image),
        ]
        return cmd

    def _stage_io(self, io_dir: str, spec: SandboxSpec) -> None:
        os.makedirs(os.path.join(io_dir, "out"), exist_ok=True)
        shutil.copyfile(spec.pubkey_path, os.path.join(io_dir, "pub.pem"))
        shutil.copytree(spec.fixtures_root, os.path.join(io_dir, "fixtures"))
        with open(os.path.join(io_dir, "ticket.json"), "w", encoding="utf-8") as fh:
            fh.write(spec.stdin)
        with open(os.path.join(io_dir, "run.sh"), "w", encoding="utf-8") as fh:
            fh.write("python3 {} /io/pub.pem /io/fixtures /io/out "
                     "< /io/ticket.json\necho chef_exit=$?\n".format(_GUEST_CHEF))

    def run(self, spec: SandboxSpec) -> SandboxResult:
        if not self.is_available():
            raise RuntimeError(
                "MicroVmSandbox needs Linux + /dev/kvm + qemu + e2fsprogs and a "
                "prebuilt rootfs/kernel; not available here.")
        work = tempfile.mkdtemp(prefix="microvm_")
        try:
            io_dir = os.path.join(work, "io")
            os.makedirs(io_dir)
            self._stage_io(io_dir, spec)
            io_img = os.path.join(work, "io.ext4")
            subprocess.run(["dd", "if=/dev/zero", "of=" + io_img, "bs=1M",
                            "count=64", "status=none"], check=True,
                           capture_output=True)
            subprocess.run(["mkfs.ext4", "-q", "-d", io_dir, io_img], check=True,
                           capture_output=True)
            try:
                proc = subprocess.run(self.build_command(io_img),
                                      capture_output=True, text=True,
                                      timeout=self._timeout)
                rc, err = proc.returncode, proc.stderr or ""
            except subprocess.TimeoutExpired:
                rc, err = 124, "microVM timed out"
            # Extract the draft from the I/O disk without mounting (no root).
            dest = os.path.join(work, "output.txt")
            subprocess.run(["debugfs", "-R", "dump /out/output.txt " + dest, io_img],
                           capture_output=True, text=True)
            if os.path.isfile(dest) and os.path.getsize(dest) > 0:
                os.makedirs(spec.out_dir, exist_ok=True)
                shutil.copyfile(dest, os.path.join(spec.out_dir, "output.txt"))
                return SandboxResult(0, "", err)
            return SandboxResult(rc or 1, "",
                                 err or "no chef output produced inside the microVM")
        finally:
            shutil.rmtree(work, ignore_errors=True)
