"""MicroVmSandbox — the chef in a real KVM virtual machine.

Run-anywhere: honest label; the exact QEMU argv is asserted (snapshot=on for an
ephemeral VM); off-platform it is unavailable and refuses (fail-closed). Gated
REAL proof (Linux + /dev/kvm + a prebuilt rootfs/kernel + SENTINEL_TEST_MICROVM=1):
a real chef runs THROUGH THE BACKEND inside a KVM VM and produces a draft
byte-identical to the subprocess backend, with containment recorded honestly.
"""

import os
import sys

import pytest

from sentinel_slice.chef import microvm_sandbox
from sentinel_slice.chef.microvm_sandbox import MicroVmSandbox
from sentinel_slice.chef.sandbox import SandboxSpec

_LINUX = sys.platform.startswith("linux")
_GATED = os.environ.get("SENTINEL_TEST_MICROVM") == "1"


def test_containment_label_is_microvm_kvm():
    assert MicroVmSandbox(rootfs="/r", kernel="/k").containment_class == "microvm-kvm"


def test_build_command_is_exact():
    sb = MicroVmSandbox(rootfs="/r.ext4", kernel="/k", initrd="/i", memory_mb=512)
    assert sb.build_command("/io.ext4") == [
        "qemu-system-x86_64", "-accel", "kvm", "-m", "512", "-smp", "1",
        "-nographic", "-no-reboot", "-kernel", "/k", "-initrd", "/i",
        "-append", microvm_sandbox._BOOT_ARGS,
        "-drive", "file=/r.ext4,format=raw,if=virtio,snapshot=on",
        "-drive", "file=/io.ext4,format=raw,if=virtio",
    ]


def test_off_platform_is_unavailable_and_refuses(tmp_path):
    # No rootfs/kernel files (and almost certainly no /dev/kvm here).
    sb = MicroVmSandbox(rootfs=str(tmp_path / "nope.ext4"), kernel=str(tmp_path / "nope"))
    assert sb.is_available() is False
    spec = SandboxSpec(chef_main="x", pubkey_path="x", fixtures_root="x",
                       out_dir="x", workspace=".", stdin="")
    with pytest.raises(RuntimeError):
        sb.run(spec)


@pytest.mark.skipif(not (_LINUX and _GATED),
                    reason="real VM: Linux + /dev/kvm + rootfs/kernel + SENTINEL_TEST_MICROVM=1")
def test_real_chef_in_microvm_matches_subprocess(tmp_path):
    import uuid

    from sentinel_slice.chef.sandbox import SubprocessSandbox
    from sentinel_slice.keygen import generate_keypair
    from sentinel_slice.loop import build_default
    from sentinel_slice.spine.types import Order

    keys = tmp_path / "keys"
    generate_keypair(str(keys))

    def micro():
        return MicroVmSandbox(
            rootfs=os.environ["SENTINEL_MICROVM_ROOTFS"],
            kernel=os.environ["SENTINEL_MICROVM_KERNEL"],
            initrd=os.environ.get("SENTINEL_MICROVM_INITRD"))

    assert micro().is_available() is True

    def run_once(sandbox, tag):
        loop = build_default(
            str(tmp_path / (tag + ".db")),
            window_root=str(tmp_path / (tag + "_win")),
            keys_dir=str(keys), sandbox=sandbox)
        order = Order(
            order_id="ord-" + tag, principal="user.kenji",
            role="account_manager", capability_id="cap.email.draft_reply.v1",
            args={"thread_id": "user.kenji/t-001"},
            nonce="nonce-" + uuid.uuid4().hex, ts="2026-06-14T00:00:00+00:00")
        return loop.place(order), loop.last_chef

    out_sub, chef_sub = run_once(SubprocessSandbox(), "sub")
    out_vm, chef_vm = run_once(micro(), "vm")

    assert out_sub.accepted and out_vm.accepted
    assert chef_sub.returncode == 0 and chef_vm.returncode == 0
    assert chef_vm.draft_bytes is not None
    assert chef_vm.draft_bytes == chef_sub.draft_bytes
    assert chef_vm.draft_bytes.startswith(b"Re:")
    assert chef_vm.receipt.containment == "microvm-kvm"
