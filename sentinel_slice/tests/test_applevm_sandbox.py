"""AppleVmSandbox (v0.15) — macOS microVM backend, construction-tested.

Like ContainerSandbox before Linux CI ran it: the command CONSTRUCTION is the
contract, asserted exactly here (every Apple `container run` flag and the
mount layout), and `run()` refuses where it cannot execute. It is NOT run on
this Windows dev box — so it is proven by construction, never claimed to have
executed. The honest containment label and the off-platform refusal are
pinned too.
"""

import sys

import pytest

from sentinel_slice.chef.sandbox import AppleVmSandbox, SandboxSpec

SPEC = SandboxSpec(
    chef_main="/host/chef_main.py",
    pubkey_path="/host/pub.pem",
    fixtures_root="/host/mailbox",
    out_dir="/host/window/ord-1",
    workspace="/host/ws",
    stdin="{}",
)


def test_containment_label_is_applevm():
    assert AppleVmSandbox.containment_class == "applevm"


def test_build_command_is_exact():
    cmd = AppleVmSandbox(image="sentinel-chef", memory="1G", cpus=2).build_command(SPEC)
    assert cmd == [
        "container", "run", "--rm", "-i",
        "-m", "1G",
        "-c", "2",
        "-e", "PYTHONDONTWRITEBYTECODE=1",
        "-v", "/host/chef_main.py:/chef/chef_main.py:ro",
        "-v", "/host/pub.pem:/chef/pubkey.pem:ro",
        "-v", "/host/mailbox:/kitchen:ro",
        "-v", "/host/window/ord-1:/window",
        "-v", "/host/ws:/work",
        "-w", "/work",
        "sentinel-chef",
        "python", "/chef/chef_main.py", "/chef/pubkey.pem", "/kitchen", "/window",
    ]


def test_no_network_flag_is_absent_by_design():
    # Honesty: Apple `container` exposes no documented disable-all-networking
    # flag, so this backend must NOT emit a fake one (no --network none).
    cmd = AppleVmSandbox().build_command(SPEC)
    assert "--network" not in cmd
    assert "none" not in cmd


def test_code_and_inputs_are_read_only_window_is_writable():
    cmd = AppleVmSandbox().build_command(SPEC)
    joined = " ".join(cmd)
    # chef, pubkey, fixtures: :ro. window + work: NOT :ro.
    assert "/host/chef_main.py:/chef/chef_main.py:ro" in joined
    assert "/host/mailbox:/kitchen:ro" in joined
    assert "/host/window/ord-1:/window" in cmd  # exact element, no :ro suffix
    assert "/host/ws:/work" in cmd


def test_optional_uid_gid_emitted_only_when_set():
    base = AppleVmSandbox().build_command(SPEC)
    assert "--uid" not in base and "--gid" not in base
    with_ids = AppleVmSandbox(uid=65534, gid=65534).build_command(SPEC)
    assert with_ids[with_ids.index("--uid") + 1] == "65534"
    assert with_ids[with_ids.index("--gid") + 1] == "65534"


def test_custom_image_binary_resources():
    cmd = AppleVmSandbox(image="my-img", binary="container",
                         cpus=4, memory="2G").build_command(SPEC)
    assert cmd[0] == "container"
    assert cmd[cmd.index("-c") + 1] == "4"
    assert cmd[cmd.index("-m") + 1] == "2G"
    assert "my-img" in cmd


@pytest.mark.skipif(sys.platform == "darwin",
                    reason="off-macOS refusal check (this box is not a Mac)")
def test_run_refuses_off_macos():
    assert AppleVmSandbox().is_available() is False
    with pytest.raises(RuntimeError):
        AppleVmSandbox().run(SPEC)
