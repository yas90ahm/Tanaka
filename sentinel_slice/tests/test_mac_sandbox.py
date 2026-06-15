"""MacSandbox — the macOS Seatbelt microsandbox via `sandbox-exec`.

Run-anywhere bars: honest label; the exact network-deny argv is asserted
(pure construction, like ContainerSandbox); off-macOS it is unavailable and
refuses (fail-closed). Gated REAL-isolation proofs (macOS +
SENTINEL_TEST_MAC_SANDBOX=1): the Seatbelt profile actually denies a network
operation at the kernel, and a real chef under it produces the SAME draft as
the unconfined subprocess while the receipt records containment="macsandbox".
"""

import os
import subprocess
import sys

import pytest

from sentinel_slice.chef import mac_sandbox
from sentinel_slice.chef.mac_sandbox import MacSandbox
from sentinel_slice.chef.sandbox import SandboxSpec

_MAC = sys.platform == "darwin"
_GATED = os.environ.get("SENTINEL_TEST_MAC_SANDBOX") == "1"


def test_containment_label_is_macsandbox():
    assert MacSandbox().containment_class == "macsandbox"


def test_build_command_denies_network():
    spec = SandboxSpec(chef_main="/c/chef.py", pubkey_path="/c/pub.pem",
                       fixtures_root="/k", out_dir="/w/out",
                       workspace="/w", stdin="")
    cmd = MacSandbox().build_command(spec)
    assert cmd[:3] == ["sandbox-exec", "-p", "(version 1)(allow default)(deny network*)"]
    assert cmd[3] == sys.executable
    assert cmd[4:] == ["/c/chef.py", "/c/pub.pem", "/k", "/w/out"]


@pytest.mark.skipif(_MAC, reason="off-macOS degradation check")
def test_off_mac_is_unavailable_and_refuses():
    sb = MacSandbox()
    assert sb.is_available() is False
    spec = SandboxSpec(chef_main="x", pubkey_path="x", fixtures_root="x",
                       out_dir="x", workspace=".", stdin="")
    with pytest.raises(RuntimeError):
        sb.run(spec)


@pytest.mark.skipif(not (_MAC and _GATED),
                    reason="real isolation: macOS + SENTINEL_TEST_MAC_SANDBOX=1")
def test_seatbelt_denies_network_operation():
    prog = (
        "import socket\n"
        "s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
        "try:\n"
        "    s.bind(('127.0.0.1', 0))\n"
        "    print('BIND_OK')\n"
        "except OSError as e:\n"
        "    print('BIND_BLOCKED', e.errno)\n"
    )
    blocked = subprocess.run(
        ["sandbox-exec", "-p", mac_sandbox._PROFILE, sys.executable, "-c", prog],
        capture_output=True, text=True,
    )
    assert "BIND_OK" not in blocked.stdout, blocked.stdout + blocked.stderr
    assert "BIND_BLOCKED" in blocked.stdout, blocked.stdout + blocked.stderr

    # Control: the SAME program WITHOUT the profile binds fine — proving the
    # denial is the Seatbelt profile, not the environment.
    control = subprocess.run([sys.executable, "-c", prog],
                             capture_output=True, text=True)
    assert "BIND_OK" in control.stdout, control.stdout + control.stderr


@pytest.mark.skipif(not (_MAC and _GATED),
                    reason="real isolation: macOS + SENTINEL_TEST_MAC_SANDBOX=1")
def test_real_chef_under_macsandbox_matches_subprocess(tmp_path):
    import uuid

    from sentinel_slice.chef.sandbox import SubprocessSandbox
    from sentinel_slice.keygen import generate_keypair
    from sentinel_slice.loop import build_default
    from sentinel_slice.spine.types import Order

    keys = tmp_path / "keys"
    generate_keypair(str(keys))

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
        out = loop.place(order)
        return out, loop.last_chef

    out_sub, chef_sub = run_once(SubprocessSandbox(), "sub")
    out_mac, chef_mac = run_once(MacSandbox(), "mac")

    assert out_sub.accepted and out_mac.accepted
    assert chef_sub.returncode == 0 and chef_mac.returncode == 0
    assert chef_mac.draft_bytes is not None
    assert chef_mac.draft_bytes == chef_sub.draft_bytes
    assert chef_mac.draft_bytes.startswith(b"Re:")
    assert chef_mac.receipt.containment == "macsandbox"
