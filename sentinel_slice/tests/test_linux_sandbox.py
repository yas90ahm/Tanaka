# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Yasir Qureshi
"""LinuxSeccompSandbox — the in-process Linux microsandbox.

Run-anywhere bars: honest containment label; off-Linux it is unavailable and
refuses to run (fail-closed). Gated REAL-isolation proofs (Linux +
SENTINEL_TEST_LINUX_SANDBOX=1, mirroring the AppContainer gate): the seccomp
filter actually denies socket creation at the kernel, and a real chef run under
it produces the SAME draft as the unconfined subprocess while the receipt
honestly records containment="seccomp".
"""

import os
import subprocess
import sys

import pytest

from sentinel_slice.chef.linux_sandbox import (
    LinuxSeccompSandbox,
    install_network_seccomp,
    is_available,
)
from sentinel_slice.chef.sandbox import SandboxSpec

_LINUX = sys.platform.startswith("linux")
_GATED = os.environ.get("SENTINEL_TEST_LINUX_SANDBOX") == "1"


def test_containment_label_is_seccomp_landlock():
    assert LinuxSeccompSandbox().containment_class == "seccomp+landlock"


@pytest.mark.skipif(_LINUX, reason="off-Linux degradation check")
def test_off_linux_is_unavailable_and_refuses():
    assert is_available() is False
    sb = LinuxSeccompSandbox()
    assert sb.is_available() is False
    spec = SandboxSpec(chef_main="x", pubkey_path="x", fixtures_root="x",
                       out_dir="x", workspace=".", stdin="")
    with pytest.raises(RuntimeError):
        sb.run(spec)


@pytest.mark.skipif(not _LINUX, reason="Linux-only availability check")
def test_on_linux_is_available():
    # GitHub ubuntu runners (and any x86_64/aarch64 Linux) are supported.
    assert is_available() is True


@pytest.mark.skipif(not (_LINUX and _GATED),
                    reason="real isolation: Linux + SENTINEL_TEST_LINUX_SANDBOX=1")
def test_seccomp_denies_socket_creation():
    prog = (
        "import socket\n"
        "try:\n"
        "    socket.socket(socket.AF_INET, socket.SOCK_STREAM)\n"
        "    print('SOCKET_OK')\n"
        "except OSError as e:\n"
        "    print('BLOCKED', e.errno)\n"
    )
    blocked = subprocess.run(
        [sys.executable, "-c", prog],
        preexec_fn=install_network_seccomp,
        capture_output=True, text=True,
    )
    # The kernel made socket() fail with EACCES (13); no socket was created.
    assert "SOCKET_OK" not in blocked.stdout, blocked.stdout + blocked.stderr
    assert "BLOCKED 13" in blocked.stdout, blocked.stdout + blocked.stderr

    # Control: the SAME program WITHOUT the filter creates a socket fine —
    # proving the denial is the seccomp filter, not the environment.
    control = subprocess.run([sys.executable, "-c", prog],
                             capture_output=True, text=True)
    assert "SOCKET_OK" in control.stdout, control.stdout + control.stderr


@pytest.mark.skipif(not (_LINUX and _GATED),
                    reason="real isolation: Linux + SENTINEL_TEST_LINUX_SANDBOX=1")
def test_landlock_denies_reads_and_writes_outside_allowlist(tmp_path):
    from sentinel_slice.chef.linux_sandbox import apply_landlock, python_read_roots

    allowed = tmp_path / "allowed"
    allowed.mkdir()
    (allowed / "ok.txt").write_text("INSIDE", encoding="utf-8")
    secret = tmp_path / "secret.txt"          # NOT under any granted root
    secret.write_text("TOPSECRET", encoding="utf-8")
    outdir = tmp_path / "out"
    outdir.mkdir()

    prog = (
        "print('INSIDE_READ', open(r'{ok}').read())\n"
        "try:\n"
        "    open(r'{secret}').read(); print('SECRET_READ_OK')\n"
        "except OSError as e:\n"
        "    print('SECRET_BLOCKED', e.errno)\n"
        "try:\n"
        "    open(r'{newp}', 'w').write('x'); print('WRITE_OK')\n"
        "except OSError as e:\n"
        "    print('WRITE_BLOCKED', e.errno)\n"
        "open(r'{outp}', 'w').write('y'); print('WRITE_GRANTED_OK')\n"
    ).format(ok=allowed / "ok.txt", secret=secret,
             newp=tmp_path / "new.txt", outp=outdir / "draft.txt")

    def preexec():
        apply_landlock(read_exec_roots=python_read_roots() + [str(allowed)],
                       read_roots=[], write_roots=[str(outdir)])

    proc = subprocess.run(
        [sys.executable, "-c", prog], preexec_fn=preexec,
        capture_output=True, text=True,
        env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1"))
    out = proc.stdout + proc.stderr
    assert "INSIDE_READ INSIDE" in out, out      # granted read works (python ran)
    assert "SECRET_READ_OK" not in out, out      # read outside the allow-list...
    assert "SECRET_BLOCKED" in out, out          # ...is denied by the kernel
    assert "WRITE_OK" not in out, out            # write outside the allow-list...
    assert "WRITE_BLOCKED" in out, out           # ...is denied
    assert "WRITE_GRANTED_OK" in out, out        # write to the granted dir works


@pytest.mark.skipif(not (_LINUX and _GATED),
                    reason="real isolation: Linux + SENTINEL_TEST_LINUX_SANDBOX=1")
def test_real_chef_under_seccomp_matches_subprocess(tmp_path):
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
    out_sec, chef_sec = run_once(LinuxSeccompSandbox(), "sec")

    # The confined chef did real work and produced the SAME draft as unconfined.
    assert out_sub.accepted and out_sec.accepted
    assert chef_sub.returncode == 0 and chef_sec.returncode == 0
    assert chef_sec.draft_bytes is not None
    assert chef_sec.draft_bytes == chef_sub.draft_bytes
    assert chef_sec.draft_bytes.startswith(b"Re:")
    # And the receipt honestly records the containment that actually ran.
    assert chef_sec.receipt.containment == "seccomp+landlock"
