"""Sandbox backends (v0.4) — the containment seam.

The default SubprocessSandbox is exercised by the whole existing suite (it's
what run_chef uses). Here we pin:
- run_chef talks to ANY Sandbox via the SandboxSpec contract (backend swap):
  a fake backend receives the right spec and its result flows through;
- ContainerSandbox builds the EXACT hardened command — the security-relevant
  flags (no network, all caps dropped, read-only rootfs, non-root, pid limit,
  no-new-privileges, gVisor runtime, ro inputs / rw window) are asserted
  literally, regardless of whether a container runtime exists here;
- a real container run is attempted ONLY where a runtime is available
  (skipped on Windows / no-Docker CI) — and is honest that it needs an image
  with Python + cryptography.
"""

import os
import shutil
import uuid
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from sentinel_slice.attestor.mock import MockAttestor
from sentinel_slice.cashier.engine import process_order
from sentinel_slice.cashier.policy import load_policy_set
from sentinel_slice.cashier.store import CashierStore
from sentinel_slice.chef.runner import run_chef
from sentinel_slice.chef.sandbox import (
    ContainerSandbox,
    SandboxResult,
    SandboxSpec,
    SubprocessSandbox,
)
from sentinel_slice.ledger.receipts import Ledger
from sentinel_slice.menu.catalog import load_catalog
from sentinel_slice.spine.types import Order

SENTINEL_DIR = Path(__file__).resolve().parents[1]
FIXTURES_ROOT = SENTINEL_DIR / "kitchen" / "fixtures" / "mailbox"


def _spec(tmp_path):
    return SandboxSpec(
        chef_main="/host/chef_main.py",
        pubkey_path="/host/pub.pem",
        fixtures_root="/host/mailbox",
        out_dir="/host/window/ord-1",
        workspace=str(tmp_path),
        stdin='{"ticket_id":"t"}',
    )


def test_container_command_is_hardened_and_exact(tmp_path):
    sb = ContainerSandbox(runtime="runsc", image="sentinel/chef:1",
                          pids_limit=64, memory="256m")
    cmd = sb.build_command(_spec(tmp_path))

    # The exact hardened argv (order matters for readability; assert as a whole).
    assert cmd == [
        "docker", "run", "--rm", "-i",
        "--network", "none",
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges",
        "--read-only",
        "--pids-limit", "64",
        "--memory", "256m",
        "--user", "65534:65534",
        "-e", "PYTHONDONTWRITEBYTECODE=1",
        "--runtime", "runsc",
        "-v", "/host/chef_main.py:/chef/chef_main.py:ro",
        "-v", "/host/pub.pem:/chef/pubkey.pem:ro",
        "-v", "/host/mailbox:/kitchen:ro",
        "-v", "/host/window/ord-1:/window",
        "--tmpfs", "/work",
        "-w", "/work",
        "sentinel/chef:1",
        "python", "/chef/chef_main.py", "/chef/pubkey.pem", "/kitchen", "/window",
    ]


def test_container_without_runtime_flag_omits_runsc(tmp_path):
    cmd = ContainerSandbox().build_command(_spec(tmp_path))
    assert "--runtime" not in cmd          # host default runtime
    # The hardening is still present without gVisor.
    for must in ("--network", "none", "--cap-drop", "ALL", "--read-only"):
        assert must in cmd


def test_container_run_refuses_when_runtime_absent(tmp_path):
    sb = ContainerSandbox(docker="definitely-not-a-real-binary-xyz")
    assert sb.is_available() is False
    with pytest.raises(RuntimeError):
        sb.run(_spec(tmp_path))


def test_run_chef_swaps_backend_via_contract(tmp_path):
    """run_chef must work against any Sandbox. A fake backend that actually
    writes the draft (as a real chef would) drives the FULFILLED path —
    proving the seam carries the spec and the result through."""
    priv = Ed25519PrivateKey.generate()
    pub = tmp_path / "pub.pem"
    pub.write_bytes(priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo))
    ledger = Ledger(str(tmp_path / "ledger.db"), priv)

    order = Order(order_id="ord-" + uuid.uuid4().hex, principal="user.kenji",
                  role="account_manager", capability_id="cap.email.draft_reply.v1",
                  args={"thread_id": "user.kenji/t-001"},
                  nonce="n-" + uuid.uuid4().hex, ts="2026-06-10T00:00:00+00:00")
    outcome = process_order(order, menu=load_catalog(), policy_set=load_policy_set(),
                            store=CashierStore(), ledger=ledger, private_key=priv,
                            spawn=None)
    assert outcome.accepted

    seen = {}

    class FakeSandbox:
        def run(self, spec: SandboxSpec) -> SandboxResult:
            seen["spec"] = spec
            # Behave like a successful chef: write the draft to out_dir.
            import os
            os.makedirs(spec.out_dir, exist_ok=True)
            with open(os.path.join(spec.out_dir, "output.txt"), "w",
                      encoding="utf-8", newline="\n") as fh:
                fh.write("Re: x\n")
            return SandboxResult(returncode=0, stdout="", stderr="")

    res = run_chef(outcome.ticket, ledger=ledger, public_key_pem_path=str(pub),
                   fixtures_root=str(FIXTURES_ROOT), attestor=MockAttestor(),
                   window_root=str(tmp_path / "win"), sandbox=FakeSandbox())

    # The seam handed the backend the real spec...
    assert seen["spec"].pubkey_path == str(pub)
    assert seen["spec"].fixtures_root == str(FIXTURES_ROOT)
    assert seen["spec"].stdin  # the signed ticket JSON
    # ...and the backend's success produced a FULFILLED receipt.
    assert res.returncode == 0
    assert res.receipt.status == "FULFILLED"
    assert res.draft_bytes == b"Re: x\n"


@pytest.mark.skipif(
    shutil.which("docker") is None,
    reason="no container runtime on PATH (expected on Windows / minimal CI); "
           "ContainerSandbox isolation is real only on Linux + Docker (+ gVisor)",
)
def test_container_runtime_present_builds_command(tmp_path):
    """Smoke: where Docker exists, the backend reports available and builds a
    docker command. (The full real run is the env-gated test below.)"""
    sb = ContainerSandbox()
    assert sb.is_available() is True
    assert sb.build_command(_spec(tmp_path))[0] == "docker"


@pytest.mark.skipif(
    os.environ.get("SENTINEL_TEST_CONTAINER") != "1",
    reason="real container run: set SENTINEL_TEST_CONTAINER=1 (+ build the "
           "chef image, optionally install gVisor). The Linux CI job does "
           "this; it proves the sandbox GUARANTEE, not just the contract.",
)
def test_container_real_chef_run_produces_signed_receipt(tmp_path):
    """THE PROOF: run a real chef inside a hardened container (optionally under
    gVisor) through run_chef, and assert it produced the exact draft + a
    FULFILLED receipt — i.e. the isolated backend is functionally identical to
    the subprocess one, just contained. Configured entirely by env so it runs
    only where a runtime + image exist:
        SENTINEL_SANDBOX_IMAGE  (default 'sentinel-chef')
        SENTINEL_SANDBOX_RUNTIME (e.g. 'runsc' for gVisor; unset = host)
    """
    image = os.environ.get("SENTINEL_SANDBOX_IMAGE", "sentinel-chef")
    runtime = os.environ.get("SENTINEL_SANDBOX_RUNTIME") or None
    # Map the container user to the host uid so writes to the bind-mounted
    # window dir are readable back by the test runner.
    uid_gid = "{}:{}".format(os.getuid(), os.getgid())  # POSIX-only; CI is Linux

    priv = Ed25519PrivateKey.generate()
    pub = tmp_path / "pub.pem"
    pub.write_bytes(priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo))
    ledger = Ledger(str(tmp_path / "ledger.db"), priv)

    order = Order(order_id="ord-" + uuid.uuid4().hex, principal="user.kenji",
                  role="account_manager", capability_id="cap.email.draft_reply.v1",
                  args={"thread_id": "user.kenji/t-001"},
                  nonce="n-" + uuid.uuid4().hex, ts="2026-06-10T00:00:00+00:00")
    outcome = process_order(order, menu=load_catalog(), policy_set=load_policy_set(),
                            store=CashierStore(), ledger=ledger, private_key=priv,
                            spawn=None)
    assert outcome.accepted

    sandbox = ContainerSandbox(runtime=runtime, image=image, user=uid_gid)
    res = run_chef(outcome.ticket, ledger=ledger, public_key_pem_path=str(pub),
                   fixtures_root=str(FIXTURES_ROOT), attestor=MockAttestor(),
                   window_root=str(tmp_path / "win"), sandbox=sandbox)

    assert res.returncode == 0, res.stderr
    assert res.receipt.status == "FULFILLED"
    assert res.draft_bytes.decode("utf-8").startswith("Re: Acme Corp Q3 onboarding")
