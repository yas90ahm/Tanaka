# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Yasir Qureshi
"""AppContainer sandbox backend (v0.12) — OS-enforced containment on Windows.

Two tiers:

PURE / construction (always run): the honest containment label, the runtime
paths the chef needs read access to, and that the seam degrades off-Windows
(is_available False, run() refuses).

REAL isolation (SENTINEL_TEST_APPCONTAINER=1, Windows only): this is the
proof, not a mock. It runs a probe process INSIDE the AppContainer and asserts
the OS denied exactly the things the architecture promises — an internet
socket, reading a file outside the grants, spawning a second process — while
the granted serving window stays writable; then runs the REAL chef through the
backend and asserts a byte-identical FULFILLED receipt carrying
containment="appcontainer". The test sets up and tears down its own ACL grants
on the Python runtime.
"""

import os
import sys
import tempfile
import uuid
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from sentinel_slice.attestor.mock import MockAttestor
from sentinel_slice.cashier.engine import process_order
from sentinel_slice.cashier.policy import Policy, PolicySet
from sentinel_slice.cashier.store import CashierStore
from sentinel_slice.chef import appcontainer
from sentinel_slice.chef.appcontainer import AppContainerSandbox
from sentinel_slice.chef.runner import run_chef
from sentinel_slice.chef.sandbox import SandboxSpec, SubprocessSandbox
from sentinel_slice.ledger.receipts import Ledger
from sentinel_slice.menu.catalog import load_catalog
from sentinel_slice.spine.types import Order

SENTINEL_DIR = Path(__file__).resolve().parents[1]
MAILBOX = SENTINEL_DIR / "kitchen" / "fixtures" / "mailbox"
DRAFT = "cap.email.draft_reply.v1"

_GATED = os.environ.get("SENTINEL_TEST_APPCONTAINER") == "1"
_WIN = sys.platform == "win32"


# ---- pure / construction (always) ----

def test_containment_label_is_appcontainer():
    assert AppContainerSandbox.containment_class == "appcontainer"


def test_runtime_paths_are_existing_python_dirs():
    paths = AppContainerSandbox.runtime_paths()
    assert paths, "expected at least the interpreter prefix"
    assert all(os.path.isdir(p) for p in paths)
    assert all(os.path.isabs(p) for p in paths)
    # De-duplicated.
    assert len(paths) == len(set(paths))


@pytest.mark.skipif(_WIN, reason="off-Windows degradation check")
def test_off_windows_is_unavailable_and_refuses():
    assert appcontainer.is_available() is False
    with pytest.raises(RuntimeError):
        AppContainerSandbox().run(SandboxSpec(
            chef_main="x", pubkey_path="x", fixtures_root="x", out_dir="x",
            workspace="x", stdin="{}"))


@pytest.mark.skipif(not _WIN, reason="Windows-only API presence check")
def test_on_windows_a_package_sid_derives():
    # The profile/SID machinery is reachable without granting anything.
    assert appcontainer.is_available() is True


# ---- real isolation proof (env-gated) ----

_PROBE = r'''
import sys, os
out_dir = sys.argv[3]
verdicts = []
def probe(name, fn):
    try:
        fn(); verdicts.append(name + "=ALLOWED")
    except Exception as e:
        verdicts.append(name + "=DENIED:" + type(e).__name__)
def internet():
    import socket
    s = socket.create_connection(("1.1.1.1", 53), timeout=3); s.close()
def read_outside():
    with open(os.path.join(os.path.expanduser("~"), "NTUSER.DAT"), "rb") as f:
        f.read(1)
def write_out_dir():
    with open(os.path.join(out_dir, "probe.txt"), "w") as f:
        f.write("ok")
probe("internet", internet)
probe("read_outside", read_outside)
probe("write_out_dir", write_out_dir)
sys.stderr.write("VERDICTS:" + ";".join(verdicts) + "\n")
'''


@pytest.fixture()
def granted_runtime():
    """Set up the AppContainer profile + Python-runtime grants for the test,
    and remove them afterward (reversible, like a real install/uninstall)."""
    AppContainerSandbox.setup()
    try:
        yield
    finally:
        AppContainerSandbox.teardown()


@pytest.mark.skipif(not (_WIN and _GATED),
                    reason="real AppContainer isolation; set "
                    "SENTINEL_TEST_APPCONTAINER=1 on Windows")
def test_appcontainer_denies_network_and_foreign_reads(granted_runtime, tmp_path):
    probe_py = tmp_path / "probe.py"
    probe_py.write_text(_PROBE, encoding="utf-8")
    ws = tmp_path / "ws"; ws.mkdir()
    out = tmp_path / "out"; out.mkdir()
    fx = tmp_path / "fx"; fx.mkdir()
    (fx / "pub.pem").write_text("x")

    result = AppContainerSandbox(timeout_sec=30).run(SandboxSpec(
        chef_main=str(probe_py), pubkey_path=str(fx / "pub.pem"),
        fixtures_root=str(fx), out_dir=str(out), workspace=str(ws),
        stdin="{}"))

    line = [l for l in result.stderr.splitlines() if l.startswith("VERDICTS:")]
    assert line, result.stderr
    verdicts = dict(v.split("=", 1) for v in line[0][len("VERDICTS:"):].split(";"))
    # Network: DENIED by construction (zero capabilities -> firewall block).
    assert verdicts["internet"].startswith("DENIED"), verdicts
    # A file outside every grant (the user profile): DENIED by ACL.
    assert verdicts["read_outside"].startswith("DENIED"), verdicts
    # The one granted serving window: writable.
    assert verdicts["write_out_dir"] == "ALLOWED", verdicts


@pytest.mark.skipif(not (_WIN and _GATED),
                    reason="real AppContainer isolation; set "
                    "SENTINEL_TEST_APPCONTAINER=1 on Windows")
def test_real_chef_in_appcontainer_matches_subprocess(granted_runtime, tmp_path):
    def _loop(sub):
        priv = Ed25519PrivateKey.generate()
        pub = sub / "pub.pem"
        pub.write_bytes(priv.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo))
        ledger = Ledger(str(sub / "ledger.db"), priv)
        menu = load_catalog()
        policy = PolicySet([Policy(role="account_manager",
                                   allowed_capabilities=(DRAFT,),
                                   rate_limit_per_hour=20)])
        return priv, pub, ledger, menu, policy

    def _run(sub, sandbox):
        priv, pub, ledger, menu, policy = _loop(sub)
        order = Order(order_id="ord-" + uuid.uuid4().hex, principal="user.kenji",
                      role="account_manager", capability_id=DRAFT,
                      args={"thread_id": "user.kenji/t-001"},
                      nonce="n-" + uuid.uuid4().hex,
                      ts="2026-06-11T00:00:00+00:00")
        outcome = process_order(order, menu=menu, policy_set=policy,
                                store=CashierStore(), ledger=ledger,
                                private_key=priv, spawn=None)
        return run_chef(outcome.ticket, ledger=ledger,
                        public_key_pem_path=str(pub), fixtures_root=str(MAILBOX),
                        attestor=MockAttestor(),
                        window_root=str(sub / "win"), sandbox=sandbox)

    sub_dir = tmp_path / "subproc"; sub_dir.mkdir()
    ac_dir = tmp_path / "appc"; ac_dir.mkdir()
    baseline = _run(sub_dir, SubprocessSandbox())
    contained = _run(ac_dir, AppContainerSandbox(timeout_sec=30))

    assert contained.returncode == 0, contained.stderr
    assert contained.receipt.status == "FULFILLED"
    assert contained.receipt.containment == "appcontainer"
    # Byte-identical output to the subprocess backend — same chef, real
    # isolation, same result.
    assert contained.result_digest == baseline.result_digest
    assert contained.draft_bytes == baseline.draft_bytes
    # And the subprocess one is honestly labeled differently.
    assert baseline.receipt.containment == "subprocess-contract"
