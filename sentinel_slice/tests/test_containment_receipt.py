"""Containment class on receipts (v0.12a).

The receipt records which containment class ACTUALLY executed the order, so
the chain never claims a guarantee it didn't have. Pinned: every backend's
honest label; a fulfilled run under the default backend records
"subprocess-contract" (in the Receipt object AND the stored row); an
execution failure records it too (the failed run still HAD a containment
class); cashier rejections record None (nothing executed); the new key is
hash-bound — editing it in a stored row breaks verification at that exact
seq; and a chain with the new key verifies standalone (format evolution by
append, the v0.2 rule).
"""

import base64
import json
import subprocess
import sys
import uuid
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from sentinel_slice.attestor.mock import MockAttestor
from sentinel_slice.cashier.policy import Policy, PolicySet
from sentinel_slice.cashier.store import CashierStore
from sentinel_slice.chef.sandbox import (
    AppleVmSandbox,
    ContainerSandbox,
    SubprocessSandbox,
)
from sentinel_slice.ledger.receipts import Ledger
from sentinel_slice.loop import SentinelLoop
from sentinel_slice.menu.catalog import load_catalog
from sentinel_slice.spine.types import Order

SENTINEL_DIR = Path(__file__).resolve().parents[1]
REPO_ROOT = Path(__file__).resolve().parents[2]
MAILBOX = SENTINEL_DIR / "kitchen" / "fixtures" / "mailbox"
VERIFIER = SENTINEL_DIR / "verify_ledger.py"

DRAFT = "cap.email.draft_reply.v1"


def _loop(tmp_path):
    priv = Ed25519PrivateKey.generate()
    pub = tmp_path / "pub.pem"
    pub.write_bytes(priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo))
    return SentinelLoop(
        private_key=priv, ledger=Ledger(str(tmp_path / "ledger.db"), priv),
        menu=load_catalog(),
        policy_set=PolicySet([Policy(role="account_manager",
                                     allowed_capabilities=(DRAFT,),
                                     rate_limit_per_hour=20)]),
        store=CashierStore(), public_key_pem_path=str(pub),
        fixtures_root=str(MAILBOX), attestor=MockAttestor(),
        window_root=str(tmp_path / "win")), pub


def _order(thread="user.kenji/t-001", capability_id=DRAFT):
    return Order(order_id="ord-" + uuid.uuid4().hex, principal="user.kenji",
                 role="account_manager", capability_id=capability_id,
                 args={"thread_id": thread},
                 nonce="nonce-" + uuid.uuid4().hex,
                 ts="2026-06-11T00:00:00+00:00")


def test_backend_labels_are_exact():
    assert SubprocessSandbox().containment_class == "subprocess-contract"
    assert ContainerSandbox().containment_class == "container"
    assert ContainerSandbox(runtime="runsc").containment_class == "container+runsc"
    assert AppleVmSandbox().containment_class == "applevm"


def test_fulfilled_receipt_records_subprocess_contract(tmp_path):
    loop, _ = _loop(tmp_path)
    outcome = loop.place(_order())
    assert outcome.accepted
    receipt = loop.last_chef.receipt
    assert receipt.status == "FULFILLED"
    assert receipt.containment == "subprocess-contract"
    # And the STORED row carries the key (it is part of the hashed content).
    _seq, row = loop.ledger.read_all_raw()[-1]
    assert row["containment"] == "subprocess-contract"
    # Read-back round-trips it.
    assert loop.read_receipts()[-1].containment == "subprocess-contract"


def test_cashier_rejection_records_no_containment(tmp_path):
    loop, _ = _loop(tmp_path)
    outcome = loop.place(_order(thread="user.victim/t-001"))  # OUT_OF_SCOPE
    assert not outcome.accepted
    assert outcome.receipt.containment is None
    _seq, row = loop.ledger.read_all_raw()[-1]
    assert row["containment"] is None  # stored explicitly as null


def test_execution_failure_still_records_containment(tmp_path):
    """A chef that fails AFTER acceptance still ran somewhere — the
    EXECUTION_FAILED receipt names the containment class that ran it."""
    class ExplodingSandbox:
        containment_class = "subprocess-contract"

        def run(self, spec):
            from sentinel_slice.chef.sandbox import SandboxResult
            return SandboxResult(returncode=7, stdout="", stderr="boom")

    from sentinel_slice.chef.runner import run_chef
    from sentinel_slice.cashier.engine import process_order

    loop, _ = _loop(tmp_path)
    outcome = process_order(
        _order(), menu=loop.menu, policy_set=loop.policy_set,
        store=loop.store, ledger=loop.ledger, private_key=loop.private_key,
        spawn=None)
    assert outcome.accepted
    chef = run_chef(
        outcome.ticket, ledger=loop.ledger,
        public_key_pem_path=loop.public_key_pem_path,
        fixtures_root=loop.fixtures_root, attestor=loop.attestor,
        window_root=loop.window_root, sandbox=ExplodingSandbox())
    assert chef.returncode == 7
    assert chef.receipt.status == "REJECTED"
    assert chef.receipt.reason_code == "EXECUTION_FAILED"
    assert chef.receipt.containment == "subprocess-contract"


def test_backend_without_label_is_recorded_as_unknown(tmp_path):
    class AnonymousSandbox:
        def run(self, spec):
            from sentinel_slice.chef.sandbox import SandboxResult
            return SandboxResult(returncode=1, stdout="", stderr="")

    from sentinel_slice.chef.runner import run_chef
    from sentinel_slice.cashier.engine import process_order

    loop, _ = _loop(tmp_path)
    outcome = process_order(
        _order(), menu=loop.menu, policy_set=loop.policy_set,
        store=loop.store, ledger=loop.ledger, private_key=loop.private_key,
        spawn=None)
    chef = run_chef(
        outcome.ticket, ledger=loop.ledger,
        public_key_pem_path=loop.public_key_pem_path,
        fixtures_root=loop.fixtures_root, attestor=loop.attestor,
        window_root=loop.window_root, sandbox=AnonymousSandbox())
    assert chef.receipt.containment == "unknown"


def test_chain_with_containment_verifies_standalone(tmp_path):
    loop, pub = _loop(tmp_path)
    loop.place(_order())                              # FULFILLED, containment
    loop.place(_order(thread="user.victim/x"))        # REJECTED, containment null
    proc = subprocess.run(
        [sys.executable, str(VERIFIER), str(tmp_path / "ledger.db"), str(pub)],
        capture_output=True, text=True, cwd=str(REPO_ROOT))
    assert proc.returncode == 0, (proc.stdout, proc.stderr)
    assert proc.stdout.strip() == "OK verified=2"


def test_tampering_containment_breaks_the_chain_at_that_seq(tmp_path):
    """The claim is only worth anything if it is tamper-evident: upgrading a
    stored row's containment (say subprocess-contract -> appcontainer) must
    fail verification at exactly that row."""
    loop, pub = _loop(tmp_path)
    loop.place(_order())
    db = str(tmp_path / "ledger.db")

    import sqlite3
    conn = sqlite3.connect(db)
    seq, row_json = conn.execute(
        "SELECT seq, json FROM receipts ORDER BY seq DESC LIMIT 1").fetchone()
    row = json.loads(row_json)
    assert row["containment"] == "subprocess-contract"
    row["containment"] = "appcontainer"  # forge a stronger claim
    forged = json.dumps(row, sort_keys=True, separators=(",", ":"))
    # (Tampering uses raw sqlite on the test copy — the Ledger class itself
    # has no update path, which is the point.)
    conn.execute("UPDATE receipts SET json=? WHERE seq=?", (forged, seq))
    conn.commit()
    conn.close()

    proc = subprocess.run(
        [sys.executable, str(VERIFIER), db, str(pub)],
        capture_output=True, text=True, cwd=str(REPO_ROOT))
    assert proc.returncode == 1
    assert proc.stdout.strip() == "FAIL seq={} reason=hash_mismatch".format(seq)
