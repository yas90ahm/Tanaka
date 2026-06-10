"""SPEC acceptance #1 — honest fulfillment + privacy invariant.

Mint a REAL ticket via the cashier, run the chef once via the runner, and
assert: the draft is the exact deterministic transform of the benign
fixture, a single FULFILLED receipt is appended carrying ONLY result_digest
+ a MOCK attestation, the distinctive fixture token NEVER appears in the
raw ledger.db bytes (privacy), exactly ONE chef subprocess is spawned, and
the resulting one-row chain verifies via the standalone verifier.
"""

import hashlib
import json
import os
import subprocess
import sys
import uuid
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from sentinel_slice.cashier.engine import process_order
from sentinel_slice.cashier.policy import load_policy_set
from sentinel_slice.cashier.store import CashierStore
from sentinel_slice.chef import runner as runner_mod
from sentinel_slice.chef import sandbox as sandbox_mod
from sentinel_slice.chef.runner import CHEF_MAIN, run_chef
from sentinel_slice.attestor.mock import MockAttestor
from sentinel_slice.ledger.receipts import Ledger
from sentinel_slice.menu.catalog import load_catalog
from sentinel_slice.spine.types import Order

REPO_ROOT = Path(__file__).resolve().parents[2]
FIXTURES_ROOT = Path(__file__).resolve().parents[1] / "kitchen" / "fixtures" / "mailbox"
VERIFIER = Path(__file__).resolve().parents[1] / "verify_ledger.py"

TOKEN = b"Acme Corp Q3 onboarding"
EXPECTED_DRAFT = (
    "Re: Acme Corp Q3 onboarding\n"
    "\n"
    "Thank you for your message. A draft reply has been prepared for your review.\n"
    "\n"
    "-- Sentinel Loop draft (no send performed)\n"
)


def _write_pub_pem(priv, tmp_path):
    pem = tmp_path / "pub.pem"
    pem.write_bytes(
        priv.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    return pem


def test_at01_honest(tmp_path, monkeypatch):
    priv = Ed25519PrivateKey.generate()
    db = tmp_path / "ledger.db"
    ledger = Ledger(str(db), priv)
    pem = _write_pub_pem(priv, tmp_path)

    menu = load_catalog()
    policy_set = load_policy_set()
    store = CashierStore()

    order = Order(
        order_id=f"ord-{uuid.uuid4().hex}",
        principal="user.kenji",
        role="account_manager",
        capability_id="cap.email.draft_reply.v1",
        args={"thread_id": "user.kenji/t-001"},
        nonce=f"nonce-{uuid.uuid4().hex}",
        ts="2026-06-09T00:00:00+00:00",
    )

    outcome = process_order(
        order,
        menu=menu,
        policy_set=policy_set,
        store=store,
        ledger=ledger,
        private_key=priv,
        spawn=None,
    )
    assert outcome.accepted is True
    ticket = outcome.ticket

    # Count chef-process spawns by wrapping subprocess.run inside the sandbox
    # backend (the default SubprocessSandbox is where the chef process is now
    # spawned, behind the runner's Sandbox seam).
    spawn_calls = {"n": 0}
    real_run = sandbox_mod.subprocess.run

    def counting_run(*args, **kwargs):
        spawn_calls["n"] += 1
        return real_run(*args, **kwargs)

    monkeypatch.setattr(sandbox_mod.subprocess, "run", counting_run)

    attestor = MockAttestor()
    res = run_chef(
        ticket,
        ledger=ledger,
        public_key_pem_path=str(pem),
        fixtures_root=str(FIXTURES_ROOT),
        attestor=attestor,
        window_root=str(tmp_path / "win"),
    )

    # --- fulfillment ---
    assert res.returncode == 0
    assert os.path.isfile(res.draft_path)
    assert os.path.basename(res.draft_path) == "output.txt"

    draft_bytes = open(res.draft_path, "rb").read()
    assert res.draft_bytes == draft_bytes
    assert TOKEN in draft_bytes  # the chef actually read the fixture
    assert res.draft_bytes.decode("utf-8") == EXPECTED_DRAFT  # exact transform
    assert res.result_digest == hashlib.sha256(draft_bytes).hexdigest()

    # --- the single FULFILLED receipt ---
    rows = ledger.read_all()
    assert len(rows) == 1
    assert rows[-1].status == "FULFILLED"
    assert rows[-1].reason_code is None
    assert rows[-1].ticket_id == ticket.ticket_id
    assert rows[-1].order_id == order.order_id
    assert rows[-1].result_digest == res.result_digest

    # --- MOCK attestation, with the real code-measurement ---
    measurement = hashlib.sha256(open(CHEF_MAIN, "rb").read()).hexdigest()
    assert rows[-1].attestation["mock"] is True
    assert rows[-1].attestation["attestor"] == "MockAttestor"
    assert rows[-1].attestation["measurement"] == measurement
    assert res.receipt.this_hash == rows[-1].this_hash

    # --- PRIVACY: no draft content leaks into the receipt / ledger bytes ---
    raw = open(str(db), "rb").read()
    assert TOKEN not in raw
    assert b"A draft reply has been prepared" not in raw
    # The receipt content JSON carries only digest + attestation, never text.
    receipt_content = json.dumps(
        {
            "receipt_id": rows[-1].receipt_id,
            "order_id": rows[-1].order_id,
            "ticket_id": rows[-1].ticket_id,
            "status": rows[-1].status,
            "reason_code": rows[-1].reason_code,
            "result_digest": rows[-1].result_digest,
            "attestation": rows[-1].attestation,
            "prev_hash": rows[-1].prev_hash,
        }
    )
    assert "Acme Corp Q3 onboarding" not in receipt_content
    assert "A draft reply has been prepared" not in receipt_content

    # --- exactly one chef subprocess spawned (assert before unpatching) ---
    # subprocess.run is a shared module attribute; restore it now so the
    # verifier invocation below is NOT counted as a chef spawn.
    assert spawn_calls["n"] == 1
    monkeypatch.setattr(sandbox_mod.subprocess, "run", real_run)

    # --- verifier over the one-row chain ---
    proc = subprocess.run(
        [sys.executable, str(VERIFIER), str(db), str(pem)],
        capture_output=True,
        text=True,
        cwd=str(REPO_ROOT),
    )
    assert proc.returncode == 0, (proc.stdout, proc.stderr)
    assert proc.stdout.strip() == "OK verified=1"
