# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Yasir Qureshi
"""Regression: an accepted order whose chef FAILS must still leave an auditable
ledger row, and must not crash the diner (review #2, #3, #4, #5, #10).

Before the fix, a nonzero chef exit appended NO receipt and loop.place still
reported accepted=True, so run_honest read a draft that was never written and
crashed with FileNotFoundError, and run_slice's read_receipts()[-1] saw an
empty/stale chain.
"""

import subprocess
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from sentinel_slice.attestor.mock import MockAttestor
from sentinel_slice.cashier.engine import process_order
from sentinel_slice.cashier.policy import load_policy_set
from sentinel_slice.cashier.store import CashierStore
from sentinel_slice.chef.runner import run_chef
from sentinel_slice.diner.agent import make_honest_order, run_honest
from sentinel_slice.ledger.receipts import Ledger
from sentinel_slice.loop import SentinelLoop
from sentinel_slice.menu.catalog import load_catalog

SENTINEL_DIR = Path(__file__).resolve().parents[1]
REPO_ROOT = Path(__file__).resolve().parents[2]
VERIFIER = SENTINEL_DIR / "verify_ledger.py"


def _keypair(tmp_path):
    priv = Ed25519PrivateKey.generate()
    pub = tmp_path / "pub.pem"
    pub.write_bytes(priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ))
    return priv, pub


def _verify(db, pem):
    return subprocess.run(
        [sys.executable, str(VERIFIER), str(db), str(pem)],
        capture_output=True, text=True, cwd=str(REPO_ROOT),
    )


def test_run_chef_failure_appends_execution_failed_receipt(tmp_path):
    priv, pub = _keypair(tmp_path)
    ledger = Ledger(str(tmp_path / "l.db"), priv)
    menu, pset, store = load_catalog(), load_policy_set(), CashierStore()

    # Mint a real, validly-signed ticket (cashier accepts).
    out = process_order(
        make_honest_order(),
        menu=menu, policy_set=pset, store=store, ledger=ledger, private_key=priv,
    )
    assert out.accepted is True

    # Run the chef against an EMPTY fixtures root -> the fixture is missing ->
    # chef exits 4. The fix must append an EXECUTION_FAILED receipt, not crash.
    empty_root = tmp_path / "empty_mailbox"
    empty_root.mkdir()
    res = run_chef(
        out.ticket,
        ledger=ledger,
        public_key_pem_path=str(pub),
        fixtures_root=str(empty_root),
        attestor=MockAttestor(),
        window_root=str(tmp_path / "win"),
    )

    assert res.returncode != 0
    assert res.draft_bytes is None
    assert res.result_digest is None
    assert res.receipt is not None
    assert res.receipt.status == "REJECTED"
    assert res.receipt.reason_code == "EXECUTION_FAILED"
    assert res.receipt.ticket_id == out.ticket.ticket_id
    assert res.receipt.result_digest is None
    assert res.receipt.attestation is None

    # Exactly one ledger row for the accepted-but-failed order, and it verifies.
    rows = ledger.read_all()
    assert len(rows) == 1
    assert rows[-1].reason_code == "EXECUTION_FAILED"
    v = _verify(tmp_path / "l.db", pub)
    assert v.returncode == 0
    assert v.stdout.strip() == "OK verified=1"


def test_honest_run_survives_chef_failure_without_crash(tmp_path):
    priv, pub = _keypair(tmp_path)
    ledger = Ledger(str(tmp_path / "l.db"), priv)
    empty_root = tmp_path / "empty_mailbox"
    empty_root.mkdir()

    loop = SentinelLoop(
        private_key=priv,
        ledger=ledger,
        menu=load_catalog(),
        policy_set=load_policy_set(),
        store=CashierStore(),
        public_key_pem_path=str(pub),
        fixtures_root=str(empty_root),   # benign fixture absent -> chef fails
        attestor=MockAttestor(),
        window_root=str(tmp_path / "win"),
    )

    # Must NOT raise FileNotFoundError.
    result = run_honest(loop)
    assert result["accepted"] is True       # cashier accepted
    assert result["fulfilled"] is False     # chef did not produce a draft
    assert result["draft"] is None

    # The order is still auditable: one EXECUTION_FAILED row, chain verifies.
    rows = loop.read_receipts()
    assert len(rows) == 1
    assert rows[-1].status == "REJECTED"
    assert rows[-1].reason_code == "EXECUTION_FAILED"
    v = _verify(tmp_path / "l.db", pub)
    assert v.returncode == 0
    assert v.stdout.strip() == "OK verified=1"
