# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Yasir Qureshi
"""Honest end-to-end through the loop + the credential-boundary proof.

- test_honest_endtoend_fulfilled_and_private: the diner places an honest
  order via the loop; a chef draft is produced (exact deterministic transform
  of the benign fixture) and readable from the window; a single FULFILLED
  receipt carries result_digest == sha256(draft) and a MOCK attestation; the
  distinctive draft content NEVER appears in the raw ledger bytes (digest
  only); the one-row chain verifies standalone.
- test_diner_holds_no_credentials: the diner source references no key/signing
  primitive, and the Order it builds carries no signature field.

Loop is constructed DIRECTLY with a hermetic temp keypair/ledger/window and
the REAL mailbox fixtures root (so the chef reads the benign t-001 thread).
"""

import dataclasses
import hashlib
import subprocess
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from sentinel_slice.attestor.mock import MockAttestor
from sentinel_slice.cashier.policy import load_policy_set
from sentinel_slice.cashier.store import CashierStore
from sentinel_slice.diner.agent import make_honest_order, run_honest
from sentinel_slice.ledger.receipts import Ledger
from sentinel_slice.loop import SentinelLoop
from sentinel_slice.menu.catalog import load_catalog

SENTINEL_DIR = Path(__file__).resolve().parents[1]
REPO_ROOT = Path(__file__).resolve().parents[2]
MAILBOX = SENTINEL_DIR / "kitchen" / "fixtures" / "mailbox"
VERIFIER = SENTINEL_DIR / "verify_ledger.py"
DINER_SRC = SENTINEL_DIR / "diner" / "agent.py"

EXPECTED_DRAFT = (
    "Re: Acme Corp Q3 onboarding\n"
    "\n"
    "Thank you for your message. A draft reply has been prepared for your review.\n"
    "\n"
    "-- Sentinel Loop draft (no send performed)\n"
)


def _build_loop(tmp_path):
    priv = Ed25519PrivateKey.generate()
    pub = tmp_path / "pub.pem"
    pub.write_bytes(
        priv.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    ledger = Ledger(str(tmp_path / "ledger.db"), priv)
    loop = SentinelLoop(
        private_key=priv,
        ledger=ledger,
        menu=load_catalog(),
        policy_set=load_policy_set(),
        store=CashierStore(),
        public_key_pem_path=str(pub),
        fixtures_root=str(MAILBOX),
        attestor=MockAttestor(),
        window_root=str(tmp_path / "win"),
    )
    return loop, pub


def _run_verifier(db, pem):
    return subprocess.run(
        [sys.executable, str(VERIFIER), str(db), str(pem)],
        capture_output=True,
        text=True,
        cwd=str(REPO_ROOT),
    )


def test_honest_endtoend_fulfilled_and_private(tmp_path):
    loop, pem = _build_loop(tmp_path)

    result = run_honest(loop)

    assert result["accepted"] is True
    order_id = result["order_id"]

    # The diner reads the draft out of the window (bytes), and the file exists.
    draft = loop.read_window_draft(order_id)
    assert isinstance(draft, bytes)
    assert len(draft) > 0
    assert (tmp_path / "win" / order_id / "output.txt").is_file()
    assert draft.decode("utf-8") == EXPECTED_DRAFT

    # Exactly one FULFILLED receipt, digest-only with a MOCK attestation.
    rows = loop.read_receipts()
    assert len(rows) == 1
    assert rows[-1].status == "FULFILLED"
    assert rows[-1].reason_code is None
    assert rows[-1].result_digest == hashlib.sha256(draft).hexdigest()
    assert rows[-1].attestation["mock"] is True
    assert rows[-1].attestation["attestor"] == "MockAttestor"

    # PRIVACY: the draft content never leaks into the raw ledger bytes.
    raw = (tmp_path / "ledger.db").read_bytes()
    assert b"Acme Corp Q3 onboarding" not in raw
    assert b"A draft reply has been prepared" not in raw

    res = _run_verifier(tmp_path / "ledger.db", pem)
    assert res.returncode == 0, (res.stdout, res.stderr)
    assert res.stdout.strip() == "OK verified=1"


def test_diner_holds_no_credentials():
    src = DINER_SRC.read_text(encoding="utf-8").lower()
    for forbidden in ("private", "sign", ".pem", "ed25519", "load_pem"):
        assert forbidden not in src, f"diner source references {forbidden!r}"

    # The Order the diner builds carries no signature field whatsoever.
    fields = {f.name for f in dataclasses.fields(make_honest_order())}
    assert fields == {
        "order_id",
        "principal",
        "role",
        "capability_id",
        "args",
        "nonce",
        "ts",
    }
