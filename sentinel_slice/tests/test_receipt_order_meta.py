# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Yasir Qureshi
"""v0.2 receipt metadata — the receipt names everyone involved.

Essays (Essay 3): "The receipt names everyone involved: the diner, the
cashier, the chef, the station, the time, the order..." Before v0.2 receipts
carried no principal/role/capability/ts, leaving the inspector blind. These
tests pin the new contract exactly:

- a REJECTED receipt carries the exact 4-key order_meta of the rejected order;
- a FULFILLED receipt carries the exact 4-key order_meta of the fulfilling
  order (threaded loop -> runner alongside, not inside, the frozen Ticket);
- order_meta NEVER contains args (metadata only — args could carry content);
- a mixed chain (a legacy 10-key v0.1 row followed by v0.2 rows) verifies
  standalone on ONE unbroken chain — schema evolution by append, not rewrite;
- inserting a foreign key into a stored row breaks verification (the hash
  binds the row's entire key set).
"""

import base64
import hashlib
import json
import sqlite3
import subprocess
import sys
import uuid
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from sentinel_slice.attestor.mock import MockAttestor
from sentinel_slice.cashier.policy import load_policy_set
from sentinel_slice.cashier.store import CashierStore
from sentinel_slice.ledger.receipts import Ledger
from sentinel_slice.loop import SentinelLoop
from sentinel_slice.menu.catalog import load_catalog
from sentinel_slice.spine.canonical import canonical_bytes
from sentinel_slice.spine.hashing import GENESIS_PREV_HASH
from sentinel_slice.spine.types import Order

SENTINEL_DIR = Path(__file__).resolve().parents[1]
REPO_ROOT = Path(__file__).resolve().parents[2]
MAILBOX = SENTINEL_DIR / "kitchen" / "fixtures" / "mailbox"
VERIFIER = SENTINEL_DIR / "verify_ledger.py"


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
    return loop, priv, pub


def _order(**overrides):
    base = dict(
        order_id="ord-" + uuid.uuid4().hex,
        principal="user.kenji",
        role="account_manager",
        capability_id="cap.email.draft_reply.v1",
        args={"thread_id": "user.kenji/t-001"},
        nonce="nonce-" + uuid.uuid4().hex,
        ts="2026-06-10T08:00:00+00:00",
    )
    base.update(overrides)
    return Order(**base)


def test_rejection_receipt_carries_exact_order_meta(tmp_path):
    loop, _priv, _pub = _build_loop(tmp_path)

    outcome = loop.place(_order(capability_id="forward_inbox", args={"target": "x"}))

    assert outcome.accepted is False
    assert outcome.receipt.order_meta == {
        "principal": "user.kenji",
        "role": "account_manager",
        "capability_id": "forward_inbox",
        "ts": "2026-06-10T08:00:00+00:00",
    }
    # Metadata only: args never enter the receipt.
    assert "args" not in outcome.receipt.order_meta
    assert "target" not in json.dumps(outcome.receipt.order_meta)


def test_fulfilled_receipt_carries_exact_order_meta(tmp_path):
    loop, _priv, _pub = _build_loop(tmp_path)

    outcome = loop.place(_order())

    assert outcome.accepted is True
    receipt = loop.last_chef.receipt
    assert receipt.status == "FULFILLED"
    assert receipt.order_meta == {
        "principal": "user.kenji",
        "role": "account_manager",
        "capability_id": "cap.email.draft_reply.v1",
        "ts": "2026-06-10T08:00:00+00:00",
    }
    assert "args" not in receipt.order_meta
    # And it round-trips through storage identically.
    assert loop.read_receipts()[-1].order_meta == receipt.order_meta


def _append_legacy_v01_row(db_path, priv):
    """Hand-write a v0.1-format (10-key, no order_meta) genesis row exactly
    the way the v0.1 ledger did, so the chain starts with a legacy row."""
    content = {
        "receipt_id": "rcpt-legacy-1",
        "order_id": "ord-legacy-1",
        "ticket_id": None,
        "status": "REJECTED",
        "reason_code": "OFF_MENU",
        "result_digest": None,
        "attestation": None,
        "prev_hash": GENESIS_PREV_HASH,
    }
    this_hash = hashlib.sha256(canonical_bytes(content)).hexdigest()
    sig = base64.b64encode(priv.sign(this_hash.encode("utf-8"))).decode("ascii")
    row = dict(content, this_hash=this_hash, sig=sig)
    con = sqlite3.connect(str(db_path))
    try:
        con.execute(
            "CREATE TABLE IF NOT EXISTS receipts ("
            "seq INTEGER PRIMARY KEY, json TEXT NOT NULL)"
        )
        con.execute(
            "INSERT INTO receipts (json) VALUES (?)",
            (canonical_bytes(row).decode("utf-8"),),
        )
        con.commit()
    finally:
        con.close()
    return this_hash


def test_mixed_v01_v02_chain_verifies_standalone(tmp_path):
    priv = Ed25519PrivateKey.generate()
    pub = tmp_path / "pub.pem"
    pub.write_bytes(
        priv.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    db = tmp_path / "ledger.db"

    legacy_hash = _append_legacy_v01_row(db, priv)

    # v0.2 rows append on top of the legacy row — same chain, no rewrite.
    ledger = Ledger(str(db), priv)
    r2 = ledger.append(
        receipt_id="rcpt-new-2",
        order_id="ord-new-2",
        ticket_id=None,
        status="REJECTED",
        reason_code="REPLAY",
        result_digest=None,
        attestation=None,
        order_meta={
            "principal": "user.kenji",
            "role": "account_manager",
            "capability_id": "cap.email.draft_reply.v1",
            "ts": "2026-06-10T08:00:00+00:00",
        },
    )
    assert r2.prev_hash == legacy_hash

    proc = subprocess.run(
        [sys.executable, str(VERIFIER), str(db), str(pub)],
        capture_output=True,
        text=True,
        cwd=str(REPO_ROOT),
    )
    assert proc.returncode == 0, (proc.stdout, proc.stderr)
    assert proc.stdout.strip() == "OK verified=2"


def test_inserting_foreign_key_into_stored_row_breaks_chain(tmp_path):
    priv = Ed25519PrivateKey.generate()
    pub = tmp_path / "pub.pem"
    pub.write_bytes(
        priv.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    db = tmp_path / "ledger.db"
    ledger = Ledger(str(db), priv)
    ledger.append(
        receipt_id="rcpt-1",
        order_id="ord-1",
        ticket_id=None,
        status="REJECTED",
        reason_code="OFF_MENU",
        result_digest=None,
        attestation=None,
        order_meta=None,
    )

    # Adversary smuggles a brand-new key into the stored row (trying to
    # retro-attach exculpatory metadata). The hash binds the WHOLE key set,
    # so verification must fail at seq 1 with hash_mismatch.
    con = sqlite3.connect(str(db))
    try:
        (raw,) = con.execute("SELECT json FROM receipts WHERE seq=1").fetchone()
        row = json.loads(raw)
        row["reviewed_by"] = "auditor.friendly"
        con.execute(
            "UPDATE receipts SET json=? WHERE seq=1",
            (json.dumps(row, sort_keys=True, separators=(",", ":")),),
        )
        con.commit()
    finally:
        con.close()

    proc = subprocess.run(
        [sys.executable, str(VERIFIER), str(db), str(pub)],
        capture_output=True,
        text=True,
        cwd=str(REPO_ROOT),
    )
    assert proc.returncode == 1
    assert proc.stdout.strip() == "FAIL seq=1 reason=hash_mismatch"
