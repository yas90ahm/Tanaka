# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Yasir Qureshi
"""Pluggable capabilities (v0.5) — the chef is no longer email-only.

Proves the system is GENERAL: different capabilities, different scoped-input
keys, different deterministic transforms, all through the same cashier ->
ticket -> chef -> receipt path. Asserted on exact output bytes (recomputed
independently from the fixture), the privacy invariant (even derived content
stays out of the ledger), and the unknown-handler contract (exit 5).
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
from sentinel_slice.chef.runner import CHEF_MAIN
from sentinel_slice.ledger.receipts import Ledger
from sentinel_slice.loop import SentinelLoop
from sentinel_slice.menu.catalog import load_catalog
from sentinel_slice.spine.canonical import canonical_bytes
from sentinel_slice.spine.types import Order

SENTINEL_DIR = Path(__file__).resolve().parents[1]
MAILBOX = SENTINEL_DIR / "kitchen" / "fixtures" / "mailbox"
REPORT = MAILBOX / "user.kenji" / "report.txt"

DRAFT = "cap.email.draft_reply.v1"
DOCS = "cap.docs.summarize.v1"
PAY = "cap.payment.initiate.v1"


def _loop(tmp_path, allowed):
    priv = Ed25519PrivateKey.generate()
    pub = tmp_path / "pub.pem"
    pub.write_bytes(priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo))
    policy = PolicySet([Policy(role="account_manager",
                              allowed_capabilities=tuple(allowed),
                              rate_limit_per_hour=50)])
    loop = SentinelLoop(
        private_key=priv, ledger=Ledger(str(tmp_path / "ledger.db"), priv),
        menu=load_catalog(), policy_set=policy, store=CashierStore(),
        public_key_pem_path=str(pub), fixtures_root=str(MAILBOX),
        attestor=MockAttestor(), window_root=str(tmp_path / "win"))
    return loop, priv, pub


def _order(capability_id, scoped_key, resource):
    return Order(order_id="ord-" + uuid.uuid4().hex, principal="user.kenji",
                 role="account_manager", capability_id=capability_id,
                 args={scoped_key: resource}, nonce="n-" + uuid.uuid4().hex,
                 ts="2026-06-10T00:00:00+00:00")


def _expected_summary(resource, text):
    lines = text.splitlines()
    first = next((ln.strip() for ln in lines if ln.strip()), "(empty document)")
    return (
        "Summary of {}\n\n"
        "Opening: {}\n"
        "Length: {} lines, {} words.\n\n"
        "-- Sentinel Loop summary (extractive, no model)\n"
    ).format(resource, first, len(lines), len(text.split()))


def test_docs_summarize_end_to_end_and_private(tmp_path):
    loop, _priv, _pub = _loop(tmp_path, [DOCS])

    outcome = loop.place(_order(DOCS, "doc_id", "user.kenji/report"))

    assert outcome.accepted is True
    chef = loop.last_chef
    assert chef.receipt.status == "FULFILLED"

    expected = _expected_summary("user.kenji/report",
                                 REPORT.read_text(encoding="utf-8"))
    assert chef.draft_bytes.decode("utf-8") == expected
    assert "Quarterly Operations Report" in expected  # it really read the doc...

    # ...yet the document's content (opening line AND body) never lands in the
    # ledger — only the digest does. Even the derived summary stays on the
    # content path (the window), not the evidence path (the ledger).
    raw = (tmp_path / "ledger.db").read_bytes()
    assert b"Quarterly Operations" not in raw
    assert b"142 accounts" not in raw


def test_payment_initiate_produces_no_funds_artifact(tmp_path):
    loop, _priv, _pub = _loop(tmp_path, [PAY])

    outcome = loop.place(_order(PAY, "thread_id", "user.kenji/t-001"))

    assert outcome.accepted is True
    out = loop.last_chef.draft_bytes.decode("utf-8")
    assert out == (
        "PAYMENT REQUEST — NO FUNDS MOVED\n\n"
        "Regarding: user.kenji/t-001\n"
        "This is a request artifact for human authorization. The Sentinel Loop "
        "slice does not execute payments.\n\n"
        "-- Sentinel Loop (no side effect performed)\n"
    )


def test_two_capabilities_share_one_pipeline(tmp_path):
    """A draft and a summary, different scoped-input keys, one chain."""
    loop, _priv, _pub = _loop(tmp_path, [DRAFT, DOCS])

    d = loop.place(_order(DRAFT, "thread_id", "user.kenji/t-001"))
    s = loop.place(_order(DOCS, "doc_id", "user.kenji/report"))

    assert d.accepted and s.accepted
    rows = loop.read_receipts()
    assert [r.status for r in rows] == ["FULFILLED", "FULFILLED"]
    assert rows[0].order_meta["capability_id"] == DRAFT
    assert rows[1].order_meta["capability_id"] == DOCS


def test_unknown_capability_handler_exits_5(tmp_path):
    """A capability with a valid signature but NO chef handler (a developer
    added a descriptor + policy but no transform) fails cleanly with exit 5,
    writing nothing — not a silent wrong-output."""
    priv = Ed25519PrivateKey.generate()
    pub = tmp_path / "pub.pem"
    pub.write_bytes(priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo))
    out_dir = tmp_path / "win" / "ord-x"

    signable = {
        "ticket_id": "tkt-x", "order_id": "ord-x",
        "capability_id": "cap.ghost.v1",
        "behavior": "ghost_behavior",   # a behavior the chef has no handler for
        "behavior_config": {},
        "scoped_args": {"thread_id": "user.kenji/t-001"},
        "issued_ts": "2026-06-10T00:00:00+00:00",
    }
    sig = priv.sign(canonical_bytes(signable))
    wire = dict(signable, cashier_sig=base64.b64encode(sig).decode("ascii"))

    proc = subprocess.run(
        [sys.executable, str(CHEF_MAIN), str(pub), str(MAILBOX), str(out_dir)],
        input=json.dumps(wire), capture_output=True, text=True)

    assert proc.returncode == 5, (proc.stdout, proc.stderr)
    assert "no handler for behavior" in proc.stderr
    assert not (out_dir / "output.txt").exists()
