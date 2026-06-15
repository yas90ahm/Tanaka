# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Yasir Qureshi
"""SPEC acceptance #5 — REPLAY, plus the positive ticket-minting and
rate-limit assertions.

- test_at05_replay: a valid order is accepted (ticket minted, spawn once,
  NO receipt in Phase 3). A second order reusing the SAME nonce is rejected
  REPLAY at step 1, regardless of the first outcome. The only ledger row is
  the REPLAY rejection (acceptance writes no receipt). Chain verifies.
- test_honest_order_mints_verifiable_ticket: scoped_args carries the
  validated thread_id ONLY (no path, no extra keys); the cashier_sig
  verifies over canonical_bytes(ticket_signable_dict(ticket)); and an
  accept-only ledger has zero rows.
- test_rate_limited_after_limit: with an in-memory limit L=2 and an
  injected clock, the first L accept and the (L+1)-th rejects RATE_LIMITED;
  after advancing the clock past the trailing 3600.0s window the old
  records age out and a fresh order accepts again.
"""

import subprocess
import sys
import uuid
from pathlib import Path

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from sentinel_slice.cashier.engine import process_order, ticket_signable_dict
from sentinel_slice.cashier.policy import Policy, PolicySet, load_policy_set
from sentinel_slice.cashier.store import CashierStore
from sentinel_slice.ledger.receipts import Ledger
from sentinel_slice.menu.catalog import load_catalog
from sentinel_slice.spine.canonical import canonical_bytes
from sentinel_slice.spine.types import Order

REPO_ROOT = Path(__file__).resolve().parents[2]
VERIFIER = Path(__file__).resolve().parents[1] / "verify_ledger.py"


class SpawnSpy:
    def __init__(self):
        self.calls = []

    def __call__(self, ticket):
        self.calls.append(ticket)


def _write_pub_pem(priv, tmp_path):
    pem = tmp_path / "pub.pem"
    pem.write_bytes(
        priv.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    return pem


def _run_verifier(db, pem):
    return subprocess.run(
        [sys.executable, str(VERIFIER), str(db), str(pem)],
        capture_output=True,
        text=True,
        cwd=str(REPO_ROOT),
    )


def _order(*, principal, role, capability_id, args, nonce=None, order_id=None):
    return Order(
        order_id=order_id or f"ord-{uuid.uuid4().hex}",
        principal=principal,
        role=role,
        capability_id=capability_id,
        args=args,
        nonce=nonce or f"nonce-{uuid.uuid4().hex}",
        ts="2026-06-09T00:00:00+00:00",
    )


def test_at05_replay(tmp_path):
    priv = Ed25519PrivateKey.generate()
    db = tmp_path / "ledger.db"
    ledger = Ledger(str(db), priv)
    pem = _write_pub_pem(priv, tmp_path)

    menu = load_catalog()
    policy_set = load_policy_set()
    store = CashierStore()
    spy = SpawnSpy()

    shared_nonce = f"nonce-{uuid.uuid4().hex}"

    o1 = _order(
        principal="user.kenji",
        role="account_manager",
        capability_id="cap.email.draft_reply.v1",
        args={"thread_id": "user.kenji/t1"},
        nonce=shared_nonce,
    )
    r1 = process_order(
        o1,
        menu=menu,
        policy_set=policy_set,
        store=store,
        ledger=ledger,
        private_key=priv,
        spawn=spy,
    )
    assert r1.accepted is True
    assert r1.ticket is not None
    assert r1.receipt is None
    assert len(spy.calls) == 1
    assert spy.calls[0] is r1.ticket

    # Identical load-bearing fields, fresh order_id, SAME nonce -> REPLAY.
    o2 = _order(
        principal="user.kenji",
        role="account_manager",
        capability_id="cap.email.draft_reply.v1",
        args={"thread_id": "user.kenji/t1"},
        nonce=shared_nonce,
    )
    r2 = process_order(
        o2,
        menu=menu,
        policy_set=policy_set,
        store=store,
        ledger=ledger,
        private_key=priv,
        spawn=spy,
    )

    assert r2.accepted is False
    assert r2.reason_code == "REPLAY"
    assert len(spy.calls) == 1  # no new spawn

    assert r1.accepted is True and r2.accepted is False and r2.reason_code == "REPLAY"

    rows = ledger.read_all()
    # Only the REPLAY rejection appended; acceptance writes no receipt in Phase 3.
    assert len(rows) == 1
    assert rows[-1].status == "REJECTED"
    assert rows[-1].reason_code == "REPLAY"
    assert rows[-1].order_id == o2.order_id

    res = _run_verifier(db, pem)
    assert res.returncode == 0, (res.stdout, res.stderr)
    assert res.stdout.strip() == "OK verified=1"


def test_honest_order_mints_verifiable_ticket(tmp_path):
    priv = Ed25519PrivateKey.generate()
    db = tmp_path / "ledger.db"
    ledger = Ledger(str(db), priv)

    menu = load_catalog()
    policy_set = load_policy_set()
    store = CashierStore()
    spy = SpawnSpy()

    order = _order(
        principal="user.kenji",
        role="account_manager",
        capability_id="cap.email.draft_reply.v1",
        args={"thread_id": "user.kenji/thread-7"},
    )
    result = process_order(
        order,
        menu=menu,
        policy_set=policy_set,
        store=store,
        ledger=ledger,
        private_key=priv,
        spawn=spy,
    )

    assert result.accepted is True
    # Exact dict equality: narrowing carries thread_id ONLY (no path, no extras).
    assert result.ticket.scoped_args == {"thread_id": "user.kenji/thread-7"}
    assert result.ticket.capability_id == "cap.email.draft_reply.v1"
    assert result.ticket.order_id == order.order_id
    assert len(spy.calls) == 1
    assert spy.calls[0] is result.ticket

    pub = priv.public_key()
    try:
        pub.verify(
            result.ticket.cashier_sig,
            canonical_bytes(ticket_signable_dict(result.ticket)),
        )
        verified = True
    except InvalidSignature:
        verified = False
    assert verified is True

    # Acceptance appends no receipt in Phase 3.
    assert ledger.read_all() == []


def test_rate_limited_after_limit(tmp_path):
    priv = Ed25519PrivateKey.generate()
    db = tmp_path / "ledger.db"
    ledger = Ledger(str(db), priv)
    pem = _write_pub_pem(priv, tmp_path)

    menu = load_catalog()
    # In-memory PolicySet OWNS the limit L=2 (independent of the committed 5).
    policy_set = PolicySet(
        [
            Policy(
                role="account_manager",
                allowed_capabilities=("cap.email.draft_reply.v1",),
                rate_limit_per_hour=2,
            )
        ]
    )

    clock = [1000.0]
    store = CashierStore(now=lambda: clock[0])
    spy = SpawnSpy()

    def place():
        order = _order(
            principal="user.kenji",
            role="account_manager",
            capability_id="cap.email.draft_reply.v1",
            args={"thread_id": "user.kenji/t"},
        )
        return process_order(
            order,
            menu=menu,
            policy_set=policy_set,
            store=store,
            ledger=ledger,
            private_key=priv,
            spawn=spy,
        )

    # First L=2 accept at clock 1000.0.
    r1 = place()
    r2 = place()
    assert r1.accepted is True
    assert r2.accepted is True

    # (L+1)=3rd at the same instant -> RATE_LIMITED.
    r3 = place()
    assert r3.accepted is False
    assert r3.reason_code == "RATE_LIMITED"

    # Advance past the window: now - ts == 3600.0 is NOT < 3600.0, so the two
    # old records age out and a fresh order accepts again.
    clock[0] = 1000.0 + 3600.0
    r4 = place()
    assert r4.accepted is True

    # Exactly one REJECTED/RATE_LIMITED row was appended (only r3).
    rows = ledger.read_all()
    assert len(rows) == 1
    assert rows[-1].status == "REJECTED"
    assert rows[-1].reason_code == "RATE_LIMITED"
    assert rows[-1].order_id == r3.receipt.order_id

    # Three acceptances spawned exactly three tickets.
    assert len(spy.calls) == 3

    res = _run_verifier(db, pem)
    assert res.returncode == 0, (res.stdout, res.stderr)
    assert res.stdout.strip() == "OK verified=1"
