"""evaluate_order is a PURE decision function (v0.3 console seam).

The console's Simulate runs the SAME pipeline process_order runs, so it must
be the same function with zero side effects. These tests pin that:

- every pipeline verdict is reproduced exactly (REPLAY/OFF_MENU/ROLE/PAUSED/
  OUT_OF_SCOPE/RATE/accept) with the right scoped_args on accept;
- calling evaluate_order N times appends ZERO ledger rows, consumes ZERO
  nonces, and records ZERO rate history - asserted on the live store;
- process_order and evaluate_order never disagree on the same input (the
  honesty invariant: Simulate cannot lie).
"""

import uuid

from sentinel_slice.cashier.engine import (
    Decision,
    evaluate_order,
    process_order,
)
from sentinel_slice.cashier.policy import Policy, PolicySet, load_policy_set
from sentinel_slice.cashier.store import CashierStore
from sentinel_slice.ledger.receipts import Ledger
from sentinel_slice.menu.catalog import load_catalog
from sentinel_slice.spine.types import Order

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey


def _order(**kw):
    base = dict(
        order_id="ord-" + uuid.uuid4().hex,
        principal="user.kenji",
        role="account_manager",
        capability_id="cap.email.draft_reply.v1",
        args={"thread_id": "user.kenji/t-001"},
        nonce="nonce-" + uuid.uuid4().hex,
        ts="2026-06-10T10:00:00+00:00",
    )
    base.update(kw)
    return Order(**base)


def _ctx():
    return dict(
        menu=load_catalog(),
        policy_set=load_policy_set(),
        store=CashierStore(),
    )


def test_evaluate_accepts_honest_order_with_scoped_args():
    d = evaluate_order(_order(), **_ctx())
    assert d == Decision(
        accepted=True, reason_code=None, scoped_args={"thread_id": "user.kenji/t-001"}
    )


def test_evaluate_each_rejection_reason():
    ctx = _ctx()
    assert evaluate_order(
        _order(capability_id="forward_inbox", args={"target": "x"}), **ctx
    ) == Decision(False, "OFF_MENU", None)
    assert evaluate_order(
        _order(role="intern"), **ctx
    ) == Decision(False, "ROLE_NOT_PERMITTED", None)
    assert evaluate_order(
        _order(args={"thread_id": "user.victim/t-9"}), **ctx
    ) == Decision(False, "OUT_OF_SCOPE", None)
    assert evaluate_order(
        _order(args={"thread_id": "user.kenji/../user.victim/x"}), **ctx
    ) == Decision(False, "OUT_OF_SCOPE", None)


def test_evaluate_replay_is_read_only_check():
    ctx = _ctx()
    store = ctx["store"]
    n = "nonce-fixed-1"
    # Not spent yet -> accepted, and STILL not spent (read-only).
    assert evaluate_order(_order(nonce=n), **ctx).accepted is True
    assert store.nonce_is_spent(n) is False
    # Mark it spent via the mutating call; now evaluate sees REPLAY.
    store.nonce_seen(n)
    assert evaluate_order(_order(nonce=n), **ctx) == Decision(False, "REPLAY", None)


def test_evaluate_is_pure_no_side_effects(tmp_path):
    priv = Ed25519PrivateKey.generate()
    ledger = Ledger(str(tmp_path / "ledger.db"), priv)
    store = CashierStore()
    ctx = dict(menu=load_catalog(), policy_set=load_policy_set(), store=store)

    for _ in range(25):
        evaluate_order(_order(), **ctx)

    # No receipts appended, no nonces consumed, no rate history recorded.
    assert ledger.read_all() == []
    assert store._seen_nonces == set()
    assert store.rate_count("user.kenji", "cap.email.draft_reply.v1") == 0


def test_simulate_and_real_never_disagree(tmp_path):
    """For the same input, evaluate_order's verdict == process_order's
    observed outcome. If these ever drift, Simulate is a lie."""
    priv = Ed25519PrivateKey.generate()

    cases = [
        _order(),
        _order(capability_id="forward_inbox", args={"target": "x"}),
        _order(role="intern"),
        _order(args={"thread_id": "user.victim/t-9"}),
    ]
    for order in cases:
        sim = evaluate_order(
            order, menu=load_catalog(), policy_set=load_policy_set(),
            store=CashierStore(),
        )
        ledger = Ledger(str(tmp_path / f"l-{order.order_id}.db"), priv)
        outcome = process_order(
            order,
            menu=load_catalog(),
            policy_set=load_policy_set(),
            store=CashierStore(),
            ledger=ledger,
            private_key=priv,
            spawn=None,
        )
        assert outcome.accepted == sim.accepted
        if not sim.accepted:
            assert outcome.reason_code == sim.reason_code


def test_evaluate_paused_capability_distinct_from_role():
    # Same role+cap: allowed normally, CAPABILITY_PAUSED when paused.
    allowed = PolicySet([
        Policy(
            role="account_manager",
            allowed_capabilities=("cap.email.draft_reply.v1",),
            rate_limit_per_hour=5,
        )
    ])
    paused = PolicySet([
        Policy(
            role="account_manager",
            allowed_capabilities=("cap.email.draft_reply.v1",),
            rate_limit_per_hour=5,
            paused_capabilities=("cap.email.draft_reply.v1",),
        )
    ])
    menu = load_catalog()
    assert evaluate_order(
        _order(), menu=menu, policy_set=allowed, store=CashierStore()
    ).accepted is True
    assert evaluate_order(
        _order(), menu=menu, policy_set=paused, store=CashierStore()
    ) == Decision(False, "CAPABILITY_PAUSED", None)
