"""SPEC acceptance #9 — authoring round-trip + rate enforcement.

Three concrete assertions:

- test_at09_emitted_bytes_equal_committed_file: the form's pure
  `emit_policy_bytes(...)` for the canonical inputs is BYTE-IDENTICAL to the
  committed `policies/account_manager.json` (the form is the generator).
- test_at09_rate_two_blocks_third: a form-authored policy at rate=2 drives
  the cashier — orders 1,2 accept, order 3 -> RATE_LIMITED.
- test_at09_rate_five_blocks_sixth: at rate=5 — orders 1..5 accept, order 6
  -> RATE_LIMITED. Changing the authored rate changes enforcement.

A fixed clock (CashierStore(now=lambda: 1000.0)) keeps all orders in one
rate window; each order gets a fresh nonce/order_id so REPLAY never fires.
"""

import uuid
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from sentinel_slice.authoring.policy_form import emit_policy_bytes
from sentinel_slice.cashier.engine import process_order
from sentinel_slice.cashier.policy import load_policy_set
from sentinel_slice.cashier.store import CashierStore
from sentinel_slice.ledger.receipts import Ledger
from sentinel_slice.menu.catalog import load_catalog
from sentinel_slice.spine.types import Order

SENTINEL_DIR = Path(__file__).resolve().parents[1]
COMMITTED_POLICY = SENTINEL_DIR / "policies" / "account_manager.json"


def _order():
    return Order(
        order_id=f"ord-{uuid.uuid4().hex}",
        principal="user.kenji",
        role="account_manager",
        capability_id="cap.email.draft_reply.v1",
        args={"thread_id": "user.kenji/t-001"},
        nonce=f"nonce-{uuid.uuid4().hex}",
        ts="2026-06-09T00:00:00+00:00",
    )


def _harness(tmp_path, rate):
    policy_bytes = emit_policy_bytes(
        "account_manager", ["cap.email.draft_reply.v1"], rate
    )
    (tmp_path / "account_manager.json").write_bytes(policy_bytes)
    policy_set = load_policy_set(str(tmp_path))

    priv = Ed25519PrivateKey.generate()
    ledger = Ledger(str(tmp_path / "ledger.db"), priv)
    menu = load_catalog()
    store = CashierStore(now=lambda: 1000.0)

    def place():
        return process_order(
            _order(),
            menu=menu,
            policy_set=policy_set,
            store=store,
            ledger=ledger,
            private_key=priv,
            spawn=None,
        )

    return place


def test_at09_emitted_bytes_equal_committed_file():
    committed_bytes = COMMITTED_POLICY.read_bytes()
    assert (
        emit_policy_bytes("account_manager", ["cap.email.draft_reply.v1"], 5)
        == committed_bytes
    )


def test_at09_rate_two_blocks_third(tmp_path):
    place = _harness(tmp_path, 2)

    r1 = place()
    r2 = place()
    r3 = place()

    assert r1.accepted is True
    assert r2.accepted is True
    assert r3.accepted is False
    assert r3.reason_code == "RATE_LIMITED"


def test_at09_rate_five_blocks_sixth(tmp_path):
    place = _harness(tmp_path, 5)

    outcomes = [place() for _ in range(6)]

    for i in range(5):
        assert outcomes[i].accepted is True, f"order {i + 1} should accept"
    assert outcomes[5].accepted is False
    assert outcomes[5].reason_code == "RATE_LIMITED"
