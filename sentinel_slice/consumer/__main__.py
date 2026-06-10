"""Consumer-mode demo — `python -m sentinel_slice.consumer`.

A tiny computer-use scenario on your own machine: an agent does a benign
action (drafts a reply — runs with no friction), then reaches for a
high-stakes one (initiates a payment — pauses and asks you). The second is the
chokepoint: a prompt-injected agent meets your decision, and either way it
lands on the receipt chain.

Self-contained: it generates an ephemeral keypair + ledger in a temp dir, so
it runs on a fresh clone with no setup. The payment is never actually executed
(the chef writes a 'no send performed' stand-in — the slice does not move
money); the point is the GATE and the RECEIPT, not the side effect.
"""

import os
import shutil
import sys
import tempfile
import uuid
from datetime import datetime, timezone

from cryptography.hazmat.primitives import serialization

from sentinel_slice.attestor.mock import MockAttestor
from sentinel_slice.cashier.policy import Policy, PolicySet
from sentinel_slice.cashier.store import CashierStore
from sentinel_slice.consumer.approval import CliApprover
from sentinel_slice.consumer.loop import ConsumerLoop
from sentinel_slice.consumer.preferences import Preferences
from sentinel_slice.keygen import generate_keypair
from sentinel_slice.ledger.receipts import Ledger
from sentinel_slice.loop import SentinelLoop
from sentinel_slice.menu.catalog import load_catalog
from sentinel_slice.spine.types import Order

_SENTINEL_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_MAILBOX = os.path.join(_SENTINEL_DIR, "kitchen", "fixtures", "mailbox")

DRAFT = "cap.email.draft_reply.v1"
PAY = "cap.payment.initiate.v1"


def _order(capability_id):
    return Order(
        order_id="ord-" + uuid.uuid4().hex,
        principal="user.kenji",
        role="account_manager",
        capability_id=capability_id,
        args={"thread_id": "user.kenji/t-001"},
        nonce="nonce-" + uuid.uuid4().hex,
        ts=datetime.now(timezone.utc).isoformat(),
    )


def main() -> int:
    tmp = tempfile.mkdtemp(prefix="consumer_demo_")
    try:
        keys_dir = os.path.join(tmp, "keys")
        generate_keypair(keys_dir)
        with open(os.path.join(keys_dir, "cashier_ed25519_private.pem"), "rb") as fh:
            priv = serialization.load_pem_private_key(fh.read(), password=None)
        pub_path = os.path.join(keys_dir, "cashier_ed25519_public.pem")

        # A personal policy that PERMITS both actions; the difference between
        # them is the per-action confirmation flag on the payment capability.
        policy = PolicySet([
            Policy(
                role="account_manager",
                allowed_capabilities=(DRAFT, PAY),
                rate_limit_per_hour=20,
            )
        ])
        loop = SentinelLoop(
            private_key=priv,
            ledger=Ledger(os.path.join(tmp, "ledger.db"), priv),
            menu=load_catalog(),
            policy_set=policy,
            store=CashierStore(),
            public_key_pem_path=pub_path,
            fixtures_root=_MAILBOX,
            attestor=MockAttestor(),
            window_root=os.path.join(tmp, "win"),
        )
        # Honor a saved permissions file if the user made one with
        # `python -m sentinel_slice.consumer.permissions`; else defaults apply
        # (low-stakes ALLOW, high-stakes ASK).
        prefs = Preferences.load(os.path.abspath("sentinel_permissions.json"))
        consumer = ConsumerLoop(loop, approver=CliApprover(), preferences=prefs)

        print("=== benign action: draft a reply (no friction expected) ===")
        r1 = consumer.place(_order(DRAFT))
        print("  -> {} (asked you? {})".format(r1.status, r1.confirmation_asked))

        print("\n=== high-stakes action: initiate a payment ===")
        print("  (imagine the agent reached this after reading a sketchy email)")
        r2 = consumer.place(_order(PAY))
        print("  -> {} (reason: {})".format(r2.status, r2.reason_code))

        print("\n=== the receipt chain (what your agent actually did) ===")
        for i, rc in enumerate(consumer.read_receipts(), start=1):
            who = rc.order_meta or {}
            print("  seq {} {:<10} {:<18} {}".format(
                i, rc.status, rc.reason_code or "-",
                who.get("capability_id", "?")))
        return 0
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    sys.exit(main())
