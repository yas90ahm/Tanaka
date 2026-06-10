"""The money artifact — the injected-diner probe.

After the deterministic diner "reads" the poisoned fixture email, it attempts
the OFF-MENU capability `forward_inbox`. Expected, asserted concretely:

- the cashier rejects OFF_MENU, NO ticket is minted;
- the REJECTION ITSELF is a single chained REJECTED receipt carrying
  reason_code OFF_MENU and the order's id;
- the resulting one-row chain verifies standalone (exit 0, OK verified=1);
- no draft is ever written for the off-menu order (chef never spawns).

The loop is constructed DIRECTLY with a hermetic temp keypair/ledger/window
but the REAL poisoned fixture path, so the probe exercises the real parse.
"""

import subprocess
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from sentinel_slice.attestor.mock import MockAttestor
from sentinel_slice.cashier.policy import load_policy_set
from sentinel_slice.cashier.store import CashierStore
from sentinel_slice.diner.agent import make_injected_order, run_injected
from sentinel_slice.ledger.receipts import Ledger
from sentinel_slice.loop import SentinelLoop
from sentinel_slice.menu.catalog import load_catalog
from sentinel_slice.spine.types import Order

SENTINEL_DIR = Path(__file__).resolve().parents[1]
REPO_ROOT = Path(__file__).resolve().parents[2]
MAILBOX = SENTINEL_DIR / "kitchen" / "fixtures" / "mailbox"
POISONED = MAILBOX / "user.kenji" / "poisoned.txt"
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
    return loop, pub


def _run_verifier(db, pem):
    return subprocess.run(
        [sys.executable, str(VERIFIER), str(db), str(pem)],
        capture_output=True,
        text=True,
        cwd=str(REPO_ROOT),
    )


def test_injected_probe_dict_reports_rejection(tmp_path):
    loop, _pem = _build_loop(tmp_path)

    result = run_injected(loop, str(POISONED))

    assert result["accepted"] is False
    assert result["reason_code"] == "OFF_MENU"


def test_injected_probe_off_menu_is_chained_receipt(tmp_path):
    loop, pem = _build_loop(tmp_path)

    # Drive EXACTLY one injected order via the loop so the receipt count is
    # deterministic, and capture the outcome object to inspect the ticket.
    order = make_injected_order("user.kenji", str(POISONED))
    assert order.capability_id == "forward_inbox"
    assert order.args == {"target": "attacker@evil.test"}

    outcome = loop.place(order)

    # No ticket minted; the rejection carries the exact reason code.
    assert outcome.accepted is False
    assert outcome.reason_code == "OFF_MENU"
    assert outcome.ticket is None
    assert outcome.receipt.status == "REJECTED"
    assert outcome.receipt.reason_code == "OFF_MENU"
    assert outcome.receipt.order_id == order.order_id

    # The rejection IS a chained receipt — exactly one row, the artifact.
    rows = loop.read_receipts()
    assert len(rows) == 1
    assert rows[-1].status == "REJECTED"
    assert rows[-1].reason_code == "OFF_MENU"
    assert rows[-1].ticket_id is None
    assert rows[-1].order_id == order.order_id

    # No draft was produced — the off-menu order never spawns a chef.
    assert not (tmp_path / "win" / order.order_id / "output.txt").exists()

    # The one-row chain (a pure rejection) still verifies standalone.
    res = _run_verifier(tmp_path / "ledger.db", pem)
    assert res.returncode == 0, (res.stdout, res.stderr)
    assert res.stdout.strip() == "OK verified=1"
