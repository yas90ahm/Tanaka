"""Gateway behavior tests — the model-agnostic counter.

The gateway is the diner protocol made wire-real: order JSON in, outcome JSON
out. These tests assert exact values (full outcome dicts, exact draft bytes,
exact reason codes, ledger row counts), never shapes:

- an honest order JSON comes back FULFILLED with the exact deterministic
  draft riding base64 and the exact receipt the ledger holds;
- an off-menu order JSON comes back as the EXACT rejection outcome dict
  (compared by full dict equality against the appended receipt);
- every malformed-order variant is refused with MALFORMED_ORDER and appends
  ZERO ledger rows;
- the stdin/stdout CLI (`python -m sentinel_slice.gateway`) fulfills an
  honest order end-to-end as a subprocess — proving an external agent process
  (any model, any language) can drive the slice holding no credentials —
  and the resulting one-row chain verifies standalone.
"""

import base64
import hashlib
import json
import subprocess
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from sentinel_slice.attestor.mock import MockAttestor
from sentinel_slice.cashier.policy import load_policy_set
from sentinel_slice.cashier.store import CashierStore
from sentinel_slice.gateway import parse_order, place_order_json, receipt_to_dict
from sentinel_slice.keygen import generate_keypair
from sentinel_slice.ledger.receipts import Ledger
from sentinel_slice.loop import SentinelLoop
from sentinel_slice.menu.catalog import load_catalog
from sentinel_slice.spine.types import Order

SENTINEL_DIR = Path(__file__).resolve().parents[1]
REPO_ROOT = Path(__file__).resolve().parents[2]
MAILBOX = SENTINEL_DIR / "kitchen" / "fixtures" / "mailbox"
VERIFIER = SENTINEL_DIR / "verify_ledger.py"

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


def _order_json(**overrides) -> str:
    base = {
        "order_id": "ord-gw-1",
        "principal": "user.kenji",
        "role": "account_manager",
        "capability_id": "cap.email.draft_reply.v1",
        "args": {"thread_id": "user.kenji/t-001"},
        "nonce": "nonce-gw-1",
        "ts": "2026-06-10T00:00:00+00:00",
    }
    base.update(overrides)
    return json.dumps(base)


def test_parse_order_roundtrips_exactly():
    order = parse_order(_order_json())
    assert order == Order(
        order_id="ord-gw-1",
        principal="user.kenji",
        role="account_manager",
        capability_id="cap.email.draft_reply.v1",
        args={"thread_id": "user.kenji/t-001"},
        nonce="nonce-gw-1",
        ts="2026-06-10T00:00:00+00:00",
    )


def test_parse_order_tolerates_utf8_bom():
    """Windows shells prepend a BOM when piping to a native process; the
    gateway strips it (str and bytes forms both)."""
    expected = parse_order(_order_json())
    assert parse_order("﻿" + _order_json()) == expected
    assert parse_order(b"\xef\xbb\xbf" + _order_json().encode("utf-8")) == expected


def test_gateway_honest_order_fulfilled(tmp_path):
    loop, _pub = _build_loop(tmp_path)

    result = place_order_json(loop, _order_json())

    rows = loop.read_receipts()
    assert len(rows) == 1
    receipt = rows[-1]
    draft = base64.b64decode(result["draft_b64"])

    assert result == {
        "order_id": "ord-gw-1",
        "accepted": True,
        "status": "FULFILLED",
        "reason_code": None,
        "ticket_id": result["ticket_id"],  # asserted non-None below
        "receipt": receipt_to_dict(receipt),
        "window_dir": str(tmp_path / "win" / "ord-gw-1"),
        "draft_b64": result["draft_b64"],
    }
    assert result["ticket_id"] is not None
    assert result["ticket_id"] == receipt.ticket_id
    assert draft.decode("utf-8") == EXPECTED_DRAFT
    assert receipt.result_digest == hashlib.sha256(draft).hexdigest()
    # Privacy holds across the wire: the receipt half of the response never
    # carries draft content, only the digest.
    assert "Acme Corp" not in json.dumps(result["receipt"])


def test_gateway_off_menu_order_rejected_exact_dict(tmp_path):
    loop, _pub = _build_loop(tmp_path)

    result = place_order_json(
        loop,
        _order_json(
            order_id="ord-gw-2",
            capability_id="forward_inbox",
            args={"target": "attacker@evil.test"},
            nonce="nonce-gw-2",
        ),
    )

    rows = loop.read_receipts()
    assert len(rows) == 1
    assert result == {
        "order_id": "ord-gw-2",
        "accepted": False,
        "status": "REJECTED",
        "reason_code": "OFF_MENU",
        "ticket_id": None,
        "receipt": receipt_to_dict(rows[-1]),
        "window_dir": None,
        "draft_b64": None,
    }
    assert rows[-1].reason_code == "OFF_MENU"
    assert rows[-1].ticket_id is None


def test_gateway_malformed_orders_refused_without_receipt(tmp_path):
    loop, _pub = _build_loop(tmp_path)

    cases = [
        ("not json at all {{{", "unparseable JSON"),
        ("[1,2,3]", "order JSON is not an object"),
        (
            json.dumps(json.loads(_order_json()) | {"extra": 1}),
            "unknown key: extra",
        ),
        (
            json.dumps({k: v for k, v in json.loads(_order_json()).items() if k != "nonce"}),
            "missing required key: nonce",
        ),
        (_order_json(role=7), "key must be a string: role"),
        (_order_json(args="user.kenji/t-001"), "args must be an object"),
    ]
    for text, detail in cases:
        assert place_order_json(loop, text) == {
            "accepted": False,
            "error": "MALFORMED_ORDER",
            "detail": detail,
        }

    # NOTHING was admitted: zero rows appended for the whole malformed batch.
    assert loop.read_receipts() == []


def test_gateway_cli_external_agent_process(tmp_path):
    """An external agent process drives the slice end-to-end via stdin/stdout.

    The 'agent' here is the subprocess caller itself: it holds no key, imports
    no package code, and sends exactly the diner-protocol JSON."""
    keys_dir = tmp_path / "keys"
    _priv_path, pub_path = generate_keypair(str(keys_dir))
    db = tmp_path / "ledger.db"
    win = tmp_path / "win"

    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "sentinel_slice.gateway",
            "--ledger", str(db),
            "--keys", str(keys_dir),
            "--window", str(win),
        ],
        input=_order_json(order_id="ord-cli-1", nonce="nonce-cli-1"),
        capture_output=True,
        text=True,
        cwd=str(REPO_ROOT),
    )
    assert proc.returncode == 0, (proc.stdout, proc.stderr)

    result = json.loads(proc.stdout)
    assert result["accepted"] is True
    assert result["status"] == "FULFILLED"
    assert result["reason_code"] is None
    draft = base64.b64decode(result["draft_b64"])
    assert draft.decode("utf-8") == EXPECTED_DRAFT
    assert result["receipt"]["result_digest"] == hashlib.sha256(draft).hexdigest()
    assert result["receipt"]["attestation"]["mock"] is True
    # The draft really sits in the window where the response says it does.
    assert (win / "ord-cli-1" / "output.txt").read_text(encoding="utf-8") == EXPECTED_DRAFT

    # The chain the CLI produced verifies standalone.
    vproc = subprocess.run(
        [sys.executable, str(VERIFIER), str(db), str(pub_path)],
        capture_output=True,
        text=True,
        cwd=str(REPO_ROOT),
    )
    assert vproc.returncode == 0, (vproc.stdout, vproc.stderr)
    assert vproc.stdout.strip() == "OK verified=1"


def test_gateway_cli_malformed_order_exits_2(tmp_path):
    keys_dir = tmp_path / "keys"
    generate_keypair(str(keys_dir))
    db = tmp_path / "ledger.db"

    proc = subprocess.run(
        [
            sys.executable,
            "-m",
            "sentinel_slice.gateway",
            "--ledger", str(db),
            "--keys", str(keys_dir),
            "--window", str(tmp_path / "win"),
        ],
        input="this is not an order",
        capture_output=True,
        text=True,
        cwd=str(REPO_ROOT),
    )
    assert proc.returncode == 2
    assert json.loads(proc.stdout) == {
        "accepted": False,
        "error": "MALFORMED_ORDER",
        "detail": "unparseable JSON",
    }
