"""Phase-2 ledger tests (Worker B owns these).

Build a real chain via the Ledger writer, assert genesis prev_hash on seq=1,
assert prev_hash linkage across rows, assert the returned Receipt is fully
populated and self-consistent under the spine hash, assert the stored row
format, assert a 100-receipt chain makes the STANDALONE verify_ledger.py
(run as a subprocess with the temp pubkey) exit 0, and assert the ledger
module source contains no UPDATE/DELETE/etc (CLAUDE.md #3 grep).
"""

import base64
import hashlib
import json
import sqlite3
import subprocess
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from sentinel_slice.ledger.receipts import Ledger
from sentinel_slice.spine.hashing import (
    receipt_content_dict,
    receipt_content_hash,
)

GENESIS = "901131d838b17aac0f7885b81e03cbdc9f5157a00343d30ab22083685ed1416a"

VERIFIER = Path(__file__).resolve().parents[1] / "verify_ledger.py"

LEDGER_SRC = Path(__file__).resolve().parents[1] / "ledger" / "receipts.py"

# The exact 10-key set stored in the json column (§2 of the contract).
STORED_KEYS = {
    "receipt_id",
    "order_id",
    "ticket_id",
    "status",
    "reason_code",
    "result_digest",
    "attestation",
    "prev_hash",
    "this_hash",
    "sig",
}


def _keypair(tmp_path):
    """Generate a fresh Ed25519 keypair; write the public key PEM to tmp."""
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()
    pem = tmp_path / "pub.pem"
    pem.write_bytes(
        pub.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    return priv, pub, pem


def _appended(ledger, i):
    """Append a receipt with a distinct, fully-populated body."""
    return ledger.append(
        receipt_id=f"r-{i}",
        order_id=f"order-{i}",
        ticket_id=f"t-{i}",
        status="accepted",
        reason_code=None,
        result_digest=f"digest-{i:04d}",
        attestation={"mock": True, "n": i},
    )


def _run_verifier(db, pem):
    return subprocess.run(
        [sys.executable, str(VERIFIER), str(db), str(pem)],
        capture_output=True,
        text=True,
    )


def test_genesis_prev_hash_on_seq1(tmp_path):
    priv, pub, pem = _keypair(tmp_path)
    db = tmp_path / "ledger.db"
    ledger = Ledger(str(db), priv)

    _appended(ledger, 1)

    rows = ledger.read_all()
    assert len(rows) == 1
    assert rows[0].prev_hash == GENESIS
    # Prove the literal is exactly sha256(b"GENESIS").
    assert rows[0].prev_hash == hashlib.sha256(b"GENESIS").hexdigest()


def test_chain_links(tmp_path):
    priv, pub, pem = _keypair(tmp_path)
    db = tmp_path / "ledger.db"
    ledger = Ledger(str(db), priv)

    r1 = _appended(ledger, 1)
    r2 = _appended(ledger, 2)
    r3 = _appended(ledger, 3)

    assert r1.prev_hash == GENESIS
    assert r2.prev_hash == r1.this_hash
    assert r3.prev_hash == r2.this_hash

    # seq values are exactly 1, 2, 3 (raw query).
    con = sqlite3.connect(str(db))
    try:
        seqs = [row[0] for row in con.execute(
            "SELECT seq FROM receipts ORDER BY seq ASC"
        ).fetchall()]
    finally:
        con.close()
    assert seqs == [1, 2, 3]


def test_append_returns_populated_receipt(tmp_path):
    priv, pub, pem = _keypair(tmp_path)
    db = tmp_path / "ledger.db"
    ledger = Ledger(str(db), priv)

    r = ledger.append(
        receipt_id="r-7",
        order_id="order-7",
        ticket_id="t-7",
        status="accepted",
        reason_code=None,
        result_digest="digest-0007",
        attestation={"mock": True, "n": 7},
    )

    # Full field-by-field equality against the inputs.
    assert r.receipt_id == "r-7"
    assert r.order_id == "order-7"
    assert r.ticket_id == "t-7"
    assert r.status == "accepted"
    assert r.reason_code is None
    assert r.result_digest == "digest-0007"
    assert r.attestation == {"mock": True, "n": 7}
    assert r.prev_hash == GENESIS

    # this_hash is 64 lowercase hex chars.
    assert len(r.this_hash) == 64
    assert all(c in "0123456789abcdef" for c in r.this_hash)

    # sig carries the RAW 64-byte Ed25519 signature (not base64).
    assert isinstance(r.sig, bytes)
    assert len(r.sig) == 64

    # this_hash recomputes via the spine over the content dict.
    assert r.this_hash == receipt_content_hash(receipt_content_dict(r))


def test_stored_row_format(tmp_path):
    priv, pub, pem = _keypair(tmp_path)
    db = tmp_path / "ledger.db"
    ledger = Ledger(str(db), priv)

    r = _appended(ledger, 1)

    con = sqlite3.connect(str(db))
    try:
        (raw,) = con.execute(
            "SELECT json FROM receipts WHERE seq=1"
        ).fetchone()
    finally:
        con.close()

    row = json.loads(raw)
    # Exactly the 10 keys of §2 — no more, no fewer.
    assert set(row.keys()) == STORED_KEYS

    # sig base64-decodes to exactly 64 raw bytes.
    raw_sig = base64.b64decode(row["sig"])
    assert len(raw_sig) == 64

    # The stored sig verifies under the pubkey over this_hash's UTF-8 bytes.
    # (Proves the §5 signing-input agreement directly: no exception => valid.)
    pub.verify(raw_sig, row["this_hash"].encode("utf-8"))

    # The stored this_hash matches the returned Receipt's this_hash.
    assert row["this_hash"] == r.this_hash


def test_hundred_receipt_chain_verifies_subprocess(tmp_path):
    priv, pub, pem = _keypair(tmp_path)
    db = tmp_path / "ledger.db"
    ledger = Ledger(str(db), priv)

    for i in range(1, 101):
        _appended(ledger, i)

    result = _run_verifier(db, pem)
    assert result.returncode == 0, (result.stdout, result.stderr)
    assert result.stdout.strip() == "OK verified=100"


def test_ledger_source_has_no_update_delete(tmp_path):
    src = LEDGER_SRC.read_text(encoding="utf-8").upper()
    for forbidden in ("UPDATE", "DELETE", "REPLACE", "DROP", "ALTER"):
        assert forbidden not in src, f"forbidden SQL token in ledger source: {forbidden}"
