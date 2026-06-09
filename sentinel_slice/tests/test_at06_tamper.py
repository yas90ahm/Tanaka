"""SPEC acceptance #6 — tamper detection.

Build a 100-receipt chain, confirm it verifies, then tamper row 50 via a
raw sqlite UPDATE *in the test* (tests are not ledger code, so UPDATE is
allowed here) and assert the standalone verifier exits 1 and reports the
exact broken seq integer (50). Two flavors: content tamper -> hash_mismatch,
and signature-only tamper -> bad_signature.
"""

import base64
import json
import re
import sqlite3
import subprocess
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from sentinel_slice.ledger.receipts import Ledger

VERIFIER = Path(__file__).resolve().parents[1] / "verify_ledger.py"


def _keypair(tmp_path):
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


def _build_chain(tmp_path):
    priv, pub, pem = _keypair(tmp_path)
    db = tmp_path / "ledger.db"
    ledger = Ledger(str(db), priv)
    for i in range(1, 101):
        ledger.append(
            receipt_id=f"r-{i}",
            order_id=f"order-{i}",
            ticket_id=f"t-{i}",
            status="accepted",
            reason_code=None,
            result_digest=f"digest-{i:04d}",
            attestation={"mock": True, "n": i},
        )
    return db, pem


def _run_verifier(db, pem):
    return subprocess.run(
        [sys.executable, str(VERIFIER), str(db), str(pem)],
        capture_output=True,
        text=True,
    )


def test_at06_tamper_flips_byte_in_row50_reports_seq50(tmp_path):
    db, pem = _build_chain(tmp_path)

    # Clean chain verifies first.
    ok = _run_verifier(db, pem)
    assert ok.returncode == 0, (ok.stdout, ok.stderr)
    assert ok.stdout.strip() == "OK verified=100"

    # Tamper a content field of row 50 so the content changes but the
    # json stays valid: flip one character of result_digest.
    con = sqlite3.connect(str(db))
    try:
        (raw,) = con.execute("SELECT json FROM receipts WHERE seq=50").fetchone()
        row = json.loads(raw)
        old = row["result_digest"]
        last = old[-1]
        flipped = "0" if last != "0" else "1"
        row["result_digest"] = old[:-1] + flipped
        assert row["result_digest"] != old
        con.execute(
            "UPDATE receipts SET json=? WHERE seq=50",
            (json.dumps(row, sort_keys=True, separators=(",", ":")),),
        )
        con.commit()
    finally:
        con.close()

    bad = _run_verifier(db, pem)
    assert bad.returncode == 1, (bad.stdout, bad.stderr)

    out = bad.stdout.strip()
    # The exact failure line.
    assert out == "FAIL seq=50 reason=hash_mismatch", out

    # Parse the seq integer out of the token and assert it equals 50.
    m = re.search(r"seq=(\d+)", out)
    assert m is not None, out
    assert int(m.group(1)) == 50


def test_at06_tamper_signature_only(tmp_path):
    db, pem = _build_chain(tmp_path)

    # Replace row 50's sig with a valid signature from a DIFFERENT key over
    # the same (unchanged) this_hash. Hash + chain still pass; sig fails.
    con = sqlite3.connect(str(db))
    try:
        (raw,) = con.execute("SELECT json FROM receipts WHERE seq=50").fetchone()
        row = json.loads(raw)
        this_hash = row["this_hash"]
        other = Ed25519PrivateKey.generate()
        forged = other.sign(this_hash.encode("utf-8"))
        row["sig"] = base64.b64encode(forged).decode("ascii")
        con.execute(
            "UPDATE receipts SET json=? WHERE seq=50",
            (json.dumps(row, sort_keys=True, separators=(",", ":")),),
        )
        con.commit()
    finally:
        con.close()

    bad = _run_verifier(db, pem)
    assert bad.returncode == 1, (bad.stdout, bad.stderr)
    out = bad.stdout.strip()
    assert out == "FAIL seq=50 reason=bad_signature", out
    assert int(re.search(r"seq=(\d+)", out).group(1)) == 50
