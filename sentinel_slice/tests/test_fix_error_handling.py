# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Yasir Qureshi
"""Regression: malformed crypto/db inputs yield the documented usage exit code
(2) with a one-line message, never an uncaught traceback / exit 1
(review #6, #7, #8, #9).
"""

import base64
import json
import sqlite3
import subprocess
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

SENTINEL_DIR = Path(__file__).resolve().parents[1]
CHEF_MAIN = SENTINEL_DIR / "chef" / "chef_main.py"
VERIFIER = SENTINEL_DIR / "verify_ledger.py"

# A structurally valid wire ticket so the chef reaches the pubkey-loading step
# (it parses stdin BEFORE loading the key). The signature need not be valid:
# the pubkey-type/format checks happen before verify().
VALID_WIRE = json.dumps({
    "ticket_id": "tkt-x",
    "order_id": "ord-x",
    "capability_id": "cap.email.draft_reply.v1",
    "behavior": "draft_reply",
    "behavior_config": {},
    "scoped_args": {"thread_id": "user.kenji/t-001"},
    "issued_ts": "2026-06-10T00:00:00+00:00",
    "cashier_sig": base64.b64encode(b"\x00" * 64).decode("ascii"),
})


def _chef(pubkey_path, fixtures_root, out_dir):
    return subprocess.run(
        [sys.executable, str(CHEF_MAIN), str(pubkey_path), str(fixtures_root), str(out_dir)],
        input=VALID_WIRE, capture_output=True, text=True,
    )


def test_chef_exit2_on_non_ed25519_pubkey(tmp_path):
    rsa_pub = tmp_path / "rsa.pem"
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    rsa_pub.write_bytes(key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ))
    proc = _chef(rsa_pub, tmp_path, tmp_path / "out")
    # Was exit 1 + TypeError traceback before the fix.
    assert proc.returncode == 2, (proc.stdout, proc.stderr)
    assert not (tmp_path / "out" / "output.txt").exists()


def test_chef_exit2_on_malformed_pubkey_pem(tmp_path):
    bad = tmp_path / "bad.pem"
    bad.write_text("this is not a PEM public key\n", encoding="utf-8")
    proc = _chef(bad, tmp_path, tmp_path / "out")
    # Was exit 1 + ValueError traceback before the fix.
    assert proc.returncode == 2, (proc.stdout, proc.stderr)


def _verify(db, pem):
    return subprocess.run(
        [sys.executable, str(VERIFIER), str(db), str(pem)],
        capture_output=True, text=True,
    )


def test_verifier_exit2_on_missing_pubkey_file(tmp_path):
    proc = _verify(tmp_path / "nope.db", tmp_path / "does_not_exist.pem")
    assert proc.returncode == 2, (proc.stdout, proc.stderr)
    assert proc.stdout.startswith("usage:")


def test_verifier_exit2_on_private_key_as_pubkey(tmp_path):
    priv_pem = tmp_path / "priv.pem"
    priv_pem.write_bytes(Ed25519PrivateKey.generate().private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ))
    proc = _verify(tmp_path / "nope.db", priv_pem)
    # A private-key PEM is not a public key -> usage error, not a traceback.
    assert proc.returncode == 2, (proc.stdout, proc.stderr)
    assert proc.stdout.startswith("usage:")


def test_verifier_exit2_on_db_without_receipts_table(tmp_path):
    # A valid Ed25519 pubkey so the verifier reaches the db query...
    priv = Ed25519PrivateKey.generate()
    pub = tmp_path / "pub.pem"
    pub.write_bytes(priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ))
    # ...but the db has no `receipts` table.
    db = tmp_path / "wrong.db"
    conn = sqlite3.connect(str(db))
    conn.execute("CREATE TABLE other (x INTEGER)")
    conn.commit()
    conn.close()

    proc = _verify(db, pub)
    # Was exit 1 + sqlite3.OperationalError traceback before the fix.
    assert proc.returncode == 2, (proc.stdout, proc.stderr)
    assert proc.stdout.startswith("usage:")
