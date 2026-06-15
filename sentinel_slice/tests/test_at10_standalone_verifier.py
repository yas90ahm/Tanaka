# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Yasir Qureshi
"""SPEC acceptance #10 — standalone verifier.

(a) The verifier validates a real db using ONLY db + public-key PEM (no
    package on the path's reach) -> exit 0, exact OK line.
(b) Import-closure: in a FRESH subprocess, import verify_ledger.py BY FILE
    PATH and assert that no 'sentinel_slice' module landed in sys.modules.
(c) An empty ledger verifies as OK verified=0.
"""

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


def _run_verifier(db, pem):
    return subprocess.run(
        [sys.executable, str(VERIFIER), str(db), str(pem)],
        capture_output=True,
        text=True,
    )


def test_at10_full_chain_verifies_standalone(tmp_path):
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

    result = _run_verifier(db, pem)
    assert result.returncode == 0, (result.stdout, result.stderr)
    assert result.stdout.strip() == "OK verified=100"


def test_at10_verifier_import_closure_excludes_sentinel_slice(tmp_path):
    # Child program: import the verifier by FILE PATH (not package import),
    # then assert nothing under 'sentinel_slice' got pulled into sys.modules.
    child = (
        "import importlib.util, sys\n"
        f"path = {str(VERIFIER)!r}\n"
        "spec = importlib.util.spec_from_file_location('verify_ledger_mod', path)\n"
        "mod = importlib.util.module_from_spec(spec)\n"
        "spec.loader.exec_module(mod)\n"
        "bad = [m for m in sys.modules if m == 'sentinel_slice' or m.startswith('sentinel_slice.')]\n"
        "assert not bad, bad\n"
        "print('OK')\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", child],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, (result.stdout, result.stderr)
    assert result.stdout.strip() == "OK"


def test_at10_empty_ledger_ok(tmp_path):
    priv, pub, pem = _keypair(tmp_path)
    db = tmp_path / "ledger.db"
    # Construct but never append: table exists, zero rows.
    Ledger(str(db), priv)

    result = _run_verifier(db, pem)
    assert result.returncode == 0, (result.stdout, result.stderr)
    assert result.stdout.strip() == "OK verified=0"
