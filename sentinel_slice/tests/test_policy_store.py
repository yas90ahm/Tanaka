"""Policy store - the policy chain has the same integrity as the ledger.

Asserts exact values: genesis on v1, chain linkage, active = latest active,
rollback appends (never deletes) and restores content, materialize writes the
engine's file shape, the standalone verifier returns OK verified=N, and a
tampered version breaks it at the right seq. Append-only is grep-proven on the
source (no UPDATE/DELETE), same bar as the ledger.
"""

import hashlib
import json
import sqlite3
import subprocess
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from sentinel_slice.authoring.policy_store import (
    POLICY_GENESIS_PREV_HASH,
    PolicyStore,
)
from sentinel_slice.cashier.policy import load_policy_set

SENTINEL_DIR = Path(__file__).resolve().parents[1]
REPO_ROOT = Path(__file__).resolve().parents[2]
VERIFIER = SENTINEL_DIR / "verify_policy_history.py"
STORE_SRC = SENTINEL_DIR / "authoring" / "policy_store.py"

P1 = [{"role": "account_manager",
       "allowed_capabilities": ["cap.email.draft_reply.v1"],
       "rate_limit_per_hour": 5}]
P2 = [{"role": "account_manager",
       "allowed_capabilities": ["cap.email.draft_reply.v1"],
       "rate_limit_per_hour": 9}]


def _keypair(tmp_path):
    priv = Ed25519PrivateKey.generate()
    pub = tmp_path / "pub.pem"
    pub.write_bytes(
        priv.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    return priv, pub


def _run_verifier(db, pem):
    return subprocess.run(
        [sys.executable, str(VERIFIER), str(db), str(pem)],
        capture_output=True, text=True, cwd=str(REPO_ROOT),
    )


def test_genesis_and_chain_links(tmp_path):
    priv, _pub = _keypair(tmp_path)
    store = PolicyStore(str(tmp_path / "policy.db"), priv)

    v1 = store.append_version(policies=P1, author="tanaka", reason="initial")
    v2 = store.append_version(policies=P2, author="tanaka", reason="raise rate")

    assert v1["prev_hash"] == POLICY_GENESIS_PREV_HASH
    assert v1["prev_hash"] == hashlib.sha256(b"POLICY-GENESIS").hexdigest()
    assert v2["prev_hash"] == v1["this_hash"]
    assert [r["seq"] for r in store.read_all()] == [1, 2]


def test_active_is_latest_active(tmp_path):
    priv, _pub = _keypair(tmp_path)
    store = PolicyStore(str(tmp_path / "policy.db"), priv)

    store.append_version(policies=P1, author="t", reason="v1")
    store.append_version(policies=P2, author="t", reason="v2")
    # A pending proposal does NOT become active.
    store.append_version(policies=P1, author="t", reason="proposal",
                         status="pending")

    active = store.active_version()
    assert active["policies"] == P2
    assert active["reason"] == "v2"


def test_rollback_appends_and_restores(tmp_path):
    priv, _pub = _keypair(tmp_path)
    store = PolicyStore(str(tmp_path / "policy.db"), priv)

    store.append_version(policies=P1, author="t", reason="v1")
    store.append_version(policies=P2, author="t", reason="v2")
    # Rollback = republish v1's content as a NEW version.
    target = store.read_all()[0]
    store.append_version(policies=target["policies"], author="t",
                         reason="rollback to seq 1")

    history = store.read_all()
    assert len(history) == 3          # nothing deleted
    assert store.active_version()["policies"] == P1
    assert history[-1]["reason"] == "rollback to seq 1"


def test_materialize_active_feeds_the_engine(tmp_path):
    priv, _pub = _keypair(tmp_path)
    store = PolicyStore(str(tmp_path / "policy.db"), priv)
    store.append_version(policies=P2, author="t", reason="rate 9")

    policies_dir = tmp_path / "policies"
    policies_dir.mkdir()
    store.materialize_active(str(policies_dir / "account_manager.json"))

    # The engine loads the materialized file verbatim - the round trip.
    pset = load_policy_set(str(policies_dir))
    pol = pset.for_role("account_manager")
    assert pol.rate_limit_per_hour == 9
    assert pol.allowed_capabilities == ("cap.email.draft_reply.v1",)


def test_standalone_verifier_ok(tmp_path):
    priv, pub = _keypair(tmp_path)
    db = tmp_path / "policy.db"
    store = PolicyStore(str(db), priv)
    store.append_version(policies=P1, author="t", reason="v1")
    store.append_version(policies=P2, author="t", reason="v2")
    store.append_version(policies=P1, author="t", reason="rollback")

    proc = _run_verifier(db, pub)
    assert proc.returncode == 0, (proc.stdout, proc.stderr)
    assert proc.stdout.strip() == "OK verified=3"


def test_tampered_version_breaks_at_right_seq(tmp_path):
    priv, pub = _keypair(tmp_path)
    db = tmp_path / "policy.db"
    store = PolicyStore(str(db), priv)
    store.append_version(policies=P1, author="t", reason="v1")
    store.append_version(policies=P2, author="t", reason="v2")

    # Forge version 2's rate back down without re-signing.
    con = sqlite3.connect(str(db))
    try:
        (raw,) = con.execute("SELECT json FROM policy_versions WHERE seq=2").fetchone()
        row = json.loads(raw)
        row["policies"][0]["rate_limit_per_hour"] = 999
        con.execute(
            "UPDATE policy_versions SET json=? WHERE seq=2",
            (json.dumps(row, sort_keys=True, separators=(",", ":")),),
        )
        con.commit()
    finally:
        con.close()

    proc = _run_verifier(db, pub)
    assert proc.returncode == 1
    assert proc.stdout.strip() == "FAIL seq=2 reason=hash_mismatch"


def test_store_source_has_no_update_delete():
    src = STORE_SRC.read_text(encoding="utf-8").upper()
    for forbidden in ("UPDATE", "DELETE", "REPLACE", "DROP", "ALTER"):
        assert forbidden not in src, f"forbidden SQL token in policy store: {forbidden}"
