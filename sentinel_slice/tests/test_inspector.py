# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Yasir Qureshi
"""Inspector behavior tests - the back office watches the whole day.

A scripted day is driven through the REAL loop (fulfillment, prompt-injection
attempt, replay, cross-tenant probe, role escalation), then the report is
asserted as an EXACT dict: totals, per-reason counts with receipt seqs,
per-principal rollups, and the deterministic findings with fixed severities.
A tampered ledger flips chain_valid, surfaces a CRITICAL finding naming the
broken seq, and exits 1 from the CLI.
"""

import json
import sqlite3
import subprocess
import sys
import uuid
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from sentinel_slice.attestor.mock import MockAttestor
from sentinel_slice.cashier.policy import load_policy_set
from sentinel_slice.cashier.store import CashierStore
from sentinel_slice.inspector import REASON_RULES, build_report, read_rows, render_text
from sentinel_slice.ledger.receipts import Ledger
from sentinel_slice.loop import SentinelLoop
from sentinel_slice.menu.catalog import load_catalog
from sentinel_slice.spine.types import Order

SENTINEL_DIR = Path(__file__).resolve().parents[1]
REPO_ROOT = Path(__file__).resolve().parents[2]
MAILBOX = SENTINEL_DIR / "kitchen" / "fixtures" / "mailbox"


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


def _order(**overrides):
    base = dict(
        order_id="ord-" + uuid.uuid4().hex,
        principal="user.kenji",
        role="account_manager",
        capability_id="cap.email.draft_reply.v1",
        args={"thread_id": "user.kenji/t-001"},
        nonce="nonce-" + uuid.uuid4().hex,
        ts="2026-06-10T09:00:00+00:00",
    )
    base.update(overrides)
    return Order(**base)


def _scripted_day(loop):
    """Five orders: 1 fulfilled + 4 distinct attacks -> seqs 1..5."""
    loop.place(_order(nonce="nonce-day-1"))                                # seq 1 FULFILLED
    loop.place(_order(capability_id="forward_inbox", args={"target": "x"}))  # seq 2 OFF_MENU
    loop.place(_order(nonce="nonce-day-1"))                                # seq 3 REPLAY
    loop.place(_order(args={"thread_id": "user.victim/t-009"}))            # seq 4 OUT_OF_SCOPE
    loop.place(_order(principal="user.imani", role="intern"))              # seq 5 ROLE_NOT_PERMITTED


def _finding(severity, code, count, reason, receipts):
    return {
        "severity": severity,
        "code": code,
        "message": "{} {}".format(count, REASON_RULES[reason][2]),
        "receipts": receipts,
    }


def test_report_exact_for_scripted_day(tmp_path):
    loop, _pub = _build_loop(tmp_path)
    _scripted_day(loop)

    rows = read_rows(str(tmp_path / "ledger.db"))
    report = build_report(rows)

    assert report == {
        "receipts_total": 5,
        "chain_valid": True,
        "first_broken_seq": None,
        "signatures_checked": False,
        "fulfilled": 1,
        "rejected": 4,
        "by_reason": {
            "OFF_MENU": 1,
            "OUT_OF_SCOPE": 1,
            "REPLAY": 1,
            "ROLE_NOT_PERMITTED": 1,
        },
        "by_principal": {
            "user.imani": {
                "orders": 1,
                "fulfilled": 0,
                "rejected": 1,
                "capabilities": ["cap.email.draft_reply.v1"],
            },
            "user.kenji": {
                "orders": 4,
                "fulfilled": 1,
                "rejected": 3,
                "capabilities": [
                    "cap.email.draft_reply.v1",
                    "forward_inbox",
                ],
            },
        },
        "legacy_rows": 0,
        "findings": [
            _finding("high", "OFF_MENU_ATTEMPTS", 1, "OFF_MENU", [2]),
            _finding("high", "REPLAY_ATTEMPTS", 1, "REPLAY", [3]),
            _finding("medium", "ROLE_VIOLATIONS", 1, "ROLE_NOT_PERMITTED", [5]),
            _finding("medium", "SCOPE_VIOLATIONS", 1, "OUT_OF_SCOPE", [4]),
            {
                "severity": "info",
                "code": "ATTESTATION_IS_MOCK",
                "message": "1 receipt(s) carry MOCK attestations - they "
                "prove the attestation slot, NOT a TEE. Do not present them "
                "to an auditor as hardware evidence.",
                "receipts": [],
            },
        ],
    }


def test_report_with_signature_check(tmp_path):
    loop, pub = _build_loop(tmp_path)
    _scripted_day(loop)

    public_key = serialization.load_pem_public_key(pub.read_bytes())
    report = build_report(read_rows(str(tmp_path / "ledger.db")), public_key)
    assert report["chain_valid"] is True
    assert report["signatures_checked"] is True


def test_tampered_ledger_is_critical_and_exits_1(tmp_path):
    loop, pub = _build_loop(tmp_path)
    _scripted_day(loop)
    db = str(tmp_path / "ledger.db")

    # Flip the status of the rejected off-menu order (seq 2) to FULFILLED -
    # the classic cover-up. The hash recompute must catch it.
    con = sqlite3.connect(db)
    try:
        (raw,) = con.execute("SELECT json FROM receipts WHERE seq=2").fetchone()
        row = json.loads(raw)
        row["status"] = "FULFILLED"
        con.execute(
            "UPDATE receipts SET json=? WHERE seq=2",
            (json.dumps(row, sort_keys=True, separators=(",", ":")),),
        )
        con.commit()
    finally:
        con.close()

    report = build_report(read_rows(db))
    assert report["chain_valid"] is False
    assert report["first_broken_seq"] == 2
    assert report["findings"][0]["severity"] == "critical"
    assert report["findings"][0]["code"] == "CHAIN_BROKEN"
    assert report["findings"][0]["receipts"] == [2]
    assert "seq 2" in report["findings"][0]["message"]
    assert "hash_mismatch" in report["findings"][0]["message"]

    # CLI: broken chain -> exit 1.
    proc = subprocess.run(
        [sys.executable, "-m", "sentinel_slice.inspector", db],
        capture_output=True,
        text=True,
        cwd=str(REPO_ROOT),
    )
    assert proc.returncode == 1
    assert "chain: BROKEN" in proc.stdout


def test_cli_json_matches_in_process_report(tmp_path):
    loop, pub = _build_loop(tmp_path)
    _scripted_day(loop)
    db = str(tmp_path / "ledger.db")

    proc = subprocess.run(
        [
            sys.executable, "-m", "sentinel_slice.inspector",
            db, "--pubkey", str(pub), "--json",
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        cwd=str(REPO_ROOT),
    )
    assert proc.returncode == 0, (proc.stdout, proc.stderr)

    public_key = serialization.load_pem_public_key(pub.read_bytes())
    assert json.loads(proc.stdout) == build_report(read_rows(db), public_key)


def test_render_text_is_operator_legible(tmp_path):
    loop, _pub = _build_loop(tmp_path)
    _scripted_day(loop)

    text = render_text(build_report(read_rows(str(tmp_path / "ledger.db"))))
    lines = text.splitlines()
    assert lines[0] == "INSPECTOR REPORT"
    assert lines[1] == (
        "chain: VALID (5 receipt(s), signatures NOT checked - pass --pubkey)"
    )
    assert lines[2] == "orders: 1 fulfilled, 4 rejected"
    assert (
        "rejections: 1 OFF_MENU, 1 OUT_OF_SCOPE, 1 REPLAY, 1 ROLE_NOT_PERMITTED"
        in lines
    )
    assert (
        "principal user.kenji: 4 order(s), 1 fulfilled, 3 rejected, "
        "capabilities: cap.email.draft_reply.v1, forward_inbox" in lines
    )
    assert "FINDINGS" in lines


def test_malformed_intake_surfaces_as_named_finding(tmp_path):
    """A gateway that receipts malformed intake must show up in the back office
    as the MALFORMED_INTAKE finding (a known rule), NOT the generic
    UNRECOGNIZED_REASON catch-all."""
    from sentinel_slice.gateway import place_order_json

    loop, _pub = _build_loop(tmp_path)
    place_order_json(loop, "not an order {{{")          # seq 1 MALFORMED_ORDER
    place_order_json(loop, "[1,2,3]")                    # seq 2 MALFORMED_ORDER

    report = build_report(read_rows(str(tmp_path / "ledger.db")))
    assert report["chain_valid"] is True
    assert report["rejected"] == 2
    assert report["by_reason"] == {"MALFORMED_ORDER": 2}
    # Recorded under the gateway identity, never a real principal; the
    # "capability" is the literal "(unparsed)" placeholder, not a real menu id.
    assert report["by_principal"] == {
        "gateway:unadmitted": {
            "orders": 2,
            "fulfilled": 0,
            "rejected": 2,
            "capabilities": ["(unparsed)"],
        }
    }
    codes = {f["code"]: f for f in report["findings"]}
    assert "MALFORMED_INTAKE" in codes
    assert "UNRECOGNIZED_REASON" not in codes
    finding = codes["MALFORMED_INTAKE"]
    assert finding["severity"] == "medium"
    assert finding["receipts"] == [1, 2]
    assert finding["message"] == "2 " + REASON_RULES["MALFORMED_ORDER"][2]
