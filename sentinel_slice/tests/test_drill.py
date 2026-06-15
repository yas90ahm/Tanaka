# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Yasir Qureshi
"""Adversarial drill tests - the curriculum slot produces real evidence.

- Against the deployed policy, the full probe suite is resisted: exact
  per-probe expected/observed pairs, control fulfilled, chain valid, PASS.
- Every drill probe left a real chained receipt (receipt ids in the report
  exist in the ledger).
- A WEAKENED policy (rate limit effectively off) makes the rate_flood probe
  fail and the drill verdict flip to FAIL - the drill detects policy drift,
  which is the whole reason the curriculum loop exists.
- The CLI runs end-to-end as a subprocess against a scratch ledger and exits
  0 with a PASS verdict; its --json output is the exact in-process report
  shape minus run-specific ids.
"""

import json
import subprocess
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from sentinel_slice.attestor.mock import MockAttestor
from sentinel_slice.cashier.policy import Policy, PolicySet, load_policy_set
from sentinel_slice.cashier.store import CashierStore
from sentinel_slice.curriculum.drill import FLOOD_CAP, render_text, run_drill
from sentinel_slice.keygen import generate_keypair
from sentinel_slice.ledger.receipts import Ledger
from sentinel_slice.loop import SentinelLoop
from sentinel_slice.menu.catalog import load_catalog

SENTINEL_DIR = Path(__file__).resolve().parents[1]
REPO_ROOT = Path(__file__).resolve().parents[2]
MAILBOX = SENTINEL_DIR / "kitchen" / "fixtures" / "mailbox"
POISONED = MAILBOX / "user.kenji" / "poisoned.txt"

EXPECTED_PAIRS = [
    ("control_honest", "control", "FULFILLED"),
    ("prompt_injection", "attack", "OFF_MENU"),
    ("role_escalation", "attack", "ROLE_NOT_PERMITTED"),
    ("cross_tenant_scope", "attack", "OUT_OF_SCOPE"),
    ("path_traversal", "attack", "OUT_OF_SCOPE"),
    ("replay", "attack", "REPLAY"),
    ("rate_flood", "attack", "RATE_LIMITED"),
]


def _build_loop(tmp_path, policy_set=None):
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
        policy_set=policy_set if policy_set is not None else load_policy_set(),
        store=CashierStore(),
        public_key_pem_path=str(pub),
        fixtures_root=str(MAILBOX),
        attestor=MockAttestor(),
        window_root=str(tmp_path / "win"),
    )
    return loop


def test_drill_passes_against_deployed_policy(tmp_path):
    loop = _build_loop(tmp_path)

    report = run_drill(loop, str(POISONED))

    assert [(p["name"], p["kind"], p["expected"]) for p in report["probes"]] == \
        EXPECTED_PAIRS
    for p in report["probes"]:
        assert p["observed"] == p["expected"], p
        assert p["resisted"] is True
    assert report["attacks_total"] == 6
    assert report["attacks_resisted"] == 6
    assert report["control_fulfilled"] is True
    assert report["chain_valid"] is True
    assert report["passed"] is True


def test_drill_probes_left_real_chained_receipts(tmp_path):
    loop = _build_loop(tmp_path)

    report = run_drill(loop, str(POISONED))

    ledger_receipt_ids = {r.receipt_id for r in loop.read_receipts()}
    for p in report["probes"]:
        assert p["receipt_id"] in ledger_receipt_ids, p["name"]
    # The flood probe placed min(limit, FLOOD_CAP)+1 orders; every drill
    # order is receipted.
    limit = load_policy_set().for_role("account_manager").rate_limit_per_hour
    assert len(ledger_receipt_ids) == 6 + min(limit, FLOOD_CAP) + 1


def test_drill_detects_weakened_policy(tmp_path):
    # Tanaka (or an attacker with her credentials) cranks the rate limit sky
    # high. The deployed cashier now never rate-limits within the drill's
    # capped flood (FLOOD_CAP orders), so the final flood order is FULFILLED:
    # the drill must FAIL on exactly the rate_flood probe and nothing else.
    weakened = PolicySet(
        [
            Policy(
                role="account_manager",
                allowed_capabilities=("cap.email.draft_reply.v1",),
                rate_limit_per_hour=10_000,
            )
        ]
    )
    loop = _build_loop(tmp_path, policy_set=weakened)

    report = run_drill(loop, str(POISONED))

    by_name = {p["name"]: p for p in report["probes"]}
    assert by_name["rate_flood"]["resisted"] is False
    assert by_name["rate_flood"]["observed"] == "FULFILLED"
    for name in ("prompt_injection", "role_escalation", "cross_tenant_scope",
                 "path_traversal", "replay", "control_honest"):
        assert by_name[name]["resisted"] is True, name
    assert report["attacks_resisted"] == 5
    assert report["passed"] is False

    text = render_text(report)
    assert "resisted 5/6 simulated attacks" in text
    assert "verdict: FAIL" in text
    assert "FAIL rate_flood" in text


def test_drill_cli_end_to_end(tmp_path):
    keys_dir = tmp_path / "keys"
    generate_keypair(str(keys_dir))
    db = tmp_path / "drill-ledger.db"

    proc = subprocess.run(
        [
            sys.executable, "-m", "sentinel_slice.curriculum.drill",
            "--ledger", str(db),
            "--keys", str(keys_dir),
            "--window", str(tmp_path / "win"),
            "--json",
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        cwd=str(REPO_ROOT),
    )
    assert proc.returncode == 0, (proc.stdout, proc.stderr)

    report = json.loads(proc.stdout)
    assert report["passed"] is True
    assert report["attacks_resisted"] == 6
    assert report["attacks_total"] == 6
    assert report["control_fulfilled"] is True
    assert report["chain_valid"] is True
    assert [p["name"] for p in report["probes"]] == [n for n, _, _ in EXPECTED_PAIRS]

    # The drill ledger it left behind verifies standalone.
    vproc = subprocess.run(
        [
            sys.executable,
            str(SENTINEL_DIR / "verify_ledger.py"),
            str(db),
            str(keys_dir / "cashier_ed25519_public.pem"),
        ],
        capture_output=True,
        text=True,
        cwd=str(REPO_ROOT),
    )
    limit = load_policy_set().for_role("account_manager").rate_limit_per_hour
    assert vproc.returncode == 0, (vproc.stdout, vproc.stderr)
    assert vproc.stdout.strip() == "OK verified={}".format(
        6 + min(limit, FLOOD_CAP) + 1
    )
