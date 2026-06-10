"""ConsoleService logic + separation of duties (v0.3 phase 2).

Drives the service directly (no HTTP) and asserts exact effects:
- simulate runs the real pipeline against a candidate policy and writes
  NOTHING (policy history + materialized file unchanged);
- publish of an ordinary policy is active immediately and materializes so the
  engine would enforce it; publish of a requires_second_admin capability is
  PENDING and does NOT change the active policy;
- approve needs a reviewer who is NOT the proposer; same-admin approval and
  author-role approval are both refused; a valid approval activates;
- rollback re-publishes old content as a new version (history grows, nothing
  deleted);
- role gates: a reviewer cannot publish, an author cannot approve;
- activity equals inspector.build_report over the same ledger.
"""

import uuid
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from sentinel_slice import inspector
from sentinel_slice.attestor.mock import MockAttestor
from sentinel_slice.authoring.policy_store import PolicyStore
from sentinel_slice.cashier.policy import load_policy_set
from sentinel_slice.cashier.store import CashierStore
from sentinel_slice.console.auth import Admin, ROLE_AUTHOR, ROLE_REVIEWER
from sentinel_slice.console.service import (
    AuthError,
    ConflictError,
    ConsoleService,
    NotFoundError,
)
from sentinel_slice.ledger.receipts import Ledger
from sentinel_slice.loop import SentinelLoop
from sentinel_slice.menu.catalog import load_catalog
from sentinel_slice.spine.types import Order

SENTINEL_DIR = Path(__file__).resolve().parents[1]
MAILBOX = SENTINEL_DIR / "kitchen" / "fixtures" / "mailbox"

AUTHOR = Admin(id="tanaka", role=ROLE_AUTHOR)
AUTHOR2 = Admin(id="okoro", role=ROLE_AUTHOR)
REVIEWER = Admin(id="rao", role=ROLE_REVIEWER)

DRAFT = "cap.email.draft_reply.v1"
PAY = "cap.payment.initiate.v1"

POLICY_DRAFT = [{"role": "account_manager",
                 "allowed_capabilities": [DRAFT], "rate_limit_per_hour": 5}]
POLICY_WITH_PAY = [{"role": "account_manager",
                    "allowed_capabilities": [DRAFT, PAY],
                    "rate_limit_per_hour": 5}]


def _service(tmp_path):
    priv = Ed25519PrivateKey.generate()
    pub = tmp_path / "pub.pem"
    pub.write_bytes(
        priv.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
    )
    policies_dir = tmp_path / "active_policies"
    policies_dir.mkdir()
    store = PolicyStore(str(tmp_path / "policy.db"), priv)
    svc = ConsoleService(
        private_key=priv,
        public_key_pem_path=str(pub),
        ledger_db_path=str(tmp_path / "ledger.db"),
        policy_store=store,
        policies_dir=str(policies_dir),
        catalog=load_catalog(),
    )
    return svc, priv, pub, policies_dir


def test_simulate_uses_real_pipeline_and_writes_nothing(tmp_path):
    svc, _priv, _pub, policies_dir = _service(tmp_path)

    out = svc.simulate(
        AUTHOR,
        candidate_policy=POLICY_DRAFT,
        sample_orders=[
            {"principal": "user.kenji", "role": "account_manager",
             "capability_id": DRAFT, "args": {"thread_id": "user.kenji/t-001"}},
            {"principal": "user.kenji", "role": "intern",
             "capability_id": DRAFT, "args": {"thread_id": "user.kenji/t-001"}},
            {"principal": "user.kenji", "role": "account_manager",
             "capability_id": "forward_inbox", "args": {"target": "x"}},
        ],
    )
    assert out["results"] == [
        {"principal": "user.kenji", "role": "account_manager",
         "capability_id": DRAFT, "allowed": True, "reason_code": None},
        {"principal": "user.kenji", "role": "intern",
         "capability_id": DRAFT, "allowed": False,
         "reason_code": "ROLE_NOT_PERMITTED"},
        {"principal": "user.kenji", "role": "account_manager",
         "capability_id": "forward_inbox", "allowed": False,
         "reason_code": "OFF_MENU"},
    ]
    # Nothing written: no policy versions, no materialized file.
    assert svc._policy_store.read_all() == []
    assert not (policies_dir / "active.json").exists()


def test_publish_ordinary_is_active_and_materializes(tmp_path):
    svc, _priv, _pub, policies_dir = _service(tmp_path)

    res = svc.publish(AUTHOR, POLICY_DRAFT, reason="initial policy")
    assert res["status"] == "active"
    assert res["requires_second_admin_for"] == []

    # Active version is set, and the engine would load the materialized file.
    pol = load_policy_set(str(policies_dir)).for_role("account_manager")
    assert pol.allowed_capabilities == (DRAFT,)
    assert pol.rate_limit_per_hour == 5


def test_publish_second_admin_capability_is_pending(tmp_path):
    svc, _priv, _pub, policies_dir = _service(tmp_path)
    svc.publish(AUTHOR, POLICY_DRAFT, reason="baseline")

    res = svc.publish(AUTHOR, POLICY_WITH_PAY, reason="add payments")
    assert res["status"] == "pending"
    assert res["requires_second_admin_for"] == [PAY]

    # Active policy is UNCHANGED — payments are not live yet.
    active = svc.policies(AUTHOR)["active"]
    assert active["policies"] == POLICY_DRAFT


def test_approve_requires_different_reviewer(tmp_path):
    svc, _priv, _pub, _dir = _service(tmp_path)
    svc.publish(AUTHOR, POLICY_DRAFT, reason="baseline")
    pending = svc.publish(AUTHOR, POLICY_WITH_PAY, reason="add payments")
    seq = pending["seq"]

    # An author cannot approve at all (wrong role).
    with pytest.raises(AuthError):
        svc.approve(AUTHOR, seq)
    # A reviewer who is ALSO the proposer is blocked by separation of duties...
    self_reviewer = Admin(id="tanaka", role=ROLE_REVIEWER)
    with pytest.raises(AuthError):
        svc.approve(self_reviewer, seq)
    # A different reviewer approves -> payments go active.
    res = svc.approve(REVIEWER, seq)
    assert res["status"] == "active"
    assert res["approved_by"] == "rao"
    assert res["approved_proposal_seq"] == seq
    assert svc.policies(AUTHOR)["active"]["policies"] == POLICY_WITH_PAY


def test_approve_nonpending_conflicts(tmp_path):
    svc, _priv, _pub, _dir = _service(tmp_path)
    active = svc.publish(AUTHOR, POLICY_DRAFT, reason="baseline")
    with pytest.raises(ConflictError):
        svc.approve(REVIEWER, active["seq"])
    with pytest.raises(NotFoundError):
        svc.approve(REVIEWER, 9999)


def test_rollback_appends_and_restores(tmp_path):
    svc, _priv, _pub, _dir = _service(tmp_path)
    v1 = svc.publish(AUTHOR, POLICY_DRAFT, reason="v1")
    svc.publish(AUTHOR, [{"role": "account_manager",
                          "allowed_capabilities": [DRAFT],
                          "rate_limit_per_hour": 99}], reason="v2 loosen")

    svc.rollback(AUTHOR, target_seq=v1["seq"], reason="undo loosening")

    history = svc.policies(AUTHOR)["history"]
    assert len(history) == 3                     # nothing deleted
    active = svc.policies(AUTHOR)["active"]
    assert active["policies"][0]["rate_limit_per_hour"] == 5


def test_role_gates(tmp_path):
    svc, _priv, _pub, _dir = _service(tmp_path)
    with pytest.raises(AuthError):
        svc.publish(REVIEWER, POLICY_DRAFT, reason="reviewer cannot publish")
    with pytest.raises(AuthError):
        svc.simulate(REVIEWER, POLICY_DRAFT,
                     [{"principal": "u", "role": "r", "capability_id": DRAFT}])
    with pytest.raises(AuthError):
        svc.capabilities(None)


def test_activity_matches_inspector(tmp_path):
    svc, priv, pub, _dir = _service(tmp_path)

    # Drive a few real orders into the SAME ledger the service reads.
    ledger = Ledger(svc._ledger_db_path, priv)
    loop = SentinelLoop(
        private_key=priv, ledger=ledger, menu=load_catalog(),
        policy_set=load_policy_set(), store=CashierStore(),
        public_key_pem_path=str(pub), fixtures_root=str(MAILBOX),
        attestor=MockAttestor(), window_root=str(tmp_path / "win"),
    )
    loop.place(Order(
        order_id="ord-" + uuid.uuid4().hex, principal="user.kenji",
        role="account_manager", capability_id=DRAFT,
        args={"thread_id": "user.kenji/t-001"},
        nonce="n-" + uuid.uuid4().hex, ts="2026-06-10T00:00:00+00:00"))
    loop.place(Order(
        order_id="ord-" + uuid.uuid4().hex, principal="user.kenji",
        role="account_manager", capability_id="forward_inbox",
        args={"target": "x"}, nonce="n-" + uuid.uuid4().hex,
        ts="2026-06-10T00:00:00+00:00"))

    public_key = serialization.load_pem_public_key(pub.read_bytes())
    expected = inspector.build_report(
        inspector.read_rows(svc._ledger_db_path), public_key
    )
    assert svc.activity(AUTHOR) == expected
    assert svc.activity(REVIEWER) == expected   # both roles may read


def test_run_drill_passes_and_leaves_live_ledger_untouched(tmp_path):
    svc, _priv, _pub, _dir = _service(tmp_path)
    svc.publish(AUTHOR, POLICY_DRAFT, reason="baseline")

    report = svc.run_drill(REVIEWER)
    assert report["passed"] is True
    assert report["attacks_resisted"] == 6
    # The drill used a scratch ledger; the console's live ledger is untouched.
    assert svc.activity(AUTHOR)["receipts_total"] == 0
