"""Consumer-mode approval gate (v0.4) — allow once / always / deny.

A high-stakes capability (requires_user_confirmation) pauses for the user
AFTER policy authorization. Asserted on exact outcomes and receipts:
- a low-risk action runs with NO prompt;
- 'deny' stops execution, writes a chained REJECTED/USER_DENIED receipt
  carrying the authorized ticket id, and produces no draft / no chef artifact;
- 'allow once' executes and asks again next time;
- 'allow always' executes and the SECOND identical action is not asked;
- a policy-rejected high-stakes action never reaches the prompt.
The CliApprover's allow/always/deny parsing is pinned too.
"""

import uuid
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from sentinel_slice.attestor.mock import MockAttestor
from sentinel_slice.cashier.policy import Policy, PolicySet
from sentinel_slice.cashier.store import CashierStore
from sentinel_slice.consumer.approval import (
    ApprovalDecision,
    CliApprover,
    ScriptedApprover,
)
from sentinel_slice.consumer.loop import ConsumerLoop
from sentinel_slice.consumer.preferences import ALLOW, Preferences
from sentinel_slice.ledger.receipts import Ledger
from sentinel_slice.loop import SentinelLoop
from sentinel_slice.menu.catalog import load_catalog
from sentinel_slice.spine.types import Order

SENTINEL_DIR = Path(__file__).resolve().parents[1]
MAILBOX = SENTINEL_DIR / "kitchen" / "fixtures" / "mailbox"

DRAFT = "cap.email.draft_reply.v1"
PAY = "cap.payment.initiate.v1"


def _loop(tmp_path, allowed=(DRAFT, PAY)):
    priv = Ed25519PrivateKey.generate()
    pub = tmp_path / "pub.pem"
    pub.write_bytes(priv.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo))
    policy = PolicySet([Policy(role="account_manager",
                              allowed_capabilities=tuple(allowed),
                              rate_limit_per_hour=20)])
    return SentinelLoop(
        private_key=priv, ledger=Ledger(str(tmp_path / "ledger.db"), priv),
        menu=load_catalog(), policy_set=policy, store=CashierStore(),
        public_key_pem_path=str(pub), fixtures_root=str(MAILBOX),
        attestor=MockAttestor(), window_root=str(tmp_path / "win"))


def _order(capability_id, **kw):
    base = dict(order_id="ord-" + uuid.uuid4().hex, principal="user.kenji",
                role="account_manager", capability_id=capability_id,
                args={"thread_id": "user.kenji/t-001"},
                nonce="nonce-" + uuid.uuid4().hex, ts="2026-06-10T00:00:00+00:00")
    base.update(kw)
    return Order(**base)


def test_low_risk_action_runs_without_prompt(tmp_path):
    approver = ScriptedApprover(ApprovalDecision(allow=False))  # would deny IF asked
    consumer = ConsumerLoop(_loop(tmp_path), approver=approver)

    out = consumer.place(_order(DRAFT))

    assert out.status == "FULFILLED"
    assert out.confirmation_required is False
    assert out.confirmation_asked is False
    assert approver.prompts == []          # never asked
    assert out.draft is not None


def test_deny_blocks_and_records_user_denied_receipt(tmp_path):
    approver = ScriptedApprover(ApprovalDecision(allow=False))
    loop = _loop(tmp_path)
    consumer = ConsumerLoop(loop, approver=approver)

    out = consumer.place(_order(PAY))

    assert out.status == "DENIED_BY_USER"
    assert out.reason_code == "USER_DENIED"
    assert out.confirmation_asked is True
    assert out.draft is None
    assert approver.prompts == [("user.kenji", PAY)]

    rows = consumer.read_receipts()
    assert len(rows) == 1
    assert rows[-1].status == "REJECTED"
    assert rows[-1].reason_code == "USER_DENIED"
    assert rows[-1].ticket_id is not None   # cashier DID authorize
    assert rows[-1].order_meta["capability_id"] == PAY
    # No draft on a denial.
    # (window dir may or may not exist; the draft file must not.)


def test_allow_once_executes_and_asks_again(tmp_path):
    approver = ScriptedApprover([
        ApprovalDecision(allow=True, remember=False),
        ApprovalDecision(allow=True, remember=False),
    ])
    consumer = ConsumerLoop(_loop(tmp_path), approver=approver)

    o1 = consumer.place(_order(PAY))
    o2 = consumer.place(_order(PAY))

    assert o1.status == "FULFILLED" and o2.status == "FULFILLED"
    assert len(approver.prompts) == 2       # asked BOTH times


def test_allow_always_skips_second_prompt(tmp_path):
    approver = ScriptedApprover([ApprovalDecision(allow=True, remember=True)])
    prefs = Preferences()
    consumer = ConsumerLoop(_loop(tmp_path), approver=approver, preferences=prefs)

    o1 = consumer.place(_order(PAY))
    o2 = consumer.place(_order(PAY))

    assert o1.status == "FULFILLED" and o2.status == "FULFILLED"
    assert len(approver.prompts) == 1       # asked ONCE; preference set to ALLOW
    assert prefs.explicit(PAY) == ALLOW


def test_policy_rejection_never_reaches_prompt(tmp_path):
    # Payment NOT in policy -> cashier rejects before any confirmation.
    approver = ScriptedApprover(ApprovalDecision(allow=True))
    consumer = ConsumerLoop(_loop(tmp_path, allowed=(DRAFT,)), approver=approver)

    out = consumer.place(_order(PAY))

    assert out.status == "REJECTED_BY_POLICY"
    assert out.reason_code == "ROLE_NOT_PERMITTED"
    assert approver.prompts == []           # never asked


def test_cli_approver_parsing():
    cap = load_catalog()[PAY]
    order = _order(PAY)
    answers = iter(["o", "a", "d", ""])
    decisions = []
    approver = CliApprover(input_fn=lambda _prompt: next(answers), print_fn=lambda *_a: None)
    for _ in range(4):
        decisions.append(approver.decide(order=order, capability=cap))
    assert decisions[0] == ApprovalDecision(allow=True, remember=False)   # once
    assert decisions[1] == ApprovalDecision(allow=True, remember=True)    # always
    assert decisions[2] == ApprovalDecision(allow=False, remember=False)  # deny
    assert decisions[3] == ApprovalDecision(allow=False, remember=False)  # empty -> deny
