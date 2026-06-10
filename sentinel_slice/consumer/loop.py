"""ConsumerLoop — the personal-machine orchestration with a confirmation gate.

Same engine as the enterprise path, different control shape. It runs the
cashier (policy authorization) with NO auto-execute, then — for capabilities
flagged `requires_user_confirmation` and not already standing-granted — asks
the user (via an approver). Deny stops execution and records a chained
USER_DENIED receipt; allow runs the chef exactly as the enterprise loop does.

It reuses an already-built SentinelLoop for all the wiring (key, ledger, menu,
fixtures, attestor, window) — it does not duplicate that. It simply inserts the
human gate between `process_order` (run with spawn=None, so nothing executes
yet) and `run_chef`.

This is where the computer-use-agent story lands: the agent browses/reads
freely, but the moment it reaches for a high-stakes action, this gate is the
chokepoint — and a prompt-injected agent meets your "deny", on the record.
"""

import uuid
from dataclasses import dataclass

from sentinel_slice.cashier.engine import process_order
from sentinel_slice.chef.runner import run_chef
from sentinel_slice.consumer.approval import ApprovalStore
from sentinel_slice.spine.types import order_meta_from_order


@dataclass(frozen=True)
class ConsumerOutcome:
    """What happened to one consumer action, in plain terms.

    status is one of:
      REJECTED_BY_POLICY  - the cashier refused (off-menu, scope, role, ...).
      DENIED_BY_USER      - policy allowed it, you declined at the prompt.
      FULFILLED           - allowed (or no confirmation needed) and the chef ran.
      EXECUTION_FAILED    - allowed but the chef failed.
    """
    status: str
    reason_code: str | None
    receipt: object
    draft: bytes | None
    confirmation_required: bool
    confirmation_asked: bool


class ConsumerLoop:
    def __init__(self, sentinel_loop, *, approver, approval_store=None) -> None:
        self._loop = sentinel_loop
        self._approver = approver
        self._grants = approval_store if approval_store is not None else ApprovalStore()

    @property
    def grants(self) -> ApprovalStore:
        return self._grants

    def read_receipts(self) -> list:
        return self._loop.read_receipts()

    def place(self, order) -> ConsumerOutcome:
        loop = self._loop

        # 1) Cashier authorization — spawn=None means nothing executes yet.
        outcome = process_order(
            order,
            menu=loop.menu,
            policy_set=loop.policy_set,
            store=loop.store,
            ledger=loop.ledger,
            private_key=loop.private_key,
            spawn=None,
        )
        if not outcome.accepted:
            return ConsumerOutcome(
                status="REJECTED_BY_POLICY",
                reason_code=outcome.reason_code,
                receipt=outcome.receipt,
                draft=None,
                confirmation_required=False,
                confirmation_asked=False,
            )

        ticket = outcome.ticket
        capability = loop.menu.get(order.capability_id)
        needs_confirm = bool(capability and capability.requires_user_confirmation)
        asked = False

        # 2) Human-in-the-loop gate (only for confirmation-required caps without
        #    a standing grant).
        if needs_confirm and not self._grants.has_grant(order.principal, order.capability_id):
            asked = True
            decision = self._approver.decide(order=order, capability=capability)
            if decision.allow and decision.remember:
                self._grants.grant(order.principal, order.capability_id)
            if not decision.allow:
                receipt = loop.ledger.append(
                    receipt_id="rcpt-" + uuid.uuid4().hex,
                    order_id=order.order_id,
                    ticket_id=ticket.ticket_id,  # cashier DID authorize
                    status="REJECTED",
                    reason_code="USER_DENIED",
                    result_digest=None,
                    attestation=None,
                    order_meta=order_meta_from_order(order),
                )
                return ConsumerOutcome(
                    status="DENIED_BY_USER",
                    reason_code="USER_DENIED",
                    receipt=receipt,
                    draft=None,
                    confirmation_required=True,
                    confirmation_asked=True,
                )

        # 3) Execute exactly as the enterprise loop does.
        chef = run_chef(
            ticket,
            ledger=loop.ledger,
            public_key_pem_path=loop.public_key_pem_path,
            fixtures_root=loop.fixtures_root,
            attestor=loop.attestor,
            window_root=loop.window_root,
            order_meta=order_meta_from_order(order),
        )
        fulfilled = chef.returncode == 0 and chef.draft_bytes is not None
        return ConsumerOutcome(
            status="FULFILLED" if fulfilled else "EXECUTION_FAILED",
            reason_code=None if fulfilled else "EXECUTION_FAILED",
            receipt=chef.receipt,
            draft=chef.draft_bytes if fulfilled else None,
            confirmation_required=needs_confirm,
            confirmation_asked=asked,
        )
