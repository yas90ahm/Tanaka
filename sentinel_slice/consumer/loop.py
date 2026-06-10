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
from sentinel_slice.consumer.preferences import ALLOW, ASK, BLOCK, Preferences
from sentinel_slice.spine.types import order_meta_from_order


@dataclass(frozen=True)
class ConsumerOutcome:
    """What happened to one consumer action, in plain terms.

    status is one of:
      REJECTED_BY_POLICY  - the cashier refused (off-menu, scope, role, ...).
      BLOCKED_BY_USER     - your permissions set this capability to BLOCK.
      DENIED_BY_USER      - policy + permissions allowed an ASK; you declined.
      FULFILLED           - allowed (pref ALLOW or you said yes) and chef ran.
      EXECUTION_FAILED    - allowed but the chef failed.
    """
    status: str
    reason_code: str | None
    receipt: object
    draft: bytes | None
    confirmation_required: bool
    confirmation_asked: bool


class ConsumerLoop:
    def __init__(self, sentinel_loop, *, approver, preferences=None) -> None:
        self._loop = sentinel_loop
        self._approver = approver
        self._prefs = preferences if preferences is not None else Preferences()

    @property
    def preferences(self) -> Preferences:
        return self._prefs

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
        state = self._prefs.effective_state(capability)

        # 2a) BLOCK: your permissions say never — auto-deny, no prompt, on record.
        if state == BLOCK:
            receipt = self._append_consumer_rejection(
                order, ticket, "USER_BLOCKED")
            return ConsumerOutcome(
                status="BLOCKED_BY_USER", reason_code="USER_BLOCKED",
                receipt=receipt, draft=None,
                confirmation_required=False, confirmation_asked=False,
            )

        # 2b) ASK: prompt; "allow always" upgrades the preference to ALLOW.
        asked = False
        if state == ASK:
            asked = True
            decision = self._approver.decide(order=order, capability=capability)
            if decision.allow and decision.remember:
                self._prefs.set(order.capability_id, ALLOW)
            if not decision.allow:
                receipt = self._append_consumer_rejection(
                    order, ticket, "USER_DENIED")
                return ConsumerOutcome(
                    status="DENIED_BY_USER", reason_code="USER_DENIED",
                    receipt=receipt, draft=None,
                    confirmation_required=True, confirmation_asked=True,
                )

        # 3) ALLOW (or ASK-allowed): execute exactly as the enterprise loop does.
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
            confirmation_required=(state == ASK),
            confirmation_asked=asked,
        )

    def _append_consumer_rejection(self, order, ticket, reason_code):
        """Record a consumer-side refusal (BLOCK or declined ASK) as a chained
        receipt. ticket_id is set because the cashier DID authorize by policy;
        the refusal happened at the personal-permission gate."""
        return self._loop.ledger.append(
            receipt_id="rcpt-" + uuid.uuid4().hex,
            order_id=order.order_id,
            ticket_id=ticket.ticket_id,
            status="REJECTED",
            reason_code=reason_code,
            result_digest=None,
            attestation=None,
            order_meta=order_meta_from_order(order),
        )
