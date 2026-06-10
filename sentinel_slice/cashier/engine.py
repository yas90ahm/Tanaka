"""Cashier engine: the five-step validation pipeline, ticket minting, and
rejection-receipt append. This is the only Phase-3 module that calls
Ledger.append and signs tickets.

STRUCTURAL BLINDNESS (CLAUDE.md / Phase-3 contract §1): this module imports
nothing under sentinel_slice.kitchen and never reads, opens, globs, or stats
a fixture mailbox or fixture file. Scope is decided ONLY from the Order +
policy + capability. Allowed imports: stdlib, cryptography, and
sentinel_slice.{spine,ledger,menu,cashier} modules.

Pipeline order (contract §7c), short-circuit at first failure:
    1. nonce unseen        -> REPLAY
    2. capability on menu   -> OFF_MENU
    3. role permitted       -> ROLE_NOT_PERMITTED
    4. args within scope    -> OUT_OF_SCOPE
    5. rate limit           -> RATE_LIMITED  (FLAG A)
"""

import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from sentinel_slice.spine.canonical import canonical_bytes
from sentinel_slice.spine.types import Capability, Order, Receipt, Ticket
from sentinel_slice.ledger.receipts import Ledger
from sentinel_slice.cashier.policy import PolicySet
from sentinel_slice.cashier.store import CashierStore


@dataclass(frozen=True)
class TicketOutcome:
    accepted: bool          # always True for this class
    ticket: Ticket
    receipt: None           # always None — FULFILLED receipt is Phase 4


@dataclass(frozen=True)
class RejectionOutcome:
    accepted: bool          # always False for this class
    ticket: None            # always None
    reason_code: str        # one of the 5 codes in the pipeline table
    receipt: Receipt        # the REJECTED receipt already appended to the ledger


def ticket_signable_dict(ticket: Ticket) -> dict:
    """Return the exact 5-key signable dict for a Ticket (the bytes that were
    signed): {ticket_id, order_id, capability_id, scoped_args, issued_ts}.

    This field set is FROZEN: Phase 4's chef recomputes
    canonical_bytes(this dict) from these exact five keys to verify."""
    return {
        "ticket_id": ticket.ticket_id,
        "order_id": ticket.order_id,
        "capability_id": ticket.capability_id,
        "scoped_args": ticket.scoped_args,
        "issued_ts": ticket.issued_ts,
    }


def _append_rejection(ledger: Ledger, order: Order, reason_code: str) -> Receipt:
    """Append exactly one REJECTED receipt for `order` with `reason_code`.
    ticket_id / result_digest / attestation are all None so the chain still
    verifies."""
    return ledger.append(
        receipt_id="rcpt-" + uuid.uuid4().hex,
        order_id=order.order_id,
        ticket_id=None,
        status="REJECTED",
        reason_code=reason_code,
        result_digest=None,
        attestation=None,
    )


def process_order(
    order: Order,
    *,
    menu: dict[str, Capability],
    policy_set: PolicySet,
    store: CashierStore,
    ledger: Ledger,
    private_key: Ed25519PrivateKey,
    now=time.time,
    spawn=None,
) -> TicketOutcome | RejectionOutcome:
    """Run the five-step pipeline for `order`, short-circuiting at the first
    failure. On rejection, append a REJECTED receipt and return a
    RejectionOutcome. On acceptance, mint+sign a Ticket, record the rate
    timestamp, optionally call spawn(ticket), and return a TicketOutcome
    (no receipt appended in Phase 3)."""

    # --- Step 1: nonce unseen ---
    # nonce_seen() both checks AND registers in one atomic call. Therefore
    # EVERY order — including ones later rejected at steps 2-5 and accepted
    # ones — consumes its nonce here. A second order with the same nonce
    # always rejects REPLAY at this step regardless of the first outcome.
    if store.nonce_seen(order.nonce):
        receipt = _append_rejection(ledger, order, "REPLAY")
        return RejectionOutcome(
            accepted=False, ticket=None, reason_code="REPLAY", receipt=receipt
        )

    # --- Step 2: capability on menu ---
    capability = menu.get(order.capability_id)
    if capability is None:
        receipt = _append_rejection(ledger, order, "OFF_MENU")
        return RejectionOutcome(
            accepted=False, ticket=None, reason_code="OFF_MENU", receipt=receipt
        )

    # --- Step 3: role permitted by policy ---
    # Fetch the policy once and reuse it for step 5's rate_limit_per_hour.
    policy = policy_set.for_role(order.role)
    if policy is None or order.capability_id not in policy.allowed_capabilities:
        receipt = _append_rejection(ledger, order, "ROLE_NOT_PERMITTED")
        return RejectionOutcome(
            accepted=False,
            ticket=None,
            reason_code="ROLE_NOT_PERMITTED",
            receipt=receipt,
        )

    # --- Step 4: args within scope (structural, kitchen-blind) — FLAG B ---
    # FLAG B: scoped_args holds thread_id only; chef resolves the path (cashier is kitchen-blind)
    # thread_id is namespaced "<owner>/<local>"; owner is the substring before
    # the first "/". Scope passes iff owner == order.principal. Missing,
    # non-string, or "/"-less thread_id, or empty owner -> OUT_OF_SCOPE.
    # Never raise out of process_order.
    tid = order.args.get("thread_id") if isinstance(order.args, dict) else None
    if not isinstance(tid, str) or "/" not in tid:
        receipt = _append_rejection(ledger, order, "OUT_OF_SCOPE")
        return RejectionOutcome(
            accepted=False, ticket=None, reason_code="OUT_OF_SCOPE", receipt=receipt
        )
    owner = tid.split("/", 1)[0]
    if owner == "" or owner != order.principal:
        receipt = _append_rejection(ledger, order, "OUT_OF_SCOPE")
        return RejectionOutcome(
            accepted=False, ticket=None, reason_code="OUT_OF_SCOPE", receipt=receipt
        )

    # --- Step 5: rate limit ---
    # With limit L, the first L accepted orders pass; the (L+1)-th within the
    # window fails. rate_count() does NOT record; record_accept() runs only
    # on acceptance below, after this check passes.
    if store.rate_count(order.principal, order.capability_id) >= policy.rate_limit_per_hour:
        # FLAG A: RATE_LIMITED is beyond the SPEC reason_code enum
        receipt = _append_rejection(ledger, order, "RATE_LIMITED")
        return RejectionOutcome(
            accepted=False, ticket=None, reason_code="RATE_LIMITED", receipt=receipt
        )

    # --- ACCEPTANCE: all five steps passed ---
    ticket_id = "tkt-" + uuid.uuid4().hex
    issued_ts = datetime.fromtimestamp(now(), tz=timezone.utc).isoformat()
    # The narrowed dict: the validated thread_id string ONLY, no path, no
    # other keys (FLAG B).
    scoped_args = {"thread_id": tid}

    signable = {
        "ticket_id": ticket_id,
        "order_id": order.order_id,
        "capability_id": order.capability_id,
        "scoped_args": scoped_args,
        "issued_ts": issued_ts,
    }
    cashier_sig = private_key.sign(canonical_bytes(signable))  # raw Ed25519 bytes

    ticket = Ticket(
        ticket_id=ticket_id,
        order_id=order.order_id,
        capability_id=order.capability_id,
        scoped_args=scoped_args,
        issued_ts=issued_ts,
        cashier_sig=cashier_sig,
    )

    # Record the rate timestamp ONLY now, after the rate check passed.
    store.record_accept(order.principal, order.capability_id)

    # Phase-4 hook: call spawn exactly once, with the minted Ticket, only on
    # acceptance, only after the ticket is fully built and signed.
    if spawn is not None:
        spawn(ticket)

    # No receipt is appended on acceptance in Phase 3 — the FULFILLED receipt
    # is Phase 4's job.
    return TicketOutcome(accepted=True, ticket=ticket, receipt=None)
