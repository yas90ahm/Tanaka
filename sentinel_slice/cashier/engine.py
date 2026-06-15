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
    3b. capability paused   -> CAPABILITY_PAUSED  (v0.3 kill switch)
    4. args within scope    -> OUT_OF_SCOPE
    5. rate limit           -> RATE_LIMITED  (FLAG A)

v0.3 split: the five-step decision now lives in `evaluate_order`, a PURE
function (read-only over the store, no ledger, no signing, no spawn, no nonce
mutation) so the console can SIMULATE an order against a candidate policy with
zero side effects. `process_order` calls `evaluate_order` and then performs
the I/O (nonce consumption, rejection receipt, ticket mint+sign, spawn). The
observable behavior of `process_order` is byte-for-byte unchanged.
"""

import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from sentinel_slice.spine.canonical import canonical_bytes
from sentinel_slice.spine.types import (
    Capability,
    Order,
    Receipt,
    Ticket,
    order_meta_from_order,
)
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


@dataclass(frozen=True)
class Decision:
    """The PURE verdict of the validation pipeline — no I/O, no side effects.

    accepted=True  -> reason_code is None, scoped_args is the narrowed dict.
    accepted=False -> reason_code is the failing step's code, scoped_args None.

    This is exactly what the console's Simulate needs: the real pipeline's
    answer for an order, computed against any (candidate) policy set, with
    nothing written and no nonce consumed."""
    accepted: bool
    reason_code: str | None
    scoped_args: dict | None


def evaluate_order(
    order: Order,
    *,
    menu: dict[str, Capability],
    policy_set: PolicySet,
    store: CashierStore,
) -> Decision:
    """Run the five-step pipeline as a PURE function and return a Decision.

    READ-ONLY over `store`: it uses `nonce_is_spent` (a read, not the
    mutating `nonce_seen`) and `rate_count` (already a read). It never
    appends a receipt, mints a ticket, or calls spawn. Calling it any number
    of times changes no state — that is what makes Simulate honest: the
    console runs THIS function, the same one `process_order` runs."""

    # --- Step 1: nonce unseen (read-only) ---
    if store.nonce_is_spent(order.nonce):
        return Decision(accepted=False, reason_code="REPLAY", scoped_args=None)

    # --- Step 2: capability on menu ---
    capability = menu.get(order.capability_id)
    if capability is None:
        return Decision(accepted=False, reason_code="OFF_MENU", scoped_args=None)

    # --- Step 3: role permitted by policy ---
    policy = policy_set.for_role(order.role)
    if policy is None or order.capability_id not in policy.allowed_capabilities:
        return Decision(
            accepted=False, reason_code="ROLE_NOT_PERMITTED", scoped_args=None
        )

    # --- Step 3b: kill switch (v0.3) ---
    # The role MAY use this capability in normal times, but the operator has
    # paused it. Distinct from ROLE_NOT_PERMITTED so the audit trail shows a
    # deliberate pause, not a missing grant.
    if order.capability_id in policy.paused_capabilities:
        return Decision(
            accepted=False, reason_code="CAPABILITY_PAUSED", scoped_args=None
        )

    # --- Step 4: args within scope (structural, kitchen-blind) — FLAG B ---
    # The capability declares which arg holds its scoped resource
    # (`scoped_input`, default "thread_id"). That value is namespaced
    # "<owner>/<local>"; scope passes iff owner == principal AND local is a
    # single safe path component (no traversal). This is how DIFFERENT
    # capabilities (email threads, docs, records) reuse one scope rule.
    scoped_key = capability.scoped_input
    resource = order.args.get(scoped_key) if isinstance(order.args, dict) else None
    if not isinstance(resource, str) or "/" not in resource:
        return Decision(accepted=False, reason_code="OUT_OF_SCOPE", scoped_args=None)
    # Reject control characters anywhere in the resource id. They are never part
    # of a legitimate "<owner>/<local>" name, and a NUL byte is a path-truncation
    # primitive: rejecting it HERE, at the trust anchor, means it can never reach
    # a filesystem path op — rather than relying on the chef's runtime to raise.
    if any(ord(ch) < 0x20 or ord(ch) == 0x7f for ch in resource):
        return Decision(accepted=False, reason_code="OUT_OF_SCOPE", scoped_args=None)
    owner, local = resource.split("/", 1)
    local_unsafe = (
        local == "" or "/" in local or "\\" in local or local in (".", "..")
    )
    if owner == "" or owner != order.principal or local_unsafe:
        return Decision(accepted=False, reason_code="OUT_OF_SCOPE", scoped_args=None)

    # --- Step 5: rate limit (read-only count) ---
    if store.rate_count(order.principal, order.capability_id) >= policy.rate_limit_per_hour:
        return Decision(
            accepted=False, reason_code="RATE_LIMITED", scoped_args=None
        )

    # --- ACCEPT: narrowed dict = the validated scoped resource ONLY (FLAG B),
    # under the capability's own key so the chef knows what it received. ---
    return Decision(
        accepted=True, reason_code=None, scoped_args={scoped_key: resource}
    )


def ticket_signable_dict(ticket: Ticket) -> dict:
    """Return the exact 5-key signable dict for a Ticket (the bytes that were
    signed): {ticket_id, order_id, capability_id, scoped_args, issued_ts}.

    This field set is FROZEN: Phase 4's chef recomputes
    canonical_bytes(this dict) from these exact five keys to verify."""
    return {
        "ticket_id": ticket.ticket_id,
        "order_id": ticket.order_id,
        "capability_id": ticket.capability_id,
        "behavior": ticket.behavior,
        "behavior_config": ticket.behavior_config,
        "scoped_args": ticket.scoped_args,
        "issued_ts": ticket.issued_ts,
    }


def _append_rejection(ledger: Ledger, order: Order, reason_code: str) -> Receipt:
    """Append exactly one REJECTED receipt for `order` with `reason_code`.
    ticket_id / result_digest / attestation are all None so the chain still
    verifies. order_meta names who/what/when so the inspector can read the
    rejection without the order object."""
    return ledger.append(
        receipt_id="rcpt-" + uuid.uuid4().hex,
        order_id=order.order_id,
        ticket_id=None,
        status="REJECTED",
        reason_code=reason_code,
        result_digest=None,
        attestation=None,
        order_meta=order_meta_from_order(order),
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
    (no receipt appended in Phase 3).

    v0.3: the verdict comes from the pure `evaluate_order`; this function owns
    the side effects. The nonce is still consumed for EVERY order (accepted or
    rejected) exactly as before — `evaluate_order` reads it read-only, then we
    register it here so any future repeat is caught as REPLAY."""

    decision = evaluate_order(
        order, menu=menu, policy_set=policy_set, store=store
    )

    # Consume the nonce for every order that reaches the cashier (matches the
    # old single-call step-1 behavior: accepted and rejected orders alike burn
    # their nonce). evaluate_order already returned REPLAY if it was spent;
    # registering is idempotent.
    store.nonce_seen(order.nonce)

    if not decision.accepted:
        receipt = _append_rejection(ledger, order, decision.reason_code)
        return RejectionOutcome(
            accepted=False,
            ticket=None,
            reason_code=decision.reason_code,
            receipt=receipt,
        )

    # --- ACCEPTANCE: all steps passed ---
    ticket_id = "tkt-" + uuid.uuid4().hex
    issued_ts = datetime.fromtimestamp(now(), tz=timezone.utc).isoformat()
    scoped_args = decision.scoped_args
    # Resolve which code template (behavior) the chef must run AND its config
    # (e.g. a text template), from the menu descriptor, and SIGN both into the
    # ticket — so the standalone chef can run them without reading the catalog.
    capability = menu[order.capability_id]
    behavior = capability.resolved_behavior()
    behavior_config = capability.behavior_config

    signable = {
        "ticket_id": ticket_id,
        "order_id": order.order_id,
        "capability_id": order.capability_id,
        "behavior": behavior,
        "behavior_config": behavior_config,
        "scoped_args": scoped_args,
        "issued_ts": issued_ts,
    }
    cashier_sig = private_key.sign(canonical_bytes(signable))  # raw Ed25519 bytes

    ticket = Ticket(
        ticket_id=ticket_id,
        order_id=order.order_id,
        capability_id=order.capability_id,
        behavior=behavior,
        behavior_config=behavior_config,
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
