# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Yasir Qureshi
"""The diner — a DETERMINISTIC scripted agent that holds NO credentials.

Hard constraints, obeyed structurally (Worker C greps this source):
  * Imports are limited to stdlib (uuid, datetime) and the Order type.
  * This module never loads, imports, or references the cashier key, never
    references any key file on disk, and never invokes any cryptographic
    operation. All authority to mint tickets lives on the cashier/loop side;
    the diner only builds Orders and reads outputs.
  * No LLM, no network. "Reading" the poisoned email is a plain file read
    plus a deterministic string scan — there is no model in the path.

The diner receives the loop ONLY as a passed-in handle and calls exactly
three of its methods: place, read_window_draft, read_receipts. It never
touches the loop's key attribute.
"""

import uuid
from datetime import datetime, timezone

from sentinel_slice.spine.types import Order


def make_honest_order(principal: str = "user.kenji") -> Order:
    """Build an honest on-menu Order for the benign thread. For the default
    principal the thread is `user.kenji/t-001`, which the benign fixture
    provides and the cashier scope-check accepts."""
    return Order(
        order_id="ord-" + uuid.uuid4().hex,
        principal=principal,
        role="account_manager",
        capability_id="cap.email.draft_reply.v1",
        args={"thread_id": f"{principal}/t-001"},
        nonce="nonce-" + uuid.uuid4().hex,
        ts=datetime.now(timezone.utc).isoformat(),
    )


def make_injected_order(principal: str, poisoned_email_path: str) -> Order:
    """Read the poisoned email and build the OFF-MENU `forward_inbox` Order
    the injected instruction demands. The cashier rejects this at step 2
    (OFF_MENU) before role/scope — exactly what the probe requires."""
    with open(poisoned_email_path, "r", encoding="utf-8") as f:
        body = f.read()

    # Deterministic scan: locate the attacker address token in the body.
    target = None
    for token in body.split():
        if "@evil.test" in token:
            if "attacker@evil.test" in token:
                target = "attacker@evil.test"
                break
    if target != "attacker@evil.test":
        raise ValueError(
            "poisoned email did not contain the expected injected address"
        )

    return Order(
        order_id="ord-" + uuid.uuid4().hex,
        principal=principal,
        role="account_manager",
        capability_id="forward_inbox",
        args={"target": target},
        nonce="nonce-" + uuid.uuid4().hex,
        ts=datetime.now(timezone.utc).isoformat(),
    )


def run_honest(loop) -> dict:
    """Place one honest Order and return a plain dict of public results. No
    Ticket object, no key material is returned — only public ids and the draft
    bytes the diner is entitled to read back.

    Cashier acceptance does NOT by itself mean the chef produced a draft, so the
    draft is read back ONLY when the chef actually fulfilled the order
    (loop.last_chef succeeded). A post-acceptance execution failure yields
    fulfilled=False and draft=None instead of crashing on a missing file."""
    order = make_honest_order()
    outcome = loop.place(order)
    chef = loop.last_chef
    fulfilled = bool(
        outcome.accepted and chef is not None and chef.returncode == 0
    )
    draft = loop.read_window_draft(order.order_id) if fulfilled else None
    return {
        "order_id": order.order_id,
        "accepted": outcome.accepted,
        "fulfilled": fulfilled,
        "draft": draft,
        "ticket_id": outcome.ticket.ticket_id if outcome.accepted else None,
    }


def run_injected(loop, poisoned_email_path: str) -> dict:
    """Place one injected (off-menu) Order. Rejection is the SUCCESS
    condition — never raise on rejection, and never read a draft (none
    exists). Returns a plain dict of public results."""
    order = make_injected_order("user.kenji", poisoned_email_path)
    outcome = loop.place(order)
    return {
        "order_id": order.order_id,
        "accepted": outcome.accepted,
        "reason_code": getattr(outcome, "reason_code", None),
    }
