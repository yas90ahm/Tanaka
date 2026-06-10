from dataclasses import dataclass


@dataclass(frozen=True)
class Capability:
    id: str
    name: str
    inputs: dict[str, str]
    outputs: dict[str, str]
    side_effects: str
    scope: str
    risk_class: str
    # v0.3: advisory metadata the Tanaka console reads to coach the operator
    # and gate sensitive changes. These are INPUTS TO THE CONSOLE, not new
    # enforcement — the cashier pipeline is unchanged. Optional in the JSON;
    # absent -> the conservative defaults below.
    description: str = ""
    recommended_max_rate: int | None = None   # console warns above this
    requires_second_admin: bool = False        # publish needs a 2nd approver
    # v0.4 consumer mode: high-stakes actions need human-in-the-loop
    # confirmation at EXECUTION time (Essay 5's "additional friction"). The
    # cashier still authorizes by policy; this adds a per-action allow/deny.
    requires_user_confirmation: bool = False
    # v0.5 pluggable capabilities: which args key holds the namespaced
    # "<owner>/<local>" resource the cashier scope-checks and the chef reads.
    # Defaults to "thread_id" so existing email capabilities are unchanged; a
    # docs capability can declare "doc_id", a records one "record_id", etc.
    scoped_input: str = "thread_id"


@dataclass(frozen=True)
class Order:
    order_id: str
    principal: str
    role: str
    capability_id: str
    args: dict
    nonce: str
    ts: str


@dataclass(frozen=True)
class Ticket:
    ticket_id: str
    order_id: str
    capability_id: str
    scoped_args: dict
    issued_ts: str
    cashier_sig: bytes


@dataclass(frozen=True)
class Receipt:
    receipt_id: str
    order_id: str
    ticket_id: str | None
    status: str
    reason_code: str | None
    result_digest: str | None
    attestation: dict | None
    prev_hash: str
    this_hash: str
    sig: bytes
    # v0.2: the receipt names everyone involved (who/what/when — the diner,
    # the role, the capability, the order timestamp). METADATA ONLY: never
    # args, never content. None on rows written before v0.2.
    order_meta: dict | None = None


def order_meta_from_order(order: Order) -> dict:
    """The FROZEN 4-key metadata dict a receipt records about its Order:
    who (principal, role), what (capability_id), when (the order's ts).

    Deliberately excludes `args`: args are caller-supplied and could carry
    content in future capabilities; receipts carry metadata only."""
    return {
        "principal": order.principal,
        "role": order.role,
        "capability_id": order.capability_id,
        "ts": order.ts,
    }
