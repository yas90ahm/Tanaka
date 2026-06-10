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
