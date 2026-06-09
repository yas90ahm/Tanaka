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
