"""Gateway — the model-agnostic counter.

Any diner agent — any model, any vendor, any language — interacts with the
slice through ONE wire format: an Order as plain JSON in, an outcome as plain
JSON out. The agent process holds no credentials, imports no package code, and
never sees the kitchen. The gateway stands at the counter: it holds the
SentinelLoop (which holds the cashier key) on THIS side of the boundary, so
all the diner ever sends across is the order JSON below, and all it ever gets
back is the packaged result (draft pickup) plus the receipt (evidence).

Wire format (the diner protocol — all seven keys required, no extras):

    {
      "order_id":      "ord-<unique>",
      "principal":     "user.kenji",
      "role":          "account_manager",
      "capability_id": "cap.email.draft_reply.v1",
      "args":          {"thread_id": "user.kenji/t-001"},
      "nonce":         "nonce-<unique>",
      "ts":            "2026-06-10T12:00:00+00:00"
    }

This is NOT a network boundary in the slice (SPEC: FastAPI comes later). It is
the same in-process trust boundary the scripted diner already uses, exposed as
JSON so the diner can be any external agent process:

    echo <order-json> | python -m sentinel_slice.gateway --ledger my.db

One order on stdin, one outcome JSON on stdout. Exit 0 for any GOVERNED
outcome (acceptance AND rejection both produce chained receipts — a rejection
is not an error); exit 2 only for a malformed order that never acquired an
identity the chain could record.

KNOWN LIMIT (honest disclosure): a malformed order is refused WITHOUT a ledger
receipt — there is no trustworthy order_id to chain. A production gateway
would receipt malformed intake under a gateway-assigned identity.
"""

import argparse
import base64
import json
import sys

from sentinel_slice.spine.hashing import receipt_content_dict
from sentinel_slice.spine.types import Order, Receipt


# The exact key set of the diner protocol. A strict gateway rejects unknown
# keys: a typo'd field silently ignored is how scope bugs are born.
ORDER_KEYS = (
    "order_id",
    "principal",
    "role",
    "capability_id",
    "args",
    "nonce",
    "ts",
)
_STRING_KEYS = ("order_id", "principal", "role", "capability_id", "nonce", "ts")


class MalformedOrder(ValueError):
    """Order JSON that cannot be admitted to the pipeline at all."""


def parse_order(text: str | bytes) -> Order:
    """Parse one diner-protocol JSON object into an Order, strictly.

    Strict means: valid JSON, a JSON object, exactly the seven ORDER_KEYS (no
    missing, no unknown), the six identity keys are strings, args is an
    object. Raises MalformedOrder with a one-line reason on any violation.

    A leading UTF-8 BOM is tolerated (Windows shells prepend one when piping
    to a native process) — it is an encoding artifact, not part of the order."""
    try:
        if isinstance(text, bytes):
            text = text.decode("utf-8-sig")
        else:
            text = text.lstrip("﻿")
        obj = json.loads(text)
    except (json.JSONDecodeError, TypeError, UnicodeDecodeError):
        raise MalformedOrder("unparseable JSON")
    if not isinstance(obj, dict):
        raise MalformedOrder("order JSON is not an object")
    missing = [k for k in ORDER_KEYS if k not in obj]
    if missing:
        raise MalformedOrder("missing required key: {}".format(missing[0]))
    unknown = sorted(set(obj) - set(ORDER_KEYS))
    if unknown:
        raise MalformedOrder("unknown key: {}".format(unknown[0]))
    for key in _STRING_KEYS:
        if not isinstance(obj[key], str):
            raise MalformedOrder("key must be a string: {}".format(key))
    if not isinstance(obj["args"], dict):
        raise MalformedOrder("args must be an object")
    return Order(
        order_id=obj["order_id"],
        principal=obj["principal"],
        role=obj["role"],
        capability_id=obj["capability_id"],
        args=obj["args"],
        nonce=obj["nonce"],
        ts=obj["ts"],
    )


def receipt_to_dict(receipt: Receipt) -> dict:
    """The full receipt as a JSON-plain dict: the content keys (via the one
    spine helper — incl. v0.2's order_meta who/what/when metadata) plus
    this_hash and the base64 signature."""
    d = receipt_content_dict(receipt)
    d["this_hash"] = receipt.this_hash
    d["sig"] = base64.b64encode(receipt.sig).decode("ascii")
    return d


def outcome_to_dict(loop, order: Order, outcome) -> dict:
    """Map a loop.place() outcome to the diner-facing outcome JSON.

    Acceptance is NOT fulfillment: an accepted order whose chef failed comes
    back status REJECTED / EXECUTION_FAILED with no draft. The draft (content
    path) rides back base64 alongside the receipt (evidence path); content
    still never touches the ledger."""
    if not outcome.accepted:
        return {
            "order_id": order.order_id,
            "accepted": False,
            "status": "REJECTED",
            "reason_code": outcome.reason_code,
            "ticket_id": None,
            "receipt": receipt_to_dict(outcome.receipt),
            "window_dir": None,
            "draft_b64": None,
        }
    chef = loop.last_chef
    receipt = chef.receipt
    fulfilled = chef.returncode == 0 and chef.draft_bytes is not None
    return {
        "order_id": order.order_id,
        "accepted": True,
        "status": receipt.status,
        "reason_code": receipt.reason_code,
        "ticket_id": outcome.ticket.ticket_id,
        "receipt": receipt_to_dict(receipt),
        "window_dir": chef.out_dir if fulfilled else None,
        "draft_b64": (
            base64.b64encode(chef.draft_bytes).decode("ascii") if fulfilled else None
        ),
    }


def place_order_json(loop, text: str | bytes) -> dict:
    """The whole counter in one call: order JSON in, outcome dict out.

    A malformed order returns {"accepted": false, "error": "MALFORMED_ORDER",
    "detail": ...} and appends NOTHING to the ledger (see module docstring)."""
    try:
        order = parse_order(text)
    except MalformedOrder as exc:
        return {"accepted": False, "error": "MALFORMED_ORDER", "detail": str(exc)}
    outcome = loop.place(order)
    return outcome_to_dict(loop, order, outcome)


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="sentinel-gateway",
        description="Read one diner-protocol order JSON on stdin, place it, "
        "print the outcome JSON on stdout.",
    )
    parser.add_argument("--ledger", default="ledger.db", help="ledger db path")
    parser.add_argument(
        "--keys", default=None, help="dir holding the cashier PEM pair"
    )
    parser.add_argument(
        "--window", default=None, help="serving-window root for draft output"
    )
    args = parser.parse_args(argv)

    # Import here so `--help` works even before keys exist.
    from sentinel_slice.loop import build_default

    loop = build_default(args.ledger, window_root=args.window, keys_dir=args.keys)
    # Read stdin as BYTES: the wire format is UTF-8 JSON regardless of the
    # host's locale codepage (text-mode stdin would decode with cp1252 on
    # Windows and mangle the shell's BOM). parse_order decodes utf-8-sig.
    result = place_order_json(loop, sys.stdin.buffer.read())
    print(json.dumps(result, indent=2, sort_keys=True))
    return 2 if result.get("error") == "MALFORMED_ORDER" else 0


def cli() -> None:
    sys.exit(main())


if __name__ == "__main__":
    sys.exit(main())
