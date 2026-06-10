import hashlib
from sentinel_slice.spine.canonical import canonical_bytes
from sentinel_slice.spine.types import Receipt

GENESIS_PREV_HASH = hashlib.sha256(b"GENESIS").hexdigest()


def receipt_content_dict(receipt: Receipt) -> dict:
    """Return the JSON-safe content dict of a Receipt: every field
    except this_hash and sig. This dict is what gets hashed into this_hash.

    v0.2 adds order_meta (who/what/when metadata, never content). Rows
    written before v0.2 lack the key in storage; this helper is only used to
    BUILD new receipts and to display them — verification recomputes from the
    stored row's own key set."""
    return {
        "receipt_id": receipt.receipt_id,
        "order_id": receipt.order_id,
        "ticket_id": receipt.ticket_id,
        "status": receipt.status,
        "reason_code": receipt.reason_code,
        "result_digest": receipt.result_digest,
        "attestation": receipt.attestation,
        "order_meta": receipt.order_meta,
        "prev_hash": receipt.prev_hash,
    }


def receipt_content_hash(content: dict) -> str:
    """sha256 hex of the canonical JSON of a receipt content dict."""
    return hashlib.sha256(canonical_bytes(content)).hexdigest()
