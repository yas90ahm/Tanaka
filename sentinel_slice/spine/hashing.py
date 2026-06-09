import hashlib
from sentinel_slice.spine.canonical import canonical_bytes
from sentinel_slice.spine.types import Receipt

GENESIS_PREV_HASH = hashlib.sha256(b"GENESIS").hexdigest()


def receipt_content_dict(receipt: Receipt) -> dict:
    """Return the JSON-safe content dict of a Receipt: every field
    except this_hash and sig. This dict is what gets hashed into this_hash."""
    return {
        "receipt_id": receipt.receipt_id,
        "order_id": receipt.order_id,
        "ticket_id": receipt.ticket_id,
        "status": receipt.status,
        "reason_code": receipt.reason_code,
        "result_digest": receipt.result_digest,
        "attestation": receipt.attestation,
        "prev_hash": receipt.prev_hash,
    }


def receipt_content_hash(content: dict) -> str:
    """sha256 hex of the canonical JSON of a receipt content dict."""
    return hashlib.sha256(canonical_bytes(content)).hexdigest()
