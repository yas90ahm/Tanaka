"""Append-only, hash-chained, Ed25519-signed receipt store over sqlite3.

This module is INSERT-only by construction (CLAUDE.md non-negotiable #3):
the only SQL it issues is `CREATE TABLE IF NOT EXISTS`, `INSERT`, and
`SELECT`. There is no method, statement, comment, or string anywhere in
this file that mutates or removes a stored row.

Wire/crypto agreement with the standalone verifier is fixed by the Phase-2
contract; see the spine helpers re-used below for the canonical-JSON and
content-hash definitions.
"""

import base64
import json
import sqlite3

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from sentinel_slice.spine.canonical import canonical_bytes
from sentinel_slice.spine.hashing import GENESIS_PREV_HASH, receipt_content_hash
from sentinel_slice.spine.types import Receipt


_CREATE_TABLE_SQL = (
    "CREATE TABLE IF NOT EXISTS receipts ("
    "seq INTEGER PRIMARY KEY, "
    "json TEXT NOT NULL"
    ")"
)


class Ledger:
    """An append-only hash chain of signed receipts backed by sqlite3."""

    def __init__(self, db_path: str, private_key: Ed25519PrivateKey) -> None:
        self._private_key = private_key
        self._conn = sqlite3.connect(db_path)
        self._conn.execute(_CREATE_TABLE_SQL)
        self._conn.commit()

    def _head_hash(self) -> str:
        """Return the this_hash of the current chain head, or the genesis
        prev_hash if the ledger is empty."""
        cur = self._conn.execute(
            "SELECT json FROM receipts ORDER BY seq DESC LIMIT 1"
        )
        row = cur.fetchone()
        if row is None:
            return GENESIS_PREV_HASH
        return json.loads(row[0])["this_hash"]

    def append(
        self,
        *,
        receipt_id: str,
        order_id: str,
        ticket_id: str | None,
        status: str,
        reason_code: str | None,
        result_digest: str | None,
        attestation: dict | None,
        order_meta: dict | None = None,
        containment: str | None = None,
    ) -> Receipt:
        prev_hash = self._head_hash()

        content_dict = {
            "receipt_id": receipt_id,
            "order_id": order_id,
            "ticket_id": ticket_id,
            "status": status,
            "reason_code": reason_code,
            "result_digest": result_digest,
            "attestation": attestation,
            "order_meta": order_meta,
            "containment": containment,
            "prev_hash": prev_hash,
        }
        this_hash = receipt_content_hash(content_dict)

        raw_sig = self._private_key.sign(this_hash.encode("utf-8"))
        sig_b64 = base64.b64encode(raw_sig).decode("ascii")

        row_dict = {
            "receipt_id": receipt_id,
            "order_id": order_id,
            "ticket_id": ticket_id,
            "status": status,
            "reason_code": reason_code,
            "result_digest": result_digest,
            "attestation": attestation,
            "order_meta": order_meta,
            "containment": containment,
            "prev_hash": prev_hash,
            "this_hash": this_hash,
            "sig": sig_b64,
        }
        stored_json = canonical_bytes(row_dict).decode("utf-8")

        self._conn.execute(
            "INSERT INTO receipts (json) VALUES (?)", (stored_json,)
        )
        self._conn.commit()

        return Receipt(
            receipt_id=receipt_id,
            order_id=order_id,
            ticket_id=ticket_id,
            status=status,
            reason_code=reason_code,
            result_digest=result_digest,
            attestation=attestation,
            prev_hash=prev_hash,
            this_hash=this_hash,
            sig=raw_sig,
            order_meta=order_meta,
            containment=containment,
        )

    def read_all_raw(self) -> list[tuple[int, dict]]:
        """Every (seq, parsed stored row) in seq order — the raw evidence the
        inspector's chain check consumes. SELECT only, like everything here."""
        cur = self._conn.execute(
            "SELECT seq, json FROM receipts ORDER BY seq ASC"
        )
        return [(seq, json.loads(row_json)) for seq, row_json in cur.fetchall()]

    def read_all(self) -> list[Receipt]:
        cur = self._conn.execute(
            "SELECT seq, json FROM receipts ORDER BY seq ASC"
        )
        receipts: list[Receipt] = []
        for _seq, row_json in cur.fetchall():
            row = json.loads(row_json)
            receipts.append(
                Receipt(
                    receipt_id=row["receipt_id"],
                    order_id=row["order_id"],
                    ticket_id=row["ticket_id"],
                    status=row["status"],
                    reason_code=row["reason_code"],
                    result_digest=row["result_digest"],
                    attestation=row["attestation"],
                    prev_hash=row["prev_hash"],
                    this_hash=row["this_hash"],
                    sig=base64.b64decode(row["sig"]),
                    # Rows written before v0.2 / v0.12 lack the keys -> None.
                    order_meta=row.get("order_meta"),
                    containment=row.get("containment"),
                )
            )
        return receipts
