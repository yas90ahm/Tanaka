# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Yasir Qureshi
"""Policy store — versioned, signed, append-only policy history.

The thing that governs the agents must be governed the same way the agents
are (CONSOLE_SPEC non-negotiable #2, Essay 6). A bare JSON file the form
overwrites has no audit trail and no rollback. This store gives policy changes
the SAME properties the receipt ledger gives agent actions: every published
version is hash-chained and Ed25519-signed, the chain is append-only by
construction (the only SQL issued is CREATE TABLE, INSERT, and SELECT -
nothing that mutates or removes a stored row), and a standalone verifier
(`verify_policy_history.py`) can prove the history intact from the db + public
key alone.

Genesis for the policy chain is sha256(b"POLICY-GENESIS") — a DIFFERENT domain
from the ledger's sha256(b"GENESIS"), so a row can never be replayed from one
chain into the other.

A stored version's content (the bytes the engine consumes) lives under the
`policies` key, in the SAME shape `cashier/policy.py` loads and the authoring
form emits — so `materialize_active` writes the active version straight to the
policies dir and the enforcement path is unchanged (the round-trip thesis).

Version status (`active` | `pending`) and `approved_by` are recorded but the
store does not interpret them — the second-admin workflow lives in the console
API (Phase 2). The store's only jobs: append a signed version, read the
history, report the active (latest `active`) version, and materialize it.

This module imports only stdlib + cryptography + spine.canonical. No kitchen,
no engine.
"""

import base64
import hashlib
import json
import sqlite3
import uuid

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from sentinel_slice.spine.canonical import canonical_bytes

POLICY_GENESIS_PREV_HASH = hashlib.sha256(b"POLICY-GENESIS").hexdigest()

# The content keys bound by this_hash (everything stored except this_hash/sig).
# Order is irrelevant after canonicalization; the SET is load-bearing and is
# re-declared identically in verify_policy_history.py.
CONTENT_KEYS = (
    "version_id",
    "policies",
    "author",
    "reason",
    "status",
    "approved_by",
    "prev_hash",
)

_CREATE_TABLE_SQL = (
    "CREATE TABLE IF NOT EXISTS policy_versions ("
    "seq INTEGER PRIMARY KEY, "
    "json TEXT NOT NULL"
    ")"
)


def policy_content_hash(content: dict) -> str:
    """sha256 hex of canonical JSON of a policy-version content dict."""
    return hashlib.sha256(canonical_bytes(content)).hexdigest()


class PolicyStore:
    """Append-only hash chain of signed policy versions over sqlite3."""

    def __init__(self, db_path: str, private_key: Ed25519PrivateKey) -> None:
        self._private_key = private_key
        # check_same_thread=False: the console server is constructed in one
        # thread and serves requests in another. Safe because the server is
        # single-threaded (see console/server.make_server) — appends are never
        # concurrent, they are serialized one request at a time.
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.execute(_CREATE_TABLE_SQL)
        self._conn.commit()

    def _head_hash(self) -> str:
        cur = self._conn.execute(
            "SELECT json FROM policy_versions ORDER BY seq DESC LIMIT 1"
        )
        row = cur.fetchone()
        if row is None:
            return POLICY_GENESIS_PREV_HASH
        return json.loads(row[0])["this_hash"]

    def append_version(
        self,
        *,
        policies: list,
        author: str,
        reason: str,
        status: str = "active",
        approved_by: str | None = None,
    ) -> dict:
        """Append one signed policy version. `policies` is the list that goes
        under the file's "policies" key (the engine's input shape). Returns
        the stored row dict (incl. seq, this_hash, sig_b64)."""
        if status not in ("active", "pending"):
            raise ValueError("status must be 'active' or 'pending'")
        prev_hash = self._head_hash()
        version_id = "pv-" + uuid.uuid4().hex

        content = {
            "version_id": version_id,
            "policies": policies,
            "author": author,
            "reason": reason,
            "status": status,
            "approved_by": approved_by,
            "prev_hash": prev_hash,
        }
        this_hash = policy_content_hash(content)
        raw_sig = self._private_key.sign(this_hash.encode("utf-8"))
        sig_b64 = base64.b64encode(raw_sig).decode("ascii")

        row = dict(content, this_hash=this_hash, sig=sig_b64)
        stored_json = canonical_bytes(row).decode("utf-8")

        cur = self._conn.execute(
            "INSERT INTO policy_versions (json) VALUES (?)", (stored_json,)
        )
        self._conn.commit()
        row["seq"] = cur.lastrowid
        return row

    def read_all(self) -> list[dict]:
        """Every version (parsed row dict, with seq) in seq order."""
        cur = self._conn.execute(
            "SELECT seq, json FROM policy_versions ORDER BY seq ASC"
        )
        out = []
        for seq, raw in cur.fetchall():
            row = json.loads(raw)
            row["seq"] = seq
            out.append(row)
        return out

    def active_version(self) -> dict | None:
        """The most recent version whose status == 'active', or None if the
        store holds no active version yet (e.g. only a pending proposal)."""
        for row in reversed(self.read_all()):
            if row["status"] == "active":
                return row
        return None

    def materialize_active(self, policy_file_path: str) -> dict | None:
        """Write the active version's content to `policy_file_path` in the
        exact file shape the engine loads ({"policies": [...]}), so the
        enforcement path consumes it unchanged. Returns the active version, or
        None if there is none (file left untouched)."""
        active = self.active_version()
        if active is None:
            return None
        file_obj = {"policies": active["policies"]}
        # indent=2 + trailing newline mirrors the authoring form's emit format.
        data = (json.dumps(file_obj, indent=2) + "\n").encode("utf-8")
        with open(policy_file_path, "wb") as fh:
            fh.write(data)
        return active
