"""Standalone ledger verifier.

This module is intentionally STANDALONE: it imports nothing from the
`sentinel_slice` package. It re-implements canonical JSON, the 8-key
content-dict shape, the genesis constant, and the sha256 hashing locally so
that the ledger can be verified with only `ledger.db` + the public key PEM and
no access to the package source.

CLI:  python verify_ledger.py <ledger.db> <pubkey.pem>

Walks rows in `seq` order. On the first failing row it prints

    FAIL seq=<N> reason=<reason>

to stdout and exits 1. If every row verifies it prints

    OK verified=<count>

to stdout and exits 0.
"""

import sys
import json
import sqlite3
import hashlib
import base64

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.exceptions import InvalidSignature


# Genesis prev_hash. Computed locally (NOT imported) to prove zero coupling.
# This MUST equal sha256(b"GENESIS").hexdigest() ==
# "901131d838b17aac0f7885b81e03cbdc9f5157a00343d30ab22083685ed1416a".
GENESIS_PREV_HASH = hashlib.sha256(b"GENESIS").hexdigest()

# The 8 content keys, in the binding order. Order is irrelevant after
# canonicalization (sort_keys=True), but the key SET is load-bearing.
CONTENT_KEYS = (
    "receipt_id",
    "order_id",
    "ticket_id",
    "status",
    "reason_code",
    "result_digest",
    "attestation",
    "prev_hash",
)


def canonical_bytes(obj):
    """Byte-identical to spine.canonical.canonical_bytes."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def content_dict_from_row(parsed):
    """Build the 8-key content dict by selecting those keys from a parsed row."""
    return {key: parsed[key] for key in CONTENT_KEYS}


def recompute_hash(parsed):
    """sha256 hex of the canonical JSON of the 8-key content dict."""
    return hashlib.sha256(canonical_bytes(content_dict_from_row(parsed))).hexdigest()


def main(argv):
    if len(argv) != 3:
        # Usage error -> nonzero exit, but this is not a row failure.
        print("usage: verify_ledger.py <ledger.db> <pubkey.pem>")
        return 2

    db_path = argv[1]
    pem_path = argv[2]

    try:
        with open(pem_path, "rb") as fh:
            pem_bytes = fh.read()
        public_key = serialization.load_pem_public_key(pem_bytes)
    except (OSError, ValueError):
        # Missing file, non-PEM, or a private-key PEM -> a usage error, NOT a
        # ledger-integrity failure. Exit 2, never a traceback.
        print("usage: cannot read an Ed25519 public key from {}".format(pem_path))
        return 2
    if not isinstance(public_key, ed25519.Ed25519PublicKey):
        print("usage: public key is not an Ed25519 public key")
        return 2

    try:
        conn = sqlite3.connect(db_path)
    except sqlite3.OperationalError as exc:
        print("usage: cannot open ledger db {}: {}".format(db_path, exc))
        return 2
    try:
        cur = conn.cursor()
        cur.execute("SELECT seq, json FROM receipts ORDER BY seq ASC")
        rows = cur.fetchall()
    except sqlite3.OperationalError as exc:
        # Wrong/corrupt sqlite file or one lacking a `receipts` table -> usage
        # error with a one-line message, never an uncaught traceback.
        print("usage: cannot read receipts table from {}: {}".format(db_path, exc))
        return 2
    finally:
        conn.close()

    expected_prev = GENESIS_PREV_HASH
    count = 0

    for seq, row_json in rows:
        # 1. Parse.
        try:
            parsed = json.loads(row_json)
        except (ValueError, TypeError):
            print("FAIL seq={} reason=json_parse".format(seq))
            return 1

        # Guard: the recompute step requires all 8 content keys + this_hash + sig.
        try:
            recomputed = recompute_hash(parsed)
        except (KeyError, TypeError):
            print("FAIL seq={} reason=json_parse".format(seq))
            return 1

        # 2. Recompute hash and compare to the stored this_hash.
        if recomputed != parsed.get("this_hash"):
            print("FAIL seq={} reason=hash_mismatch".format(seq))
            return 1

        # 3. Chain link.
        if parsed.get("prev_hash") != expected_prev:
            print("FAIL seq={} reason=prev_hash_mismatch".format(seq))
            return 1

        # 4. Signature over the recomputed this_hash hex string's UTF-8 bytes.
        try:
            raw_sig = base64.b64decode(parsed["sig"])
        except (KeyError, ValueError, TypeError):
            print("FAIL seq={} reason=bad_signature".format(seq))
            return 1
        try:
            public_key.verify(raw_sig, recomputed.encode("utf-8"))
        except InvalidSignature:
            print("FAIL seq={} reason=bad_signature".format(seq))
            return 1

        # 5. Advance the chain.
        expected_prev = parsed["this_hash"]
        count += 1

    print("OK verified={}".format(count))
    return 0


def cli():
    """Console-script entry point. Still standalone: no package imports."""
    sys.exit(main(sys.argv))


if __name__ == "__main__":
    sys.exit(main(sys.argv))
