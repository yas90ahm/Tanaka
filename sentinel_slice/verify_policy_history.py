# SPDX-License-Identifier: Apache-2.0
# Copyright 2026 Yasir Qureshi
"""Standalone policy-history verifier.

STANDALONE, exactly like verify_ledger.py: it imports nothing from the
`sentinel_slice` package and re-implements canonical JSON, the content rule,
the genesis constant, and sha256 hashing locally. The question "who changed
which policy when, and is that record trustworthy?" gets the same
cryptographic answer as "what did the agents do?" — proven from the policy db
+ public key alone.

Content rule (matches policy_store): this_hash binds every stored key except
this_hash and sig; the 7 core keys must be present. Genesis prev_hash is
sha256(b"POLICY-GENESIS") — a different domain from the ledger's
sha256(b"GENESIS"), so rows cannot be replayed between chains.

CLI:  python verify_policy_history.py <policy.db> <pubkey.pem>
First broken row -> "FAIL seq=<N> reason=<reason>", exit 1.
All rows verify   -> "OK verified=<count>", exit 0.
Usage error       -> one-line "usage: ..." message, exit 2.
"""

import sys
import json
import sqlite3
import hashlib
import base64

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.exceptions import InvalidSignature


POLICY_GENESIS_PREV_HASH = hashlib.sha256(b"POLICY-GENESIS").hexdigest()

CONTENT_KEYS = (
    "version_id",
    "policies",
    "author",
    "reason",
    "status",
    "approved_by",
    "prev_hash",
)
EXCLUDED_KEYS = ("this_hash", "sig")


def canonical_bytes(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


def content_dict_from_row(parsed):
    for key in CONTENT_KEYS:
        if key not in parsed:
            raise KeyError(key)
    for key in EXCLUDED_KEYS:
        if key not in parsed:
            raise KeyError(key)
    return {k: v for k, v in parsed.items() if k not in EXCLUDED_KEYS}


def recompute_hash(parsed):
    return hashlib.sha256(canonical_bytes(content_dict_from_row(parsed))).hexdigest()


def main(argv):
    if len(argv) != 3:
        print("usage: verify_policy_history.py <policy.db> <pubkey.pem>")
        return 2

    db_path = argv[1]
    pem_path = argv[2]

    try:
        with open(pem_path, "rb") as fh:
            public_key = serialization.load_pem_public_key(fh.read())
    except (OSError, ValueError):
        print("usage: cannot read an Ed25519 public key from {}".format(pem_path))
        return 2
    if not isinstance(public_key, ed25519.Ed25519PublicKey):
        print("usage: public key is not an Ed25519 public key")
        return 2

    try:
        conn = sqlite3.connect(db_path)
    except sqlite3.OperationalError as exc:
        print("usage: cannot open policy db {}: {}".format(db_path, exc))
        return 2
    try:
        cur = conn.cursor()
        cur.execute("SELECT seq, json FROM policy_versions ORDER BY seq ASC")
        rows = cur.fetchall()
    except sqlite3.OperationalError as exc:
        print("usage: cannot read policy_versions from {}: {}".format(db_path, exc))
        return 2
    finally:
        conn.close()

    expected_prev = POLICY_GENESIS_PREV_HASH
    count = 0

    for seq, row_json in rows:
        try:
            parsed = json.loads(row_json)
        except (ValueError, TypeError):
            print("FAIL seq={} reason=json_parse".format(seq))
            return 1
        try:
            recomputed = recompute_hash(parsed)
        except (KeyError, TypeError):
            print("FAIL seq={} reason=json_parse".format(seq))
            return 1
        if recomputed != parsed.get("this_hash"):
            print("FAIL seq={} reason=hash_mismatch".format(seq))
            return 1
        if parsed.get("prev_hash") != expected_prev:
            print("FAIL seq={} reason=prev_hash_mismatch".format(seq))
            return 1
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
        expected_prev = parsed["this_hash"]
        count += 1

    print("OK verified={}".format(count))
    return 0


def cli():
    """Console-script entry point. Still standalone: no package imports."""
    sys.exit(main(sys.argv))


if __name__ == "__main__":
    sys.exit(main(sys.argv))
