"""Chef subprocess entrypoint — STANDALONE.

This module is intentionally STANDALONE: it imports nothing from the
`sentinel_slice` package (same rule as `verify_ledger.py`). It re-implements
`canonical_bytes` inline so it can verify the cashier's Ed25519 signature using
only stdlib + cryptography.

SECURITY ORDERING (critical): the cashier signature on stdin is verified BEFORE
any side effect. On a bad/forged signature the chef exits nonzero having touched
NOTHING: it does not read the fixture, does not create the out_dir, does not
write a draft.

Import closure must contain NONE of socket/http/urllib/requests (AT07). We use
`os.path` (network-free) rather than pathlib for the traversal guard.

CLI / argv (see contract §1a):
    chef_main.py <pubkey_pem_path> <fixtures_root> <out_dir>

stdin: a single JSON object — the ticket (see contract §1b).

Exit codes (FROZEN, contract §1d):
    0  success: draft written to <out_dir>/draft.txt
    2  usage error (argc, unparseable/invalid stdin JSON, missing pubkey file)
    3  signature verification failed (bad/forged/wrong-key sig)
    4  scope/path-traversal violation OR fixture file missing
"""

import sys
import os
import json
import base64

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519
from cryptography.exceptions import InvalidSignature


def canonical_bytes(obj) -> bytes:
    """Byte-identical to spine.canonical.canonical_bytes (re-implemented inline)."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode("utf-8")


REQUIRED_KEYS = (
    "ticket_id",
    "order_id",
    "capability_id",
    "scoped_args",
    "issued_ts",
    "cashier_sig",
)


def main(argv) -> int:
    # 1. argc — exactly 3 args after argv[0].
    if len(argv) != 4:
        print("usage: chef_main.py <pubkey_pem> <fixtures_root> <out_dir>", file=sys.stderr)
        return 2

    pubkey_path = argv[1]
    fixtures_root_arg = argv[2]
    out_dir = argv[3]

    # 2. Read + parse stdin (no fixture read, no out_dir creation yet).
    raw_stdin = sys.stdin.read()
    if not raw_stdin:
        print("empty stdin", file=sys.stderr)
        return 2
    try:
        t = json.loads(raw_stdin)
    except json.JSONDecodeError:
        print("unparseable stdin json", file=sys.stderr)
        return 2

    if not isinstance(t, dict):
        print("stdin json is not an object", file=sys.stderr)
        return 2
    for key in REQUIRED_KEYS:
        if key not in t:
            print("missing required key: {}".format(key), file=sys.stderr)
            return 2
    for key in ("ticket_id", "order_id", "capability_id", "issued_ts", "cashier_sig"):
        if not isinstance(t[key], str):
            print("required key not a string: {}".format(key), file=sys.stderr)
            return 2
    scoped_args = t["scoped_args"]
    if not isinstance(scoped_args, dict):
        print("scoped_args is not an object", file=sys.stderr)
        return 2
    if not isinstance(scoped_args.get("thread_id"), str):
        print("scoped_args.thread_id missing or not a string", file=sys.stderr)
        return 2

    # 3. Load pubkey + VERIFY SIGNATURE. This is the security gate; it MUST
    #    precede every side effect (no fixture read, no out_dir creation above).
    if not os.path.isfile(pubkey_path):
        print("pubkey file not found", file=sys.stderr)
        return 2
    with open(pubkey_path, "rb") as fh:
        pem_bytes = fh.read()
    public_key = serialization.load_pem_public_key(pem_bytes)

    signable = {
        "ticket_id": t["ticket_id"],
        "order_id": t["order_id"],
        "capability_id": t["capability_id"],
        "scoped_args": t["scoped_args"],
        "issued_ts": t["issued_ts"],
    }
    try:
        sig = base64.b64decode(t["cashier_sig"], validate=True)
    except (ValueError, TypeError):
        # Malformed base64 signature is a signature failure.
        print("signature verification failed", file=sys.stderr)
        return 3
    try:
        public_key.verify(sig, canonical_bytes(signable))
    except InvalidSignature:
        print("signature verification failed", file=sys.stderr)
        return 3
    # NOTHING has been read from the kitchen and out_dir does NOT exist yet.

    # 4. Resolve thread_id -> fixture path, with traversal guard.
    thread_id = scoped_args["thread_id"]
    if "/" not in thread_id:
        print("path traversal rejected", file=sys.stderr)
        return 4
    owner, local = thread_id.split("/", 1)
    if owner == "" or local == "":
        print("path traversal rejected", file=sys.stderr)
        return 4

    fixtures_root = os.path.realpath(fixtures_root_arg)
    candidate = os.path.realpath(os.path.join(fixtures_root, owner, local + ".txt"))
    try:
        common = os.path.commonpath([fixtures_root, candidate])
    except ValueError:
        # Different drive on Windows, etc.
        print("path traversal rejected", file=sys.stderr)
        return 4
    if common != fixtures_root or candidate == fixtures_root:
        print("path traversal rejected", file=sys.stderr)
        return 4

    # 5. Read ONLY that file (the only read; no network, no other reads).
    if not os.path.isfile(candidate):
        print("fixture not found", file=sys.stderr)
        return 4
    with open(candidate, "r", encoding="utf-8") as fh:
        email_text = fh.read()

    # 6. Generate the DETERMINISTIC draft (FROZEN transform).
    subject = "(no subject)"
    for line in email_text.splitlines():
        if line.startswith("Subject:"):
            subject = line[len("Subject:"):].strip()
            break

    draft_text = (
        "Re: {}\n\n"
        "Thank you for your message. A draft reply has been prepared for your review.\n\n"
        "-- Sentinel Loop draft (no send performed)\n"
    ).format(subject)

    # 7. Create out_dir, write draft (success-only side effect).
    os.makedirs(out_dir, exist_ok=True)
    draft_file = os.path.join(out_dir, "draft.txt")
    with open(draft_file, "w", encoding="utf-8", newline="\n") as fh:
        fh.write(draft_text)

    # 8. Success.
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
